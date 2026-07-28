//! M13 poster wall: turn indexed release stems into a browsable catalogue.
//!
//! Two halves:
//! - a scene-name parser (pure, tested) that extracts title / year /
//!   S+E / quality from release stems and produces a dedupe key so five
//!   encodes of one film become one card;
//! - a TMDB enrichment client (metadata + artwork, cached in the index
//!   db + an on-disk art dir by the daemon's background worker). No key
//!   ⇒ the wall still works, text-only.

use std::collections::HashMap;
use std::fmt::Write as _;

// Release-name parsing moved to nzbkit::release (the indexer
// classifies at ingest - M25 browse view); re-exported so existing
// call sites keep their wall:: paths.
pub use nzbkit::release::{
    movie_name, norm_title, parse_release, quality_label, quality_suffix, Kind, NameStyle, Parsed,
};

// Cast and crew are entities, not a comma-joined string: the struct and
// its storage live in nzbkit::index, and every provider parser below
// fills it.
pub use nzbkit::index::Credit;

// ---------------------------------------------------------------------------
// Metadata lookup (network - daemon background worker only).
//
// Provider chain: TMDB when a key is configured (best data) - but TMDB
// declines API applications for NZB tooling, so the DEFAULT is keyless:
// TVmaze for TV (free, posters+synopsis+ratings), and for movies either
// the user's own free OMDb key or Wikidata + Wikipedia. Same cache
// either way.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TitleMeta {
    /// Provider's id for the match (TMDB/TVmaze/iTunes/AniList) - 0 = not found.
    pub tmdb_id: i64,
    pub overview: String,
    pub rating: f64,
    pub genres: String,
    /// Full image URLs (any provider), empty when absent.
    pub poster_url: String,
    pub backdrop_url: String,
    /// IMDb tconst when the provider knows it (TVmaze externals do).
    pub imdb: String,
    /// Top-billed cast, comma-joined (TVmaze /cast).
    pub actors: String,
    /// Original release / first-air date as ISO `YYYY-MM-DD`, empty when
    /// the provider didn't say. Year alone was too coarse to answer
    /// "what came out this week" - everything from the year landed in one
    /// undifferentiated bucket.
    pub air_date: String,
    /// Cast and crew as entities, when the provider models them that way.
    /// `actors` above stays the rendered credit line the cards already
    /// show - these ride alongside it, and only the providers that hand
    /// over a person handle (TVmaze, Wikidata) fill them.
    pub credits: Vec<Credit>,
}

/// Normalise a provider's date to ISO `YYYY-MM-DD`. The wall orders these
/// as plain strings (ISO sorts chronologically), so a format we can't
/// place is dropped rather than stored: a stray "30 Mar 1999" mixed into
/// an ISO column would sort under "3", wrecking the ordering for every
/// other row. Accepts the ISO prefix every JSON provider emits, plus
/// OMDb's "30 Mar 1999".
pub fn iso_date(s: &str) -> String {
    let s = s.trim();
    let b = s.as_bytes();
    // "YYYY-MM-DD" (optionally followed by a time, as iTunes sends).
    if b.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        return s[..10].to_string();
    }
    // "30 Mar 1999" (OMDb).
    let mut it = s.split_whitespace();
    let (Some(d), Some(m), Some(y), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return String::new();
    };
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let ml = m.to_ascii_lowercase();
    let Some(mi) = MONTHS.iter().position(|x| *x == ml) else {
        return String::new();
    };
    let (Ok(dn), Ok(yn)) = (d.parse::<u32>(), y.parse::<u32>()) else {
        return String::new();
    };
    if !(1..=31).contains(&dn) || !(1000..=9999).contains(&yn) {
        return String::new();
    }
    format!("{yn:04}-{:02}-{dn:02}", mi + 1)
}

/// One lookup via whichever provider fits: TMDB with a key, else
/// TVmaze (tv) / Wikidata (movies). `None` = looked, found nothing.
pub fn lookup(api_key: Option<&str>, kind: &Kind, title: &str, year: u32) -> Option<TitleMeta> {
    match api_key {
        Some(k) => tmdb_lookup(k, kind, title, year),
        None => match kind {
            Kind::Tv => tvmaze_lookup(title),
            Kind::Movie => wikidata_movie(title, year),
            Kind::Music | Kind::Book => media_lookup(kind, title),
            // Custom categories are never enriched: "Formula 1 Round 11"
            // has no meaningful identity at any provider, and a wrong
            // poster is worse than none.
            Kind::Software | Kind::Other | Kind::Custom(_) => None,
        },
    }
}

/// Music / book lookup. The parser stores both halves of the identity in
/// `title` as "Credit - Work" so a card reads properly before any
/// provider answers; the providers need them apart.
pub fn media_lookup(kind: &Kind, title: &str) -> Option<TitleMeta> {
    let (credit, work) = nzbkit::release::credit_split(title).unwrap_or(("", title));
    match kind {
        Kind::Book => openlibrary_lookup(credit, work),
        _ => musicbrainz_lookup(credit, work),
    }
}

/// Keyless providers have stricter (unofficial) rate limits - the
/// enricher sleeps this long after each lookup.
pub fn lookup_delay_ms(api_key: Option<&str>, kind: &Kind) -> u64 {
    match (api_key, kind) {
        (Some(_), _) => 250,
        // Music and books are paced by a real per-provider token bucket
        // (see `ratelimit`), applied to each REQUEST rather than to the
        // gap between titles. Sleeping here as well would double-pace
        // them: the bucket has already made the caller wait for its
        // turn by the time this is read.
        (None, Kind::Music) | (None, Kind::Book) => 0,
        (None, Kind::Tv) => 600,     // TVmaze: 20 req / 10 s
        // Wikimedia publishes no anonymous-read limit but does enforce
        // one: probing at ~3 req/s earned an HTTP 429 within a dozen
        // calls, and a 429 costs a title its whole card. A movie is 2-3
        // Wikidata calls plus 1-3 Wikipedia ones, all serial, so this
        // window holds the peak under ~1 req/s. Still half the old
        // iTunes crawl, and unlike iTunes it answers.
        (None, _) => 2500,
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// TMDB genre ids are stable and documented; a static map beats an extra
/// API round-trip per process.
fn genre_name(id: i64) -> Option<&'static str> {
    Some(match id {
        28 => "Action",
        12 => "Adventure",
        16 => "Animation",
        35 => "Comedy",
        80 => "Crime",
        99 => "Documentary",
        18 => "Drama",
        10751 => "Family",
        14 => "Fantasy",
        36 => "History",
        27 => "Horror",
        10402 => "Music",
        9648 => "Mystery",
        10749 => "Romance",
        878 => "Sci-Fi",
        10770 => "TV Movie",
        53 => "Thriller",
        10752 => "War",
        37 => "Western",
        10759 => "Action & Adventure",
        10762 => "Kids",
        10763 => "News",
        10764 => "Reality",
        10765 => "Sci-Fi & Fantasy",
        10766 => "Soap",
        10767 => "Talk",
        10768 => "War & Politics",
        _ => return None,
    })
}

/// One search round-trip. `None` = looked, found nothing (cache that too).
pub fn tmdb_lookup(api_key: &str, kind: &Kind, title: &str, year: u32) -> Option<TitleMeta> {
    let (path, year_param, date_field) = match kind {
        Kind::Tv => ("tv", "first_air_date_year", "first_air_date"),
        _ => ("movie", "year", "release_date"),
    };
    let mut url = format!(
        "https://api.themoviedb.org/3/search/{path}?api_key={api_key}&query={}",
        percent_encode(title)
    );
    if year > 0 {
        let _ = write!(url, "&{year_param}={year}");
    }
    let resp = match crate::serve::shared_enrich_agent().get(&url).timeout(std::time::Duration::from_secs(10)).call() {
        Ok(r) => r,
        Err(e) => {
            note_http_err(&e);
            return None;
        }
    };
    let body = match resp.into_string() {
        Ok(b) => b,
        Err(_) => {
            note_unreachable();
            return None;
        }
    };
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let hit = v["results"].get(0)?;
    let genres = hit["genre_ids"]
        .as_array()
        .map(|ids| {
            ids.iter()
                .filter_map(|i| genre_name(i.as_i64()?))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let img = |field: &str, width: &str| {
        hit[field]
            .as_str()
            .map(|p| format!("https://image.tmdb.org/t/p/{width}{p}"))
            .unwrap_or_default()
    };
    Some(TitleMeta {
        tmdb_id: hit["id"].as_i64().unwrap_or(0),
        overview: hit["overview"].as_str().unwrap_or("").to_string(),
        rating: hit["vote_average"].as_f64().unwrap_or(0.0),
        genres,
        poster_url: img("poster_path", "w342"),
        backdrop_url: img("backdrop_path", "w780"),
        imdb: String::new(),
        actors: String::new(),
        air_date: iso_date(hit[date_field].as_str().unwrap_or("")),
        credits: Vec::new(),
    })
}

fn get_json(url: &str) -> Option<serde_json::Value> {
    let resp = match crate::serve::shared_enrich_agent().get(url).timeout(std::time::Duration::from_secs(10)).call() {
        Ok(r) => r,
        Err(e) => {
            note_http_err(&e);
            return None;
        }
    };
    match resp.into_string() {
        Ok(body) => serde_json::from_str(&body).ok(),
        Err(_) => {
            note_unreachable();
            None
        }
    }
}

/// Strip HTML tags (TVmaze summaries are `<p>…</p>` fragments).
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

/// Pure parse of a TVmaze `singlesearch/shows` response (tested).
fn parse_tvmaze(v: &serde_json::Value) -> Option<TitleMeta> {
    let id = v["id"].as_i64()?;
    let poster = v["image"]["medium"].as_str().unwrap_or("").to_string();
    let backdrop = v["image"]["original"].as_str().unwrap_or("").to_string();
    Some(TitleMeta {
        tmdb_id: id,
        overview: strip_tags(v["summary"].as_str().unwrap_or("")),
        rating: v["rating"]["average"].as_f64().unwrap_or(0.0),
        genres: v["genres"]
            .as_array()
            .map(|g| g.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default(),
        poster_url: poster,
        backdrop_url: backdrop,
        imdb: v["externals"]["imdb"].as_str().unwrap_or("").to_string(),
        actors: String::new(), // separate /cast call - see tvmaze_cast
        air_date: iso_date(v["premiered"].as_str().unwrap_or("")),
        credits: Vec::new(),
    })
}

/// TVmaze: keyless TV metadata, no cast. Kept lean for the one caller
/// that only wants the show id (the watchlist's episode-list refresher);
/// the enricher uses `tvmaze_lookup_full`, which gets cast and crew in
/// this same request.
pub fn tvmaze_lookup(title: &str) -> Option<TitleMeta> {
    let v = get_json(&format!(
        "https://api.tvmaze.com/singlesearch/shows?q={}",
        percent_encode(title)
    ))?;
    parse_tvmaze(&v)
}

/// TVmaze show + cast + crew in ONE request.
///
/// This replaced a lookup followed by a separate `/shows/:id/cast` call.
/// Request budget - not parsing - is what limits enrichment throughput,
/// so halving the calls per show while returning strictly more data
/// (character names, person ids, headshots, the voice flag, and crew
/// with real roles) is the whole point. Measured live on 26 Jul 2026:
/// Severance answers in 35 KB with 11 cast and 71 crew.
pub fn tvmaze_lookup_full(title: &str) -> Option<TitleMeta> {
    let v = get_json(&format!(
        "https://api.tvmaze.com/singlesearch/shows?q={}&embed[]=cast&embed[]=crew",
        percent_encode(title)
    ))?;
    let mut m = parse_tvmaze(&v)?;
    m.credits = parse_tvmaze_credits(&v["_embedded"]);
    m.actors = credit_line(&m.credits, 8);
    Some(m)
}

/// The rendered "starring" line the cards have always shown, now derived
/// from the credit list instead of parsed separately. Cast only: a
/// producer does not belong on that line.
pub fn credit_line(credits: &[Credit], cap: usize) -> String {
    credits
        .iter()
        .filter(|c| c.role == "actor")
        .map(|c| c.name.as_str())
        .take(cap)
        .collect::<Vec<_>>()
        .join(", ")
}

/// How much a crew role earns its place when the list is capped. A show
/// can carry 70+ crew credits and most of them are production staff who
/// mean nothing on a card or a person page; these are the ones that
/// answer "who made this".
fn crew_rank(role: &str) -> u8 {
    match role {
        "creator" => 0,
        "director" => 1,
        r if r.contains("writer") || r.contains("story") || r.contains("teleplay") => 2,
        r if r.contains("composer") || r.contains("music") || r.contains("theme") => 3,
        "executive producer" => 4,
        r if r.contains("producer") => 5,
        r if r.contains("photography") || r.contains("editor") => 6,
        _ => 7,
    }
}

/// Pure parse of a TVmaze `_embedded` block (cast + crew) into credits
/// (tested).
///
/// Crew is capped at `CREW_CAP` by `crew_rank`, so a show with 71 credits
/// keeps its creators, directors, writers and composers and drops the
/// unit production managers - the cap is on storage, not on what the user
/// asked for.
fn parse_tvmaze_credits(emb: &serde_json::Value) -> Vec<Credit> {
    const CREW_CAP: usize = 12;
    let person = |p: &serde_json::Value| -> Option<(i64, String, String)> {
        let name = p["name"].as_str().filter(|n| !n.trim().is_empty())?;
        Some((
            p["id"].as_i64().unwrap_or(0),
            name.to_string(),
            // `medium` is a portrait crop, which is the shape a headshot
            // is displayed in - `original` is an uncropped still that can
            // be several MB.
            p["image"]["medium"].as_str().unwrap_or("").to_string(),
        ))
    };
    let mut out: Vec<Credit> = Vec::new();
    if let Some(list) = emb["cast"].as_array() {
        for (i, c) in list.iter().enumerate() {
            let Some((id, name, photo)) = person(&c["person"]) else {
                continue;
            };
            out.push(Credit {
                name,
                role: "actor".into(),
                // A voice role is a real distinction on an animated show
                // and the flag is right there; folding it into the
                // character keeps it visible without a schema column.
                character: match (c["character"]["name"].as_str(), c["voice"].as_bool()) {
                    (Some(n), Some(true)) if !n.is_empty() => format!("{n} (voice)"),
                    (Some(n), _) => n.to_string(),
                    (None, _) => String::new(),
                },
                // TVmaze returns cast in billing order but numbers
                // nothing, so position IS the billing order. 1-based, so
                // 0 keeps meaning "unranked" everywhere else.
                ord: i as i64 + 1,
                tvmaze_id: id,
                photo,
                ..Default::default()
            });
        }
    }
    let mut crew: Vec<Credit> = Vec::new();
    if let Some(list) = emb["crew"].as_array() {
        for c in list {
            let Some((id, name, photo)) = person(&c["person"]) else {
                continue;
            };
            let role = c["type"].as_str().unwrap_or("").trim().to_lowercase();
            if role.is_empty() {
                continue;
            }
            crew.push(Credit { name, role, tvmaze_id: id, photo, ..Default::default() });
        }
    }
    crew.sort_by_key(|c| crew_rank(&c.role));
    crew.truncate(CREW_CAP);
    out.extend(crew);
    out
}

/// One episode from a TVmaze episode list (M23d airdate calendar).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EpInfo {
    pub season: u32,
    pub episode: u32,
    pub name: String,
    /// "YYYY-MM-DD"; empty when TVmaze doesn't know yet.
    #[serde(default)]
    pub airdate: String,
    /// The episode synopsis. TVmaze sends one for essentially every
    /// aired episode and we used to throw all of them away, which is
    /// what made "what have I watched, what is next" unanswerable.
    /// `#[serde(default)]` on every field added here: episode lists are
    /// cached as JSON in `kv`, and a blob written before a field existed
    /// must still deserialize rather than emptying the calendar.
    #[serde(default)]
    pub summary: String,
    /// Episode still (medium crop), empty when TVmaze has none.
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub rating: f64,
    /// Minutes; 0 when unknown.
    #[serde(default)]
    pub runtime: u32,
}

/// Pure parse of a TVmaze `/shows/:id/episodes` response (tested).
/// Specials (null episode number) are dropped.
fn parse_tvmaze_episodes(v: &serde_json::Value) -> Vec<EpInfo> {
    v.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|e| {
                    Some(EpInfo {
                        season: e["season"].as_u64()? as u32,
                        episode: e["number"].as_u64()? as u32,
                        name: e["name"].as_str().unwrap_or("").to_string(),
                        airdate: e["airdate"].as_str().unwrap_or("").to_string(),
                        // Provider HTML, same `<p>…</p>` fragments as the
                        // show summary - stripped here so nothing
                        // downstream has to trust it as markup.
                        summary: strip_tags(e["summary"].as_str().unwrap_or("")),
                        image: e["image"]["medium"].as_str().unwrap_or("").to_string(),
                        rating: e["rating"]["average"].as_f64().unwrap_or(0.0),
                        runtime: e["runtime"].as_u64().unwrap_or(0) as u32,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Full episode list (with airdates) for a TVmaze show id.
pub fn tvmaze_episodes(show_id: i64) -> Vec<EpInfo> {
    get_json(&format!("https://api.tvmaze.com/shows/{show_id}/episodes"))
        .map(|v| parse_tvmaze_episodes(&v))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// M16 wall-fix: candidate search - the "did you mean?" list behind the
// UI's re-search flow. Same providers as lookup(), but returning SEVERAL
// matches with enough context (year, synopsis snippet, poster URL) for a
// human to pick the right one.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Candidate {
    /// Provider's id (TMDB/TVmaze/iTunes namespaces don't collide in
    /// practice because a title uses one provider at a time).
    pub id: i64,
    /// "movie" | "tv".
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub overview: String,
    pub rating: f64,
    pub genres: String,
    pub poster_url: String,
    pub backdrop_url: String,
    /// IMDb tconst when the provider exposes it (TVmaze externals) -
    /// lets a fix-applied title keep IMDb ratings working.
    pub imdb: String,
    pub provider: String,
    /// ISO release / first-air date, empty when the search response only
    /// carried a year (OMDb's `s=` list does).
    pub air_date: String,
}

fn year_of_date(d: Option<&str>) -> u32 {
    d.and_then(|d| d.get(..4)).and_then(|y| y.parse().ok()).unwrap_or(0)
}

/// Pure parse of a TMDB search response (movie or tv) → candidates.
fn parse_tmdb_search(v: &serde_json::Value, kind: &Kind) -> Vec<Candidate> {
    let (name_field, date_field, kind_str) = match kind {
        Kind::Tv => ("name", "first_air_date", "tv"),
        _ => ("title", "release_date", "movie"),
    };
    let img = |hit: &serde_json::Value, field: &str, width: &str| {
        hit[field]
            .as_str()
            .map(|p| format!("https://image.tmdb.org/t/p/{width}{p}"))
            .unwrap_or_default()
    };
    v["results"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .take(10)
                .filter_map(|hit| {
                    Some(Candidate {
                        id: hit["id"].as_i64()?,
                        kind: kind_str.to_string(),
                        title: hit[name_field].as_str().unwrap_or("").to_string(),
                        year: year_of_date(hit[date_field].as_str()),
                        overview: hit["overview"].as_str().unwrap_or("").to_string(),
                        rating: hit["vote_average"].as_f64().unwrap_or(0.0),
                        genres: hit["genre_ids"]
                            .as_array()
                            .map(|ids| {
                                ids.iter()
                                    .filter_map(|i| genre_name(i.as_i64()?))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default(),
                        poster_url: img(hit, "poster_path", "w342"),
                        backdrop_url: img(hit, "backdrop_path", "w780"),
                        imdb: String::new(),
                        provider: "tmdb".into(),
                        air_date: iso_date(hit[date_field].as_str().unwrap_or("")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Pure parse of a TVmaze `search/shows` response → candidates.
fn parse_tvmaze_search(v: &serde_json::Value) -> Vec<Candidate> {
    v.as_array()
        .map(|rs| {
            rs.iter()
                .take(10)
                .filter_map(|r| {
                    let show = &r["show"];
                    let m = parse_tvmaze(show)?;
                    Some(Candidate {
                        id: m.tmdb_id,
                        kind: "tv".into(),
                        title: show["name"].as_str().unwrap_or("").to_string(),
                        year: year_of_date(show["premiered"].as_str()),
                        overview: m.overview,
                        rating: m.rating,
                        genres: m.genres,
                        poster_url: m.poster_url,
                        backdrop_url: m.backdrop_url,
                        imdb: m.imdb,
                        provider: "tvmaze".into(),
                        air_date: m.air_date,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Candidate search for the wall's fix-match UI. `kind` decides the
/// provider (TMDB with a key, else TVmaze for tv / iTunes for movies);
/// `year` is a hint passed to TMDB only (keyless providers return the
/// full list and the user picks).
pub fn search_candidates(
    api_key: Option<&str>,
    kind: &Kind,
    query: &str,
    year: u32,
) -> Vec<Candidate> {
    match (api_key, kind) {
        (Some(k), kind) => {
            let (path, year_param) = match kind {
                Kind::Tv => ("tv", "first_air_date_year"),
                _ => ("movie", "year"),
            };
            let mut url = format!(
                "https://api.themoviedb.org/3/search/{path}?api_key={k}&query={}",
                percent_encode(query)
            );
            if year > 0 {
                let _ = write!(url, "&{year_param}={year}");
            }
            get_json(&url).map(|v| parse_tmdb_search(&v, kind)).unwrap_or_default()
        }
        (None, Kind::Tv) => get_json(&format!(
            "https://api.tvmaze.com/search/shows?q={}",
            percent_encode(query)
        ))
        .map(|v| parse_tvmaze_search(&v))
        .unwrap_or_default(),
        (None, _) => wikidata_search(query)
            .map(|(s, e)| parse_wikidata_candidates(&s, &e, year))
            .unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// OMDb (optional free key - the ONLY obtainable key upgrade: TMDB bans
// NZB apps and requires KYC; OMDb's free tier needs just an email).
// 1,000 req/day, looks up by title+year or exactly by IMDb tconst, and
// returns plot, genres, CAST (movies have none keyless) and a poster.
// Data is CC BY-NC - credited in the wall footer.
// ---------------------------------------------------------------------------

/// OMDb pads absent fields with the string "N/A" instead of omitting.
fn omdb_field(v: &serde_json::Value) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty() && *s != "N/A")
}

/// Pure parse of an OMDb detail response (t=/i= lookups; tested).
fn parse_omdb(v: &serde_json::Value) -> Option<TitleMeta> {
    if v["Response"].as_str() != Some("True") {
        return None;
    }
    let imdb = omdb_field(&v["imdbID"]).unwrap_or("").to_string();
    // Numeric part of the tconst as the provider id (nonzero = found).
    let id: i64 = imdb
        .trim_start_matches("tt")
        .parse()
        .unwrap_or(1);
    Some(TitleMeta {
        tmdb_id: id.max(1),
        overview: omdb_field(&v["Plot"]).unwrap_or("").to_string(),
        rating: omdb_field(&v["imdbRating"]).and_then(|r| r.parse().ok()).unwrap_or(0.0),
        genres: omdb_field(&v["Genre"]).unwrap_or("").to_string(),
        poster_url: omdb_field(&v["Poster"]).unwrap_or("").to_string(),
        backdrop_url: String::new(),
        imdb,
        actors: omdb_field(&v["Actors"]).unwrap_or("").to_string(),
        air_date: iso_date(omdb_field(&v["Released"]).unwrap_or("")),
        credits: Vec::new(),
    })
}

/// OMDb: movie metadata by title (+year hint).
pub fn omdb_lookup(key: &str, title: &str, year: u32) -> Option<TitleMeta> {
    let mut url = format!(
        "https://www.omdbapi.com/?apikey={key}&type=movie&t={}",
        percent_encode(title)
    );
    if year > 0 {
        let _ = write!(url, "&y={year}");
    }
    get_json(&url).as_ref().and_then(parse_omdb)
}

/// OMDb: exact lookup by IMDb tconst (Wikidata resolves those keyless,
/// so an OMDb title-miss often still lands via the id).
pub fn omdb_lookup_imdb(key: &str, tconst: &str) -> Option<TitleMeta> {
    get_json(&format!("https://www.omdbapi.com/?apikey={key}&i={tconst}"))
        .as_ref()
        .and_then(parse_omdb)
}

/// Pure parse of an OMDb `s=` search response → candidates (tested).
/// Year comes as "1999" or a range "1999–2003" - first 4 digits win.
fn parse_omdb_search(v: &serde_json::Value) -> Vec<Candidate> {
    v["Search"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .take(10)
                .filter_map(|hit| {
                    let imdb = omdb_field(&hit["imdbID"])?.to_string();
                    Some(Candidate {
                        id: imdb.trim_start_matches("tt").parse().unwrap_or(1),
                        kind: "movie".into(),
                        title: omdb_field(&hit["Title"]).unwrap_or("").to_string(),
                        year: omdb_field(&hit["Year"])
                            .and_then(|y| y.get(..4))
                            .and_then(|y| y.parse().ok())
                            .unwrap_or(0),
                        overview: String::new(),
                        rating: 0.0,
                        genres: String::new(),
                        poster_url: omdb_field(&hit["Poster"]).unwrap_or("").to_string(),
                        backdrop_url: String::new(),
                        imdb,
                        provider: "omdb".into(),
                        // The `s=` list carries Year only - a per-title
                        // Refresh picks the full date up from `t=`/`i=`.
                        air_date: String::new(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// OMDb candidate search for the wall's fix-match UI.
pub fn omdb_search(key: &str, query: &str) -> Vec<Candidate> {
    get_json(&format!(
        "https://www.omdbapi.com/?apikey={key}&type=movie&s={}",
        percent_encode(query)
    ))
    .map(|v| parse_omdb_search(&v))
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// OMDb signup automation: the free-key form only wants an email, so the
// daemon can submit it for the user (Settings → Indexing → "Request
// key"). It's a classic ASP.NET WebForms page - replay every hidden
// field verbatim, pick the FREE account-type radio, fill the email/name
// boxes, press the submit button. The key then arrives BY EMAIL with an
// activation link, so the last step is always the user's inbox.
// ---------------------------------------------------------------------------

/// One attribute out of a raw HTML tag ("<input name=\"x\" …>").
fn tag_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    for quote in ['"', '\''] {
        let pat = format!("{name}={quote}");
        if let Some(p) = tag.to_ascii_lowercase().find(&pat) {
            let rest = &tag[p + pat.len()..];
            if let Some(end) = rest.find(quote) {
                return Some(&rest[..end]);
            }
        }
    }
    None
}

/// The free-tier account-type radio: (field name, __doPostBack target
/// = the element id, field value, whether it's already selected). The
/// live form defaults to the Patreon tier with an AutoPostBack on the
/// free radio, so selection is a round-trip, not just a field value.
fn omdb_free_radio(html: &str) -> Option<(String, String, String, bool)> {
    let mut rest = html;
    while let Some(p) = rest.find("<input") {
        rest = &rest[p..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        rest = &rest[end..];
        if tag_attr(tag, "type").map(str::to_ascii_lowercase).as_deref() != Some("radio") {
            continue;
        }
        let value = tag_attr(tag, "value").unwrap_or("");
        if !value.to_ascii_lowercase().contains("free") {
            continue;
        }
        let name = tag_attr(tag, "name")?.to_string();
        let target = tag_attr(tag, "id").unwrap_or(value).to_string();
        let checked = tag.to_ascii_lowercase().contains("checked");
        return Some((name, target, value.to_string(), checked));
    }
    None
}

/// Pure form scrape (tested): every field the POST must carry, with the
/// user's email in the email boxes and the free tier selected. None if
/// the page doesn't look like the signup form (no email field). The
/// submit button only rides on the final POST - a WebForms postback
/// that selects the radio must not also "click" Submit.
fn omdb_signup_fields(
    html: &str,
    email: &str,
    include_submit: bool,
) -> Option<Vec<(String, String)>> {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut saw_email = false;
    let mut submit_taken = false;
    let mut rest = html;
    while let Some(p) = rest.find("<input") {
        rest = &rest[p..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        rest = &rest[end..];
        let Some(name) = tag_attr(tag, "name") else { continue };
        let name = name.to_string();
        let lname = name.to_ascii_lowercase();
        let value = tag_attr(tag, "value").unwrap_or("").to_string();
        let ty = tag_attr(tag, "type").unwrap_or("text").to_ascii_lowercase();
        match ty.as_str() {
            "radio" => {
                // Account type: always post the free-tier option.
                if value.to_ascii_lowercase().contains("free") {
                    fields.push((name, value));
                }
            }
            "submit" => {
                if include_submit && !submit_taken {
                    submit_taken = true;
                    fields.push((name, value));
                }
            }
            "checkbox" => {} // none required on this form
            _ => {
                // text/email/hidden: viewstate rides through verbatim,
                // email boxes (incl. the confirm box) get the address.
                if lname.contains("email") {
                    saw_email = true;
                    fields.push((name, email.to_string()));
                } else if lname.contains("firstname") {
                    fields.push((name, "nzbfast".into()));
                } else if lname.contains("lastname") {
                    fields.push((name, "user".into()));
                } else {
                    fields.push((name, value));
                }
            }
        }
    }
    // The "use" textarea posts too.
    let mut rest = html;
    while let Some(p) = rest.find("<textarea") {
        rest = &rest[p..];
        let end = rest.find('>').unwrap_or(rest.len());
        if let Some(name) = tag_attr(&rest[..end], "name") {
            fields.push((name.to_string(), "Personal media library (poster wall metadata)".into()));
        }
        rest = &rest[end..];
    }
    saw_email.then_some(fields)
}

fn form_encode(fields: &[(String, String)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Best-effort automated OMDb free-key signup. Ok = the form was
/// accepted (key + activation link arrive by email); Err = fall back to
/// doing it by hand at omdbapi.com/apikey.aspx.
///
/// Two round-trips: the live form defaults to the Patreon tier and the
/// FREE radio is a WebForms AutoPostBack - selecting it re-renders the
/// page with the free-tier fields (name, intended use). So: GET, replay
/// the __doPostBack that picks FREE, then fill + submit that form.
pub fn omdb_signup(email: &str) -> Result<(), String> {
    const URL: &str = "https://www.omdbapi.com/apikey.aspx";
    let post = |fields: &[(String, String)]| -> Result<String, String> {
        ureq::post(URL)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .timeout(std::time::Duration::from_secs(15))
            .send_string(&form_encode(fields))
            .map_err(|e| format!("signup submit failed: {e}"))?
            .into_string()
            .map_err(|e| e.to_string())
    };
    let mut page = crate::serve::shared_enrich_agent().get(URL)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .map_err(|e| format!("couldn't load the signup form: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    if let Some((_, target, _, checked)) = omdb_free_radio(&page) {
        if !checked {
            let mut fields = omdb_signup_fields(&page, email, false)
                .ok_or("the signup form has changed - request a key manually")?;
            fields.push(("__EVENTTARGET".into(), target));
            fields.push(("__EVENTARGUMENT".into(), String::new()));
            page = post(&fields)?;
        }
    }
    let fields = omdb_signup_fields(&page, email, true)
        .ok_or("the signup form has changed - request a key manually")?;
    let body = post(&fields)?.to_ascii_lowercase();
    // WebForms answers 200 either way - look for the confirmation copy.
    if ["sent", "activat", "verification", "shortly", "receive"]
        .iter()
        .any(|m| body.contains(m))
    {
        Ok(())
    } else if body.contains("exist") || body.contains("already") {
        Err("that email already has a key - check your inbox (or spam) for it".into())
    } else {
        Err("the form didn't confirm - request a key manually".into())
    }
}

// Wikimedia asks for a descriptive User-Agent; ureq's default is not one.
const WIKI_UA: &str = "nzbfast/0.1 (personal media indexer; wall metadata)";

/// Wikimedia rate-limits anonymous reads hard enough to matter: probing
/// the API at ~3 requests/second earned an HTTP 429 after a dozen calls.
/// One patient retry on 429 (honouring Retry-After when it is sent)
/// keeps a burst from silently costing a title its whole card, which is
/// the failure mode that matters - the enricher has no other chance at
/// that row until something re-queues it.
fn get_json_ua(url: &str) -> Option<serde_json::Value> {
    const BACKOFF_SECS: [u64; 2] = [5, 15];
    for attempt in 0..=BACKOFF_SECS.len() {
        match crate::serve::shared_enrich_agent().get(url)
            .set("User-Agent", WIKI_UA)
            .timeout(std::time::Duration::from_secs(10))
            .call()
        {
            Ok(resp) => {
                return match resp.into_string() {
                    Ok(body) => serde_json::from_str(&body).ok(),
                    Err(_) => {
                        note_unreachable();
                        None
                    }
                };
            }
            Err(ureq::Error::Status(429, r)) if attempt < BACKOFF_SECS.len() => {
                let wait = r
                    .header("Retry-After")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(BACKOFF_SECS[attempt])
                    .clamp(1, 30);
                std::thread::sleep(std::time::Duration::from_secs(wait));
            }
            Err(e) => {
                note_http_err(&e);
                return None;
            }
        }
    }
    note_unreachable(); // retries exhausted, still no answer
    None
}

thread_local! {
    /// Did an HTTP call in this thread fail to get an ANSWER, as opposed
    /// to being told "no such thing"?
    ///
    /// The distinction decides whether the enricher may stamp a title as
    /// checked. Every fetcher here collapses failure into `None`, so a
    /// DNS outage, a timeout, a TLS error or a provider 503 looked
    /// exactly like "this title does not exist" - and the lane's `None`
    /// arm calls `title_fill(&Default::default())`, which sets
    /// `checked=now` and `air_tried=1`. `titles_pending_lane` then never
    /// offers the row again. A few seconds of a flaky uplink was enough
    /// to mark hundreds of titles permanently as "no metadata, no art,
    /// no date", recoverable only by `titles_reset_all`. Kind::Other
    /// rows, which have no sleep between them, burned through fastest.
    ///
    /// Thread-local because the enricher lane is one row at a time on
    /// one thread: clear it before a row, read it after.
    static UNREACHABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn note_unreachable() {
    UNREACHABLE.with(|f| f.set(true));
}

/// A 5xx means the provider is broken right now, which is worth
/// retrying; a 404 or other 4xx is a real answer and must not be.
fn note_http_err(e: &ureq::Error) {
    let no_answer = match e {
        ureq::Error::Status(code, _) => *code >= 500,
        ureq::Error::Transport(_) => true,
    };
    if no_answer {
        note_unreachable();
    }
}

/// Start a fresh "was anything unreachable" window for one title.
pub fn clear_unreachable() {
    UNREACHABLE.with(|f| f.set(false));
}

/// Did any provider call since `clear_unreachable` fail to get an answer?
/// When true, an empty result means "we could not ask", not "there is
/// nothing", and the caller must leave the row unstamped so a later pass
/// retries it.
pub fn saw_unreachable() -> bool {
    UNREACHABLE.with(|f| f.get())
}

/// Entity labels are overwhelmingly repeats - every science-fiction film
/// references the same genre Q-id, and a prolific actor recurs across a
/// whole filmography - so resolving them once per process removes most
/// of the third Wikidata call as the wall fills in.
fn label_cache() -> &'static std::sync::Mutex<HashMap<String, String>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Pure candidate-picking over wbsearchentities + wbgetentities claims:
/// take the first candidate holding an IMDb id (P345) whose publication
/// year (P577) matches ±1 when we know the year (tested).
fn pick_wikidata_imdb(
    search: &serde_json::Value,
    entities: &serde_json::Value,
    year: u32,
) -> Option<String> {
    let order: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    let year_of = |ent: &serde_json::Value| -> Option<u32> {
        ent["claims"]["P577"]
            .as_array()?
            .first()?["mainsnak"]["datavalue"]["value"]["time"]
            .as_str()?
            .get(1..5)?
            .parse()
            .ok()
    };
    for id in order {
        let ent = &entities["entities"][id];
        let Some(tconst) = ent["claims"]["P345"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["mainsnak"]["datavalue"]["value"].as_str())
        else {
            continue;
        };
        if year > 0 {
            match year_of(ent) {
                Some(y) if y.abs_diff(year) <= 1 => return Some(tconst.to_string()),
                Some(_) => continue,
                None => continue,
            }
        }
        return Some(tconst.to_string());
    }
    None
}

/// Wikidata: resolve a movie title(+year) to an IMDb tconst - the join
/// key for the IMDb ratings snapshot. Two keyless calls.
pub fn wikidata_imdb(title: &str, year: u32) -> Option<String> {
    let search = get_json_ua(&format!(
        "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json\
         &language=en&type=item&limit=5&search={}",
        percent_encode(title)
    ))?;
    let ids: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    if ids.is_empty() {
        return None;
    }
    let entities = get_json_ua(&format!(
        "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json\
         &props=claims&ids={}",
        ids.join("|")
    ))?;
    pick_wikidata_imdb(&search, &entities, year)
}

// ---------------------------------------------------------------------------
// Wikidata as the keyless MOVIE provider.
//
// Apple removed movies from the iTunes Search API: as of 26 Jul 2026
// `media=movie` answers HTTP 200 with `resultCount: 0` for every title
// tried, mainstream or not, in every storefront. That left the keyless
// movie path with no metadata source at all - a live index measured 36
// posters across 3676 movie titles (1.0%) and zero cast, against 59% and
// 48% for TV, which goes to TVmaze.
//
// Wikidata replaces it using the two calls `wikidata_imdb` was already
// making: wbsearchentities to find candidates, wbgetentities to read
// their claims. The claims we were throwing away carry the whole card -
// P345 IMDb id, P577 publication date, P136 genre, P161 cast. The
// poster comes from Wikipedia, not Wikidata - see `parse_wikidata_film`. Only the third call (resolving genre/cast Q-ids to names)
// is new. Plot still comes from Wikipedia, as it did before.
// ---------------------------------------------------------------------------

/// P31 (instance of) values that mean "this entity is a film". Wikidata
/// has no single film class, and the subtypes do not all declare P31 to
/// the parent, so the specific ones have to be listed.
const FILM_CLASSES: [&str; 7] = [
    "Q11424",  // film
    "Q24869",  // feature film
    "Q506240", // television film
    "Q202866", // animated film
    "Q93204",  // documentary film
    "Q24862",  // short film
    "Q20650540", // adult film
];

/// External-id / string-valued claims (P345 imdb).
fn claim_strs(ent: &serde_json::Value, prop: &str) -> Vec<String> {
    ent["claims"][prop]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["mainsnak"]["datavalue"]["value"].as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Entity-valued claims (P136 genre, P161 cast member) → the Q-ids.
fn claim_entity_ids(ent: &serde_json::Value, prop: &str) -> Vec<String> {
    ent["claims"][prop]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["mainsnak"]["datavalue"]["value"]["id"].as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Wikidata times look like "+2010-07-16T00:00:00Z" - the leading sign
/// is mandatory in the model and breaks `iso_date`'s digit check, so it
/// is stripped here rather than teaching every caller about it.
fn wikidata_iso(t: &str) -> String {
    iso_date(t.strip_prefix('+').unwrap_or(t))
}

/// Earliest P577 (publication date). Films carry one per territory, and
/// the release we care about is the first one.
fn earliest_publication(ent: &serde_json::Value) -> String {
    let mut dates: Vec<String> = ent["claims"]["P577"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["mainsnak"]["datavalue"]["value"]["time"].as_str())
                .map(wikidata_iso)
                .filter(|d| !d.is_empty())
                .collect()
        })
        .unwrap_or_default();
    dates.sort();
    dates.into_iter().next().unwrap_or_default()
}

fn is_film_entity(ent: &serde_json::Value) -> bool {
    claim_entity_ids(ent, "P31").iter().any(|q| FILM_CLASSES.contains(&q.as_str()))
}

/// Pick the film entity a title(+year) means, in search-rank order
/// (tested). Two passes: one that insists on an IMDb id, then one that
/// does not - a Wikidata film without P345 still has art, a date, genres
/// and a cast, which beats the bare stem the wall shows otherwise.
///
/// A known year is a hard filter, not a tiebreak: "The Italian Job"
/// resolves to two films, and showing the wrong one's poster is worse
/// than showing none.
pub fn pick_wikidata_film(
    search: &serde_json::Value,
    entities: &serde_json::Value,
    year: u32,
) -> Option<String> {
    let order: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    let year_ok = |ent: &serde_json::Value| -> bool {
        if year == 0 {
            return true;
        }
        earliest_publication(ent)
            .get(..4)
            .and_then(|y| y.parse::<u32>().ok())
            .is_some_and(|y| y.abs_diff(year) <= 1)
    };
    for want_imdb in [true, false] {
        for id in &order {
            let ent = &entities["entities"][*id];
            if !is_film_entity(ent) || !year_ok(ent) {
                continue;
            }
            if want_imdb && claim_strs(ent, "P345").is_empty() {
                continue;
            }
            return Some((*id).to_string());
        }
    }
    None
}

/// A picked film entity + resolved names for its referenced Q-ids → the
/// card (tested). A Q-id missing from `labels` is dropped rather than
/// shown raw, because "Q157443" on a poster card is worse than one
/// fewer genre.
pub fn parse_wikidata_film(
    ent: &serde_json::Value,
    labels: &HashMap<String, String>,
) -> TitleMeta {
    let names = |ids: Vec<String>, cap: usize| -> String {
        ids.iter()
            .filter_map(|q| labels.get(q).cloned())
            .take(cap)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let credits = parse_wikidata_credits(ent, labels);
    TitleMeta {
        // Wikidata is not one of the id namespaces the fix-match flow
        // resolves against, so it contributes no provider id.
        tmdb_id: 0,
        // Wikidata holds no synopsis; the caller's Wikipedia fallback
        // fills this, exactly as it did behind iTunes.
        overview: String::new(),
        // No community rating either - the IMDb snapshot overlays one at
        // wall time via the tconst below.
        rating: 0.0,
        genres: names(claim_entity_ids(ent, "P136"), 4),
        // No poster from here. P18 ("image") is NOT a film poster:
        // posters are non-free and cannot live on Commons, so P18 holds
        // whatever freely-licensed picture exists instead - measured
        // against the live API, The Matrix returns a screenshot of the
        // glmatrix screensaver and Inception a photo of the cast at a
        // premiere. Both are worse on a wall than no art at all. The
        // caller pairs this with `wikipedia_page`, whose infobox image
        // IS the poster.
        poster_url: String::new(),
        backdrop_url: String::new(),
        imdb: claim_strs(ent, "P345").first().cloned().unwrap_or_default(),
        // Billing order IS modelled after all - as the P1545 qualifier on
        // each cast claim, which `parse_wikidata_credits` reads. The
        // credit line is rendered from that order rather than from the
        // order the claims happened to be stored in.
        actors: credit_line(&credits, 8),
        air_date: earliest_publication(ent),
        credits,
    }
}

/// Wikidata crew properties worth a credit, and the role each becomes.
/// Deliberately short: these are the four the film community actually
/// looks a film up by, and every one of them is already in the claims
/// response we parse for genre and cast.
const WIKIDATA_CREW: [(&str, &str); 4] =
    [("P57", "director"), ("P58", "writer"), ("P86", "composer"), ("P162", "producer")];

/// Cast and crew from a film entity's claims (tested).
///
/// The cast half is what `parse_wikidata_film` was already reading and
/// flattening to names. Two things were being dropped from claims we had
/// in hand: the **P453 character-role qualifier** (9 of the 19 cast on
/// The Matrix carry one) and **P1545, the series ordinal**, which is
/// Wikidata's billing order - without it the "starring" line is in
/// whatever order the claims happened to be stored in.
pub fn parse_wikidata_credits(
    ent: &serde_json::Value,
    labels: &HashMap<String, String>,
) -> Vec<Credit> {
    let mut out: Vec<Credit> = Vec::new();
    if let Some(list) = ent["claims"]["P161"].as_array() {
        for c in list {
            let Some(qid) = c["mainsnak"]["datavalue"]["value"]["id"].as_str() else {
                continue;
            };
            // A Q-id with no resolved label is dropped rather than shown
            // raw, exactly as the genre list does: "Q157443" is not a
            // name, and a person page titled with one is worse than one
            // fewer credit.
            let Some(name) = labels.get(qid) else {
                continue;
            };
            let qual = |p: &str| -> Option<&serde_json::Value> {
                c["qualifiers"][p].as_array().and_then(|a| a.first())
            };
            out.push(Credit {
                name: name.clone(),
                role: "actor".into(),
                character: qual("P453")
                    .and_then(|q| q["datavalue"]["value"]["id"].as_str())
                    .and_then(|q| labels.get(q))
                    .cloned()
                    .unwrap_or_default(),
                // P1545 is a string in the data model even though it
                // holds a number.
                ord: qual("P1545")
                    .and_then(|q| q["datavalue"]["value"].as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                wikidata_qid: qid.to_string(),
                ..Default::default()
            });
        }
    }
    // Only some of a cast carry P1545 (10 of 19 on The Matrix do not).
    // Sorting on ord alone would float every unranked name above the
    // billed leads, so they keep claim order in a band behind them.
    let mut n = 0;
    for c in out.iter_mut().filter(|c| c.ord == 0) {
        n += 1;
        c.ord = 1000 + n;
    }
    out.sort_by_key(|c| c.ord);
    for (prop, role) in WIKIDATA_CREW {
        for qid in claim_entity_ids(ent, prop) {
            let Some(name) = labels.get(&qid) else {
                continue;
            };
            out.push(Credit {
                name: name.clone(),
                role: role.into(),
                wikidata_qid: qid,
                ..Default::default()
            });
        }
    }
    out
}

/// Search Wikidata for a title and pull the candidates' claims: the two
/// calls every Wikidata path here starts with. `labels` and
/// `descriptions` ride along because the candidate list needs them and
/// they cost nothing extra.
fn wikidata_search(title: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    let search = get_json_ua(&format!(
        "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json\
         &language=en&type=item&limit=10&search={}",
        percent_encode(title)
    ))?;
    let ids: Vec<&str> = search["search"]
        .as_array()?
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    if ids.is_empty() {
        return None;
    }
    let entities = get_json_ua(&format!(
        "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json\
         &props=claims|labels|descriptions&languages=en|mul&ids={}",
        ids.join("|")
    ))?;
    Some((search, entities))
}

/// Every film among the candidates → the "did you mean?" list behind the
/// wall's fix-match flow (tested). Year is a filter here too, but a
/// missing date is kept: the user is looking at the list precisely
/// because the automatic pick went wrong.
pub fn parse_wikidata_candidates(
    search: &serde_json::Value,
    entities: &serde_json::Value,
    year: u32,
) -> Vec<Candidate> {
    let Some(order) = search["search"].as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for id in order.iter().filter_map(|c| c["id"].as_str()) {
        let ent = &entities["entities"][id];
        if !is_film_entity(ent) {
            continue;
        }
        let date = earliest_publication(ent);
        let y = date.get(..4).and_then(|y| y.parse::<u32>().ok()).unwrap_or(0);
        if year > 0 && y > 0 && y.abs_diff(year) > 1 {
            continue;
        }
        // `mul` fallback for the same reason `resolve_labels` needs one.
        let title = ent["labels"]["en"]["value"]
            .as_str()
            .or(ent["labels"]["mul"]["value"].as_str())
            .unwrap_or("");
        if title.is_empty() {
            continue;
        }
        out.push(Candidate {
            id: 0,
            kind: "movie".into(),
            title: title.to_string(),
            year: y,
            // Wikidata's one-line description ("1999 film by the
            // Wachowskis") is exactly the disambiguator this list needs.
            overview: ent["descriptions"]["en"]["value"].as_str().unwrap_or("").to_string(),
            rating: 0.0,
            genres: String::new(),
            // No art: P18 is not a film poster (see
            // `parse_wikidata_film`), and a wrong picture in a
            // "did you mean?" list is worse than none - the title, year
            // and Wikidata's one-line description already disambiguate.
            poster_url: String::new(),
            backdrop_url: String::new(),
            imdb: claim_strs(ent, "P345").first().cloned().unwrap_or_default(),
            provider: "wikidata".into(),
            air_date: date,
        });
    }
    out
}

/// Wikidata: the keyless movie provider. Three calls - search, claims,
/// then labels for the genre/cast entities the claims reference (skipped
/// when there are none).
pub fn wikidata_movie(title: &str, year: u32) -> Option<TitleMeta> {
    let (search, entities) = wikidata_search(title)?;
    let picked = pick_wikidata_film(&search, &entities, year)?;
    let ent = &entities["entities"][&picked];
    // Everything the card and the credits reference, in ONE label call.
    // The cast cap is 16 rather than 8 because the credit line shows 8
    // but the person graph keeps them all, and characters/crew ride in
    // the same 50-id budget `resolve_labels` already spends.
    let mut refs = claim_entity_ids(ent, "P136");
    refs.extend(claim_entity_ids(ent, "P161").into_iter().take(16));
    refs.extend(character_qids(ent).into_iter().take(16));
    for (prop, _) in WIKIDATA_CREW {
        refs.extend(claim_entity_ids(ent, prop).into_iter().take(4));
    }
    refs.sort();
    refs.dedup();
    Some(parse_wikidata_film(ent, &resolve_labels(&refs)))
}

/// The P453 (character role) Q-ids qualifying a film's cast claims -
/// resolved in the same label call as the cast themselves.
fn character_qids(ent: &serde_json::Value) -> Vec<String> {
    ent["claims"]["P161"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| {
                    c["qualifiers"]["P453"].as_array()?.first()?["datavalue"]["value"]["id"]
                        .as_str()
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Q-ids → names, serving what the process has already seen from cache
/// and asking Wikidata only for the rest.
///
/// Asks for `en|mul`, not `en`. Wikidata's newer convention is to store a
/// name that is the same in every language ONCE, under the `mul`
/// (multilingual) code, instead of duplicating it per language - and
/// modern film items increasingly do. Measured 26 Jul 2026: Top Gun:
/// Maverick (Q31202708) has NO `en` label at all, only `mul`. Asking for
/// English alone silently drops every such entity, which on a person page
/// meant losing 7 of Tom Cruise's 60 credits without a trace.
fn resolve_labels(ids: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut want: Vec<String> = Vec::new();
    {
        let cache = label_cache().lock().unwrap();
        for q in ids {
            match cache.get(q) {
                Some(name) => {
                    out.insert(q.clone(), name.clone());
                }
                None => want.push(q.clone()),
            }
        }
    }
    // wbgetentities takes at most 50 ids per call, and one call is all
    // this is worth: a film referencing more than that just gets the
    // first 50 resolved.
    want.truncate(50);
    if want.is_empty() {
        return out;
    }
    let Some(v) = get_json_ua(&format!(
        "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json\
         &props=labels&languages=en|mul&ids={}",
        want.join("|")
    )) else {
        return out;
    };
    let mut cache = label_cache().lock().unwrap();
    for q in want {
        let l = &v["entities"][&q]["labels"];
        if let Some(name) = l["en"]["value"].as_str().or(l["mul"]["value"].as_str()) {
            cache.insert(q.clone(), name.to_string());
            out.insert(q, name.to_string());
        }
    }
    out
}

/// What one Wikipedia page summary gives us.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WikiPage {
    /// Lead-section plot text (CC BY-SA; attributed in the wall footer).
    pub extract: String,
    /// The infobox image. For a film article this is the POSTER: it is
    /// non-free artwork hosted on en.wikipedia itself rather than on
    /// Commons, which is why Wikidata cannot carry it and P18 offers
    /// something else instead (see `parse_wikidata_film`).
    pub image: String,
}

/// Does this Wikipedia summary describe a film or a TV work?
///
/// Only consulted for an UNQUALIFIED title, where the article name gives
/// no clue. The REST summary's `description` is the short "2016 American
/// action film" line, and the first sentence of the lead says what the
/// subject is; requiring one of them to name a screen work keeps a stem
/// like "Ambulance" from adopting the road-vehicle article's photo as a
/// poster. Only the start of the extract is examined, so a passing
/// mention of filming further down does not qualify an unrelated page.
fn describes_a_screen_work(v: &serde_json::Value) -> bool {
    const MARKS: [&str; 8] = [
        "film",
        "movie",
        "television series",
        "tv series",
        "miniseries",
        "documentary",
        "anime",
        "sitcom",
    ];
    let desc = v["description"].as_str().unwrap_or("").to_ascii_lowercase();
    let lead: String = v["extract"]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect::<String>()
        .to_ascii_lowercase();
    MARKS.iter().any(|m| desc.contains(m) || lead.contains(m))
}

/// Wikipedia REST summary - plot and poster for a movie the metadata
/// provider could not fully answer. Tries the year-disambiguated page
/// first, since "Dune" and "Dune (2021 film)" are different articles.
pub fn wikipedia_page(title: &str, year: u32) -> Option<WikiPage> {
    let variants = if year > 0 {
        vec![format!("{title} ({year} film)"), format!("{title} (film)"), title.to_string()]
    } else {
        vec![format!("{title} (film)"), title.to_string()]
    };
    for name in variants {
        // The "(2021 film)" and "(film)" forms verify themselves: the
        // article title says what it is. The bare title does not, and it
        // is the last thing tried, so a stem with no year that misses
        // everywhere else landed on whatever article owns that word -
        // "Ambulance" the vehicle, "Sunlight" the phenomenon - and its
        // lead paragraph became the plot and its infobox photo the
        // poster, stamped `checked` so nothing revisited it.
        let self_describing = name != title;
        let url = format!(
            "https://en.wikipedia.org/api/rest_v1/page/summary/{}",
            percent_encode(&name.replace(' ', "_"))
        );
        if let Some(v) = get_json_ua(&url) {
            if v["type"].as_str() == Some("standard")
                && (self_describing || describes_a_screen_work(&v))
            {
                let page = WikiPage {
                    extract: v["extract"].as_str().unwrap_or("").to_string(),
                    image: v["originalimage"]["source"]
                        .as_str()
                        .or(v["thumbnail"]["source"].as_str())
                        .unwrap_or("")
                        .to_string(),
                };
                // A disambiguation-ish hit with neither text nor art is
                // not an answer - keep trying the other title forms.
                if !page.extract.is_empty() || !page.image.is_empty() {
                    return Some(page);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    None
}

/// Plot only - the shape every caller wanted before posters came from
/// here too.
pub fn wikipedia_summary(title: &str, year: u32) -> Option<String> {
    wikipedia_page(title, year).map(|p| p.extract).filter(|e| !e.is_empty())
}

/// Pure parse of an AniList GraphQL Media response (tested).
fn parse_anilist(v: &serde_json::Value) -> Option<TitleMeta> {
    let m = &v["data"]["Media"];
    let id = m["id"].as_i64()?;
    Some(TitleMeta {
        tmdb_id: id,
        overview: strip_tags(m["description"].as_str().unwrap_or("")),
        rating: m["averageScore"].as_f64().unwrap_or(0.0) / 10.0,
        genres: m["genres"]
            .as_array()
            .map(|g| g.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default(),
        poster_url: m["coverImage"]["extraLarge"]
            .as_str()
            .or(m["coverImage"]["large"].as_str())
            .unwrap_or("")
            .to_string(),
        backdrop_url: m["bannerImage"].as_str().unwrap_or("").to_string(),
        imdb: String::new(),
        actors: String::new(),
        // AniList sends the date split into fields, and any of them can be
        // null on an unannounced show - all three or nothing.
        air_date: match (
            m["startDate"]["year"].as_i64(),
            m["startDate"]["month"].as_i64(),
            m["startDate"]["day"].as_i64(),
        ) {
            (Some(y), Some(mo), Some(d)) => iso_date(&format!("{y:04}-{mo:02}-{d:02}")),
            _ => String::new(),
        },
        credits: Vec::new(),
    })
}

/// AniList (keyless GraphQL): anime fallback when TVmaze/iTunes miss -
/// Usenet has plenty of anime groups.
pub fn anilist_lookup(title: &str) -> Option<TitleMeta> {
    let body = serde_json::json!({
        "query": "query($s:String){Media(search:$s,type:ANIME){id \
                  description(asHtml:false) averageScore genres \
                  coverImage{large extraLarge} bannerImage \
                  startDate{year month day}}}",
        "variables": {"s": title},
    });
    let resp = ureq::post("https://graphql.anilist.co")
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send_string(&body.to_string())
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().ok()?).ok()?;
    parse_anilist(&v)
}

/// Parse IMDb's title.ratings TSV (tconst\taverageRating\tnumVotes),
/// keeping rows with ≥ `min_votes` - drops the long tail of 1-vote
/// entries and shrinks 1.5M rows to a few hundred k (tested).
// ---------------------------------------------------------------------------
// Music (MusicBrainz + Cover Art Archive) and books (OpenLibrary).
//
// Both keyless, both probed live on 26 Jul 2026 before a line of this
// was written. MusicBrainz REQUIRES a descriptive User-Agent and
// enforces roughly one request per second - it blocks clients that
// ignore that, so the calls here go through `ratelimit`, not through
// the enricher's sleep-between-titles pacing.
//
// FIELD REUSE IS DELIBERATE, NOT A BUG. `TitleMeta` has eight fields
// built for film and TV, and rather than widen the schema for two more
// kinds we map onto the ones that already read correctly on a card:
//
//   artist / author       -> `actors`   (the card renders it as a credit
//                                        line under the title, which is
//                                        exactly what "by Frank Herbert"
//                                        or "Pink Floyd" wants to be)
//   MB genres / OL subjects -> `genres`
//   first release / publish -> `air_date`
//
// Anyone reading `actors` on a music row and assuming a bug: it is not.
// ---------------------------------------------------------------------------

use crate::ratelimit::{self, Provider};

/// `TitleMeta.tmdb_id` is an i64 and doubles as the "a provider matched
/// this" flag (`titles_missing_date` filters on `tmdb_id <> 0`, and the
/// wall's card treats it as matched). MusicBrainz ids are UUIDs and
/// OpenLibrary keys are strings, so neither fits - a stable hash keeps
/// the found/not-found semantics and stays the same across runs. Never
/// use it to address the provider again; it is a flag, not an id.
fn provider_flag_id(s: &str) -> i64 {
    // FNV-1a, masked to 63 bits so it is always positive.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    ((h & 0x7fff_ffff_ffff_ffff) as i64).max(1)
}

/// Paced, UA-bearing JSON GET. A 429/503 is the provider telling us we
/// are going too fast; the bucket is penalised so the whole lane slows
/// down, not just this one call.
///
/// The retries are patient on purpose. MusicBrainz answers 503 "the
/// server is currently busy" routinely rather than exceptionally -
/// measured, three requests in a row drew one - and the enricher stamps
/// a title `checked` when a lookup returns None, never looking at it
/// again. So on this lane a moment of upstream busyness would otherwise
/// blank an album permanently. Waiting out ~50 s in a background worker
/// is cheap; losing the card is not.
fn get_json_paced(p: Provider, url: &str) -> Option<serde_json::Value> {
    const BACKOFF_SECS: [u64; 3] = [5, 15, 30];
    for attempt in 0..=BACKOFF_SECS.len() {
        ratelimit::acquire(p);
        match crate::serve::shared_enrich_agent().get(url)
            .set("User-Agent", WIKI_UA)
            .timeout(std::time::Duration::from_secs(10))
            .call()
        {
            Ok(resp) => {
                // Cap the body like `fetch_image` does: a provider that
                // answers with something enormous should cost us memory
                // no faster than one that answers correctly.
                let mut body = String::new();
                use std::io::Read;
                if resp
                    .into_reader()
                    .take(4 * 1024 * 1024)
                    .read_to_string(&mut body)
                    .is_err()
                {
                    note_unreachable();
                    return None;
                }
                return serde_json::from_str(&body).ok();
            }
            Err(ureq::Error::Status(code, r)) if matches!(code, 429 | 503) => {
                let wait = r
                    .header("Retry-After")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(BACKOFF_SECS[attempt.min(BACKOFF_SECS.len() - 1)]);
                ratelimit::penalise(p, wait);
                if attempt == BACKOFF_SECS.len() {
                    // Still busy after ~50 s. That is "we could not ask",
                    // which is exactly what this function's patience is
                    // for - do not let the caller record it as "nothing".
                    note_unreachable();
                    return None;
                }
            }
            Err(e) => {
                note_http_err(&e);
                return None;
            }
        }
    }
    note_unreachable();
    None
}

/// Comma-join at most `n` names, skipping blanks and duplicates.
fn join_names(it: impl Iterator<Item = String>, n: usize) -> String {
    let mut out: Vec<String> = Vec::new();
    for name in it {
        let name = name.trim().to_string();
        if name.is_empty() || out.iter().any(|x: &String| x.eq_ignore_ascii_case(&name)) {
            continue;
        }
        out.push(name);
        if out.len() == n {
            break;
        }
    }
    out.join(", ")
}

/// Pick the best release-group from a MusicBrainz search (tested pure).
///
/// MusicBrainz returns a `score`, but score alone is not enough: a
/// search for one album returns every release group whose title merely
/// contains the words, all at similar scores. The album title has to
/// match after normalisation or a card gets the wrong cover - the same
/// failure OpenLibrary has, where asking for "Dune" ranks "Children of
/// Dune" first.
fn pick_release_group(v: &serde_json::Value, album: &str) -> Option<serde_json::Value> {
    let want = norm_title(album);
    let groups = v["release-groups"].as_array()?;
    let mut fallback: Option<&serde_json::Value> = None;
    for g in groups {
        let title = g["title"].as_str().unwrap_or("");
        if norm_title(title) == want {
            return Some(g.clone());
        }
        // Highest-scoring near-miss, kept only if nothing matches
        // exactly and it is a strong hit - a scene stem drops
        // punctuation and subtitles, so an exact match is not always
        // available for a correct answer.
        if g["score"].as_i64().unwrap_or(0) >= 90 && fallback.is_none() {
            fallback = Some(g);
        }
    }
    fallback.cloned()
}

/// Pure parse of one MusicBrainz release-group into a card (tested).
fn parse_release_group(g: &serde_json::Value) -> Option<TitleMeta> {
    let mbid = g["id"].as_str()?;
    let artist = join_names(
        g["artist-credit"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c["name"].as_str().map(String::from)),
        4,
    );
    // The search response carries no genres; the lookup below adds them.
    // `primary-type` is the honest one-liner we can build without a
    // second call - "Album", "Live", "Compilation".
    let kind = g["primary-type"].as_str().unwrap_or("").to_string();
    let overview = match (kind.is_empty(), artist.is_empty()) {
        (false, false) => format!("{kind} by {artist}"),
        (false, true) => kind,
        _ => String::new(),
    };
    Some(TitleMeta {
        tmdb_id: provider_flag_id(mbid),
        overview,
        rating: 0.0,
        genres: String::new(),
        poster_url: String::new(),
        backdrop_url: String::new(),
        imdb: String::new(),
        actors: artist,
        air_date: iso_date(g["first-release-date"].as_str().unwrap_or("")),
        credits: Vec::new(),
    })
}

/// MusicBrainz release-group search, then the group's genres, then the
/// Cover Art Archive front cover. Three paced calls at most.
pub fn musicbrainz_lookup(artist: &str, album: &str) -> Option<TitleMeta> {
    // "VA" is the scene's tag for a various-artists compilation and
    // means nothing to MusicBrainz, which files them under an artist
    // literally named "Various Artists".
    let artist = if artist.eq_ignore_ascii_case("va") { "Various Artists" } else { artist };
    // Fail CLOSED without an artist. `credit_split` returns None on a
    // stem it cannot split, and the caller then passes "" - which made
    // this send `artist:""`, a clause Lucene simply ignores, so the
    // search degenerated to "any release called X". Verified live:
    // album "Nevermind" with no artist returns Red Hot Chili Peppers at
    // score 100, "Thriller" a Richard Grey single. The enricher stamps
    // `checked` one-shot, so a wrong artist, date, overview and cover
    // stick to that title permanently. The book sibling already guards
    // this way. No metadata beats confidently wrong metadata.
    if artist.trim().is_empty() || album.trim().is_empty() {
        return None;
    }
    // Lucene: a bare quote closes the phrase and lets the rest of a
    // release name become query syntax. Backslash first, or it escapes
    // the escapes.
    let lucene = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let query = format!(
        "release:\"{}\" AND artist:\"{}\"",
        lucene(album),
        lucene(artist)
    );
    let search = get_json_paced(
        Provider::MusicBrainz,
        &format!(
            "https://musicbrainz.org/ws/2/release-group?query={}&fmt=json&limit=5",
            percent_encode(&query)
        ),
    )?;
    let group = pick_release_group(&search, album)?;
    let mut meta = parse_release_group(&group)?;
    let mbid = group["id"].as_str()?.to_string();

    // Genres live on the release-group lookup, not on search. MB's
    // `genres` are the curated vocabulary; `tags` are raw user text and
    // measured to be noise ("1973", "5+ wochen", "britannique"), so only
    // genres are read.
    if let Some(full) = get_json_paced(
        Provider::MusicBrainz,
        &format!("https://musicbrainz.org/ws/2/release-group/{mbid}?inc=genres&fmt=json"),
    ) {
        meta.genres = join_names(
            full["genres"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|g| g["name"].as_str().map(title_case)),
            4,
        );
    }
    meta.poster_url = coverart_front(&mbid);
    Some(meta)
}

/// Front cover URL for a release group, or empty. Not every release
/// group has art, and a 404 here is ordinary, not an error.
pub fn coverart_front(mbid: &str) -> String {
    let Some(v) = get_json_paced(
        Provider::CoverArt,
        &format!("https://coverartarchive.org/release-group/{mbid}"),
    ) else {
        return String::new();
    };
    parse_coverart(&v)
}

/// Pure pick of the front cover from a Cover Art Archive index (tested).
/// Prefers the 500px thumbnail over the full-size scan, which can be a
/// 20 MB flatbed image of a gatefold sleeve.
fn parse_coverart(v: &serde_json::Value) -> String {
    let images = v["images"].as_array().map(Vec::as_slice).unwrap_or_default();
    let front = images
        .iter()
        .find(|i| i["front"].as_bool() == Some(true))
        .or_else(|| images.first());
    let Some(img) = front else {
        return String::new();
    };
    let url = img["thumbnails"]["500"]
        .as_str()
        .or_else(|| img["thumbnails"]["large"].as_str())
        .or_else(|| img["image"].as_str())
        .unwrap_or("");
    // The archive answers with http:// URLs in its JSON even though it
    // serves https perfectly well. Upgrade rather than fetch artwork in
    // the clear.
    match url.strip_prefix("http://") {
        Some(rest) => format!("https://{rest}"),
        None => url.to_string(),
    }
}

/// OpenLibrary subjects are long and full of shelving noise
/// ("Reading Level-Grade 7", "Fiction in English", "Accessible book").
/// Keep the short, genre-shaped ones.
fn useful_subject(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    s.len() <= 24
        && !s.contains(',')
        // "Dune (Imaginary Place)" - a catalogue cross-reference, not a
        // genre. Measured on the live service.
        && !s.contains('(')
        && !l.starts_with("reading level")
        && !l.contains("accessible")
        && !l.contains("in english")
        && !l.contains("protected daisy")
        && !l.contains("large type")
        && !l.contains("overdrive")
        // "New York Times Reviewed", "Times bestseller" - shelf badges.
        && !l.contains("reviewed")
        && !l.contains("bestseller")
}

/// True when a name is written mostly in Latin script. OpenLibrary
/// lists an author's name variants in `author_name` alongside any real
/// co-authors, so a single-author book comes back as
/// "Frank Herbert, Френк Герберт" - the transliteration is a duplicate,
/// not a second author, and it reads as noise on the credit line. Keeping
/// only Latin names once we have one drops the variants while leaving a
/// genuinely non-Latin author (who has no Latin form to prefer) intact.
fn mostly_latin(s: &str) -> bool {
    let letters = s.chars().filter(|c| c.is_alphabetic()).count();
    let latin = s.chars().filter(|c| c.is_alphabetic() && c.is_ascii()).count();
    letters == 0 || latin * 2 >= letters
}

/// Pick and parse the best OpenLibrary hit (tested pure).
///
/// The re-ranking is the point of this function, not a refinement:
/// OpenLibrary's own relevance order answers `title=Dune&author=Frank
/// Herbert` with "Children of Dune" first and the actual "Dune" seventh
/// (measured). Taking `docs[0]` would put the wrong cover on the card
/// every time a book is part of a series.
fn parse_openlibrary(v: &serde_json::Value, title: &str) -> Option<TitleMeta> {
    let want = norm_title(title);
    let docs = v["docs"].as_array()?;
    let best = docs
        .iter()
        .filter(|d| d["cover_i"].as_i64().is_some() || d["title"].as_str().is_some())
        .max_by_key(|d| {
            let t = norm_title(d["title"].as_str().unwrap_or(""));
            // Exact normalised title wins outright; among equals, the
            // most-published edition is the canonical work.
            let exact = i64::from(t == want) * 1_000_000;
            let starts = i64::from(t.starts_with(&want)) * 100_000;
            exact + starts + d["edition_count"].as_i64().unwrap_or(0).min(99_999)
        })?;
    // Nothing matched even loosely - better no card than the wrong book.
    let btitle = norm_title(best["title"].as_str().unwrap_or(""));
    if !btitle.starts_with(&want) && !want.starts_with(&btitle) {
        return None;
    }
    let names: Vec<String> = best["author_name"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str().map(String::from))
        .collect();
    let any_latin = names.iter().any(|n| mostly_latin(n));
    let author = join_names(
        names.into_iter().filter(|n| !any_latin || mostly_latin(n)),
        3,
    );
    let genres = join_names(
        best["subject"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str())
            .filter(|s| useful_subject(s))
            .map(title_case),
        4,
    );
    // Deliberately NOT `first_sentence`. It is not language-tagged and
    // OpenLibrary returns whichever edition it happens to hold first:
    // measured live, "Project Hail Mary" came back as "Was ist zwei plus
    // zwei?" - the German edition's opening line, on an English card.
    // A short factual line is always right, and matches the shape the
    // music provider produces ("Album by Pink Floyd").
    let overview = if author.is_empty() {
        String::new()
    } else {
        format!("Book by {author}")
    };
    let key = best["key"].as_str().unwrap_or(best["title"].as_str().unwrap_or(""));
    let poster_url = best["cover_i"]
        .as_i64()
        .map(|id| format!("https://covers.openlibrary.org/b/id/{id}-L.jpg"))
        .unwrap_or_default();
    Some(TitleMeta {
        tmdb_id: provider_flag_id(key),
        overview,
        // OpenLibrary rates out of 5; every other provider here (and the
        // IMDb snapshot the card shares a star with) is out of 10.
        rating: best["ratings_average"].as_f64().map(|r| r * 2.0).unwrap_or(0.0),
        genres,
        poster_url,
        backdrop_url: String::new(),
        imdb: String::new(),
        actors: author,
        // Only a year is published, and a bare "YYYY" is deliberate: the
        // column is sorted as a plain string and a year is a correct
        // ISO prefix, so it orders against full dates properly. Padding
        // it to "YYYY-01-01" would invent a day we do not know.
        air_date: best["first_publish_year"]
            .as_i64()
            .filter(|y| (1000..=9999).contains(y))
            .map(|y| y.to_string())
            .unwrap_or_default(),
        credits: Vec::new(),
    })
}

/// OpenLibrary search for a book by author + title.
pub fn openlibrary_lookup(author: &str, title: &str) -> Option<TitleMeta> {
    let mut url = format!(
        "https://openlibrary.org/search.json?title={}&limit=10\
         &fields=title,author_name,first_publish_year,cover_i,subject,\
ratings_average,edition_count,key",
        percent_encode(title)
    );
    if !author.is_empty() {
        let _ = write!(url, "&author={}", percent_encode(author));
    }
    let v = get_json_paced(Provider::OpenLibrary, &url)?;
    parse_openlibrary(&v, title)
}

/// Lowercase scene text ("progressive rock") reads badly next to the
/// other providers' genre lists, which are already capitalised.
fn title_case(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn parse_imdb_ratings(tsv: &str, min_votes: u64) -> Vec<(String, f64, u64)> {
    tsv.lines()
        .skip(1) // header
        .filter_map(|l| {
            let mut f = l.split('\t');
            let t = f.next()?;
            let r: f64 = f.next()?.parse().ok()?;
            let v: u64 = f.next()?.parse().ok()?;
            (v >= min_votes).then(|| (t.to_string(), r, v))
        })
        .collect()
}

/// Download + gunzip the daily IMDb ratings snapshot (keyless; IMDb's
/// official non-commercial datasets - credited in the wall footer).
pub fn imdb_ratings_fetch() -> Option<Vec<(String, f64, u64)>> {
    let resp = crate::serve::shared_enrich_agent().get("https://datasets.imdbws.com/title.ratings.tsv.gz")
        .timeout(std::time::Duration::from_secs(120))
        .call()
        .ok()?;
    let mut gz = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(64 * 1024 * 1024)
        .read_to_end(&mut gz)
        .ok()?;
    let mut tsv = String::new();
    flate2::read::GzDecoder::new(&gz[..]).read_to_string(&mut tsv).ok()?;
    Some(parse_imdb_ratings(&tsv, 100))
}

/// Fetch a poster/backdrop image by full URL (any provider). Routed
/// through the SSRF-guarded agent: metadata providers are public hosts,
/// and a "set poster from URL" value must not become a request into the
/// host's own network (cloud metadata, LAN services).
pub fn fetch_image(url: &str) -> Option<Vec<u8>> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return None;
    }
    // 15 s, as when this built its own agent: the shared one's default is
    // longer, and an art fetch should not inherit it.
    let resp = crate::serve::shared_enrich_agent()
        .get(url)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .ok()?;
    let mut bytes = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(4 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .ok()?;
    (!bytes.is_empty()).then_some(bytes)
}

// ---------------------------------------------------------------------------
// Filmography: the person page's "not in your index" half.
//
// Two sources because neither is a filmography on its own. TVmaze's
// castcredits endpoint is TV ONLY - measured live, Adam Scott comes back
// with 8 credits, a fraction of his real body of work - and Wikidata's
// reverse cast lookup is the film half. Both are keyless; both are
// on-demand only. In particular Wikidata's SPARQL service is rate-limited
// with a query timeout, which is fine for one person page and wrong for
// any kind of bulk backfill.
// ---------------------------------------------------------------------------

/// One credit on a person's filmography, wherever it came from.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FilmoEntry {
    pub title: String,
    /// ISO date, or a bare "YYYY", or empty - providers give all three.
    pub date: String,
    pub year: u32,
    /// "tv" | "movie".
    pub kind: String,
    pub character: String,
    pub source: String,
}

/// Sort a filmography newest-first with undated credits LAST.
///
/// Not a detail: many Wikidata rows carry no P577 at all, and a plain
/// descending sort on a possibly-empty string puts every one of them at
/// the head of the list, which reads as "these are the newest".
fn sort_filmography(v: &mut [FilmoEntry]) {
    v.sort_by(|a, b| {
        a.date
            .is_empty()
            .cmp(&b.date.is_empty())
            .then_with(|| b.date.cmp(&a.date))
            .then_with(|| a.title.cmp(&b.title))
    });
}

/// Pure parse of a TVmaze `/people/:id/castcredits?embed=show` response
/// (tested).
fn parse_tvmaze_castcredits(v: &serde_json::Value) -> Vec<FilmoEntry> {
    v.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|c| {
                    let show = &c["_embedded"]["show"];
                    let title = show["name"].as_str().filter(|n| !n.is_empty())?;
                    let date = iso_date(show["premiered"].as_str().unwrap_or(""));
                    Some(FilmoEntry {
                        title: title.to_string(),
                        year: date.get(..4).and_then(|y| y.parse().ok()).unwrap_or(0),
                        date,
                        kind: "tv".into(),
                        // The character rides on the link, not the
                        // embed - TVmaze only embeds one relation.
                        character: c["_links"]["character"]["name"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        source: "tvmaze".into(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every TV show a TVmaze person id has acted in. `None` = the service
/// did not answer, which is NOT the same as "they have no TV credits".
pub fn tvmaze_filmography(person_id: i64) -> Option<Vec<FilmoEntry>> {
    get_json(&format!(
        "https://api.tvmaze.com/people/{person_id}/castcredits?embed=show"
    ))
    .map(|v| parse_tvmaze_castcredits(&v))
}

/// Pure parse of a Wikidata SPARQL result set into film credits
/// (tested).
///
/// Two measured hazards, both handled here rather than by the caller:
///
/// - **The result mixes TV in with film.** A Keanu Reeves query really
///   does return "The Fresh Prince of Bel-Air" and "American Chopper" -
///   P161 (cast member) is not film-specific. Rows are kept only when
///   their P31 is one of `FILM_CLASSES`, the same list the movie
///   provider already picks entities with.
/// - **One film yields several rows**, because it has several P31 values
///   and often several P577 dates. Deduped by entity, keeping the
///   earliest date.
pub fn parse_sparql_filmography(v: &serde_json::Value) -> Vec<FilmoEntry> {
    let last = |uri: &str| uri.rsplit('/').next().unwrap_or("").to_string();
    let mut by_entity: HashMap<String, FilmoEntry> = HashMap::new();
    let mut is_film: std::collections::HashSet<String> = std::collections::HashSet::new();
    for row in v["results"]["bindings"].as_array().into_iter().flatten() {
        let Some(qid) = row["film"]["value"].as_str().map(last) else {
            continue;
        };
        if row["class"]["value"]
            .as_str()
            .map(last)
            .is_some_and(|c| FILM_CLASSES.contains(&c.as_str()))
        {
            is_film.insert(qid.clone());
        }
        let title = row["filmLabel"]["value"].as_str().unwrap_or("");
        // An unresolved label comes back as the bare Q-id; a person page
        // listing "Q157443" is worse than one fewer credit.
        if title.is_empty() || title == qid {
            continue;
        }
        let date = wikidata_iso(row["date"]["value"].as_str().unwrap_or(""));
        let e = by_entity.entry(qid).or_insert_with(|| FilmoEntry {
            title: title.to_string(),
            kind: "movie".into(),
            source: "wikidata".into(),
            ..Default::default()
        });
        // A film is released per territory; the one that matters is the
        // first.
        if !date.is_empty() && (e.date.is_empty() || date < e.date) {
            e.year = date.get(..4).and_then(|y| y.parse().ok()).unwrap_or(0);
            e.date = date;
        }
    }
    let mut out: Vec<FilmoEntry> =
        by_entity.into_iter().filter(|(q, _)| is_film.contains(q)).map(|(_, e)| e).collect();
    sort_filmography(&mut out);
    out
}

/// Every film a Wikidata Q-id is credited in, via the public SPARQL
/// endpoint. `None` = the service did not answer.
///
/// That distinction earned itself: the endpoint is rate-limited with a
/// query timeout, and it really does refuse one call and serve the next.
/// Collapsing a refusal into an empty list makes the page say "you
/// already have everything" about an actor with fifty films.
///
/// The label language is `"en,mul"`, not `"en"` - see `resolve_labels`
/// for why. Measured on this exact query: `"en"` alone lost 7 of Tom
/// Cruise's 60 credits, including Top Gun: Maverick.
pub fn wikidata_filmography(qid: &str) -> Option<Vec<FilmoEntry>> {
    if !qid.starts_with('Q') || qid.len() < 2 || !qid[1..].bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    // LIMIT keeps a prolific actor inside the service's query timeout.
    let query = format!(
        "SELECT ?film ?filmLabel ?date ?class WHERE {{ \
           ?film wdt:P161 wd:{qid} . \
           OPTIONAL {{ ?film wdt:P577 ?date }} \
           OPTIONAL {{ ?film wdt:P31 ?class }} \
           SERVICE wikibase:label {{ bd:serviceParam wikibase:language \"en,mul\" }} \
         }} LIMIT 400"
    );
    let resp = crate::serve::shared_enrich_agent().get(&format!(
        "https://query.wikidata.org/sparql?query={}",
        percent_encode(&query)
    ))
    .set("User-Agent", WIKI_UA)
    .set("Accept", "application/sparql-results+json")
    // Longer than the metadata calls on purpose: SPARQL is a query
    // engine, not a document fetch, and a busy service is slow before it
    // is unavailable.
    .timeout(std::time::Duration::from_secs(30))
    .call()
    .ok()?;
    let body = resp.into_string().ok()?;
    serde_json::from_str(&body)
        .ok()
        .map(|v: serde_json::Value| parse_sparql_filmography(&v))
}

/// Both halves of a person's filmography, fetched concurrently because
/// they are different services with different limits.
///
/// The bool is "every source we asked actually answered". False means the
/// list is short because a provider declined, not because the person has
/// no more credits - and the page has to say so rather than presenting a
/// partial list as complete.
pub fn person_filmography(tvmaze_id: i64, qid: &str) -> (Vec<FilmoEntry>, bool) {
    let (mut out, complete) = std::thread::scope(|s| {
        let tv = s.spawn(move || (tvmaze_id > 0).then(|| tvmaze_filmography(tvmaze_id)));
        let film = (!qid.is_empty()).then(|| wikidata_filmography(qid));
        let tv = tv.join().unwrap_or(None);
        // `Some(None)` is "asked, and it did not answer"; `None` is "there
        // was no handle to ask with", which is not a failure.
        let complete = !matches!(tv, Some(None)) && !matches!(film, Some(None));
        let mut out = film.flatten().unwrap_or_default();
        out.extend(tv.flatten().unwrap_or_default());
        (out, complete)
    });
    sort_filmography(&mut out);
    (out, complete)
}

/// Art-cache filename for a person's headshot. Shares the art directory
/// with posters, so the name has to be distinguishable from one: the "p"
/// prefix plus digits can never collide with `art_name`'s output, which
/// always starts with a title key's kind letter and its separator
/// underscore ("m_", "t_", "c_").
pub fn person_art_name(id: i64) -> String {
    format!("p{id}.jpg")
}

/// Is this art-directory entry an evictable headshot? Posters and
/// backdrops must never match - they are the wall itself, and nothing
/// re-fetches them on demand.
pub fn is_person_art_name(name: &str) -> bool {
    // The lazy "thumb_" variant counts too: nothing asks for one today,
    // but the /art/ route will make one for any name, and an evictable
    // file whose thumbnail is not evictable is a cache that leaks.
    name.strip_prefix("thumb_")
        .unwrap_or(name)
        .strip_prefix('p')
        .and_then(|r| r.strip_suffix(".jpg"))
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Art-cache filename for a title key (safe, flat, deterministic).
pub fn art_name(key: &str, backdrop: bool) -> String {
    let safe: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{safe}{}.jpg", if backdrop { ".bd" } else { "" })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bare-title Wikipedia fallback is the last thing tried for a
    /// movie with no year, and nothing used to check the article was
    /// about a film - so an obfuscated stem parsed as "Ambulance" took
    /// the road-vehicle article's photo as its poster and its lead
    /// paragraph as its plot, then stamped the title checked so nothing
    /// ever revisited it.
    #[test]
    fn only_a_screen_work_may_answer_an_unqualified_title() {
        let page = |desc: &str, extract: &str| {
            serde_json::json!({"description": desc, "extract": extract})
        };
        // Real films and TV, by description or by lead sentence.
        assert!(describes_a_screen_work(&page("2022 American film", "Ambulance is a 2022 film.")));
        assert!(describes_a_screen_work(&page("", "Sunlight is a 2019 Irish film directed by …")));
        assert!(describes_a_screen_work(&page("British television series", "")));
        assert!(describes_a_screen_work(&page("2021 documentary", "")));
        assert!(describes_a_screen_work(&page("anime television series", "")));

        // The articles that were being adopted as posters.
        assert!(!describes_a_screen_work(&page(
            "medical vehicle",
            "An ambulance is a medically equipped vehicle which transports patients."
        )));
        assert!(!describes_a_screen_work(&page(
            "electromagnetic radiation",
            "Sunlight is a portion of the electromagnetic radiation given off by the Sun."
        )));
        assert!(!describes_a_screen_work(&page("", "")));

        // A mention of filming far down the article does not qualify it:
        // only the start of the lead is examined.
        let buried = format!("{} It was later filmed for television.", "x".repeat(400));
        assert!(!describes_a_screen_work(&page("river in Norway", &buried)));
    }

    fn p(stem: &str) -> Parsed {
        parse_release(stem)
    }

    #[test]
    fn tvmaze_episode_parse() {
        let v: serde_json::Value = serde_json::from_str(
            r#"[
              {"season":1,"number":1,"name":"Good News About Hell","airdate":"2022-02-18"},
              {"season":1,"number":null,"name":"Special","airdate":"2022-03-01"},
              {"season":3,"number":5,"name":"","airdate":""}
            ]"#,
        )
        .unwrap();
        let eps = parse_tvmaze_episodes(&v);
        assert_eq!(eps.len(), 2); // the special (null number) is dropped
        assert_eq!(eps[0].season, 1);
        assert_eq!(eps[0].episode, 1);
        assert_eq!(eps[0].airdate, "2022-02-18");
        assert_eq!(eps[1].season, 3);
        assert_eq!(eps[1].airdate, "");
    }

    #[test]
    fn provider_dates_normalise_to_iso() {
        // ISO, plus the datetime form iTunes sends.
        assert_eq!(iso_date("1999-03-30"), "1999-03-30");
        assert_eq!(iso_date("1999-03-30T08:00:00Z"), "1999-03-30");
        assert_eq!(iso_date("  1999-03-30  "), "1999-03-30");
        // OMDb's human form, zero-padded on the way in.
        assert_eq!(iso_date("30 Mar 1999"), "1999-03-30");
        assert_eq!(iso_date("5 Jan 2026"), "2026-01-05");
        // Anything we can't place is dropped, NOT stored: the column is
        // sorted as a plain string, so one stray format would misorder
        // every card around it.
        for junk in ["", "N/A", "1999", "1999-03", "March 1999", "30 Foo 1999",
                     "32 Mar 1999", "30 Mar 99"] {
            assert_eq!(iso_date(junk), "", "{junk:?}");
        }
    }

    #[test]
    fn art_names_are_flat_and_safe() {
        assert_eq!(art_name("m:the matrix:1999", false), "m_the_matrix_1999.jpg");
        assert_eq!(art_name("t:severance", true), "t_severance.bd.jpg");
    }

    #[test]
    fn tvmaze_response_parses() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"id":431,"name":"Severance","genres":["Drama","Science-Fiction"],
                "rating":{"average":8.3},
                "image":{"medium":"https://static.tvmaze.com/m.jpg",
                         "original":"https://static.tvmaze.com/o.jpg"},
                "summary":"<p>Mark leads a team.</p>"}"#,
        )
        .unwrap();
        let m = parse_tvmaze(&v).unwrap();
        assert_eq!(m.tmdb_id, 431);
        assert_eq!(m.overview, "Mark leads a team.");
        assert_eq!(m.rating, 8.3);
        assert_eq!(m.genres, "Drama, Science-Fiction");
        assert_eq!(m.poster_url, "https://static.tvmaze.com/m.jpg");
        assert_eq!(m.backdrop_url, "https://static.tvmaze.com/o.jpg");
    }

    #[test]
    fn candidate_searches_parse() {
        let tv: serde_json::Value = serde_json::from_str(
            r#"[{"score":0.9,"show":{"id":431,"name":"Severance","premiered":"2022-02-18",
                 "genres":["Drama"],"rating":{"average":8.3},
                 "image":{"medium":"https://s.tvmaze.com/m.jpg","original":"https://s.tvmaze.com/o.jpg"},
                 "summary":"<p>Mark leads.</p>"}},
                {"score":0.5,"show":{"id":99,"name":"Severance (1998)","premiered":null,
                 "genres":[],"rating":{},"image":null,"summary":null}}]"#,
        )
        .unwrap();
        let c = parse_tvmaze_search(&tv);
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].id, c[0].year, c[0].kind.as_str()), (431, 2022, "tv"));
        assert_eq!(c[0].overview, "Mark leads.");
        assert_eq!(c[0].provider, "tvmaze");
        assert_eq!(c[1].year, 0);

        let tm: serde_json::Value = serde_json::from_str(
            r#"{"results":[{"id":603,"title":"The Matrix","release_date":"1999-03-30",
                 "overview":"Neo.","vote_average":8.2,"genre_ids":[878,28],
                 "poster_path":"/p.jpg","backdrop_path":"/b.jpg"}]}"#,
        )
        .unwrap();
        let c = parse_tmdb_search(&tm, &Kind::Movie);
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].id, c[0].year, c[0].kind.as_str()), (603, 1999, "movie"));
        assert_eq!(c[0].genres, "Sci-Fi, Action");
        assert_eq!(c[0].poster_url, "https://image.tmdb.org/t/p/w342/p.jpg");
        assert_eq!(c[0].provider, "tmdb");
    }

    #[test]
    fn tvmaze_cast_and_externals_parse() {
        // The `_embedded` shape of the ONE call that replaced the old
        // lookup + /cast pair. Fixture fields are the live ones (probed
        // 26 Jul 2026): person id, headshot, character name, voice flag,
        // and crew with a free-text `type`.
        let emb: serde_json::Value = serde_json::from_str(
            r#"{"cast":[
                  {"person":{"id":29657,"name":"Adam Scott",
                             "image":{"medium":"https://static.tvmaze.com/a.jpg"}},
                   "character":{"name":"Mark Scout"},"voice":false},
                  {"person":{"id":1,"name":"Britt Lower"},
                   "character":{"name":"Helly R"},"voice":true},
                  {"person":{"id":2,"name":"Zach Cherry"},"character":{"name":"Dylan G"}},
                  {"person":{"name":"   "},"character":{"name":"Nobody"}}],
                "crew":[
                  {"type":"Unit Production Manager","person":{"id":90,"name":"U P M"}},
                  {"type":"Creator","person":{"id":91,"name":"Dan Erickson"}},
                  {"type":"","person":{"id":92,"name":"No Role"}}]}"#,
        )
        .unwrap();
        let cr = parse_tvmaze_credits(&emb);
        // The nameless entry is dropped, not credited as "".
        let cast: Vec<&Credit> = cr.iter().filter(|c| c.role == "actor").collect();
        assert_eq!(cast.len(), 3);
        assert_eq!(cast[0].name, "Adam Scott");
        assert_eq!(cast[0].tvmaze_id, 29657);
        assert_eq!(cast[0].character, "Mark Scout");
        assert_eq!(cast[0].photo, "https://static.tvmaze.com/a.jpg");
        // Billing order is position, 1-based so 0 still means "unranked".
        assert_eq!((cast[0].ord, cast[2].ord), (1, 3));
        // A voice role stays visible without a schema column for it.
        assert_eq!(cast[1].character, "Helly R (voice)");
        // The credit line is the same string the cards always showed.
        assert_eq!(credit_line(&cr, 8), "Adam Scott, Britt Lower, Zach Cherry");
        // Crew: the role-less entry is dropped and the creator outranks
        // the production manager, so a cap keeps the useful one.
        let crew: Vec<&Credit> = cr.iter().filter(|c| c.role != "actor").collect();
        assert_eq!(crew.len(), 2);
        assert_eq!((crew[0].name.as_str(), crew[0].role.as_str()), ("Dan Erickson", "creator"));
        let show: serde_json::Value = serde_json::from_str(
            r#"{"id":431,"externals":{"imdb":"tt11280740"},"summary":"<p>x</p>"}"#,
        )
        .unwrap();
        assert_eq!(parse_tvmaze(&show).unwrap().imdb, "tt11280740");
    }

    #[test]
    fn wikidata_credits_read_the_qualifiers_we_used_to_drop() {
        // Shape taken from the live Matrix entity (Q83495): P453 is the
        // character-role qualifier, P1545 the billing ordinal, and only
        // SOME cast claims carry either.
        let ent: serde_json::Value = serde_json::from_str(
            r#"{"claims":{
                 "P161":[
                   {"mainsnak":{"datavalue":{"value":{"id":"Q43416"}}},
                    "qualifiers":{"P453":[{"datavalue":{"value":{"id":"Q1750842"}}}],
                                  "P1545":[{"datavalue":{"value":"2"}}]}},
                   {"mainsnak":{"datavalue":{"value":{"id":"Q106508"}}},
                    "qualifiers":{"P1545":[{"datavalue":{"value":"1"}}]}},
                   {"mainsnak":{"datavalue":{"value":{"id":"Q193048"}}}},
                   {"mainsnak":{"datavalue":{"value":{"id":"Q_unlabelled"}}}}],
                 "P57":[{"mainsnak":{"datavalue":{"value":{"id":"Q9545711"}}}}],
                 "P58":[{"mainsnak":{"datavalue":{"value":{"id":"Q195719"}}}}],
                 "P86":[{"mainsnak":{"datavalue":{"value":{"id":"Q207859"}}}}]}}"#,
        )
        .unwrap();
        let labels: HashMap<String, String> = [
            ("Q43416", "Keanu Reeves"),
            ("Q106508", "Laurence Fishburne"),
            ("Q193048", "Carrie-Anne Moss"),
            ("Q1750842", "Neo"),
            ("Q9545711", "Lana Wachowski"),
            ("Q195719", "Lilly Wachowski"),
            ("Q207859", "Don Davis"),
        ]
        .iter()
        .map(|(q, n)| (q.to_string(), n.to_string()))
        .collect();
        let cr = parse_wikidata_credits(&ent, &labels);
        // P1545 IS the billing order, so the ranked pair leads and the
        // unranked one falls in behind rather than jumping the queue.
        let cast: Vec<&str> =
            cr.iter().filter(|c| c.role == "actor").map(|c| c.name.as_str()).collect();
        assert_eq!(cast, ["Laurence Fishburne", "Keanu Reeves", "Carrie-Anne Moss"]);
        // The character qualifier - 9 of 19 on the real entity carry one.
        let neo = cr.iter().find(|c| c.name == "Keanu Reeves").unwrap();
        assert_eq!(neo.character, "Neo");
        assert_eq!(neo.wikidata_qid, "Q43416");
        // A Q-id with no label is dropped, not shown raw.
        assert!(!cr.iter().any(|c| c.name.starts_with('Q')));
        // Crew from claims that were already in the response.
        let role = |n: &str| cr.iter().find(|c| c.name == n).map(|c| c.role.as_str());
        assert_eq!(role("Lana Wachowski"), Some("director"));
        assert_eq!(role("Lilly Wachowski"), Some("writer"));
        assert_eq!(role("Don Davis"), Some("composer"));
    }

    #[test]
    fn episode_parse_keeps_the_synopsis() {
        let v: serde_json::Value = serde_json::from_str(
            r#"[{"season":1,"number":1,"name":"Good News About Hell",
                 "airdate":"2022-02-18","runtime":57,"rating":{"average":8.1},
                 "image":{"medium":"https://static.tvmaze.com/e.jpg"},
                 "summary":"<p>Mark leads a team of <b>four</b>.</p>"}]"#,
        )
        .unwrap();
        let e = &parse_tvmaze_episodes(&v)[0];
        // Provider HTML is stripped here so nothing downstream has to
        // decide whether to trust it as markup.
        assert_eq!(e.summary, "Mark leads a team of four.");
        assert_eq!(e.image, "https://static.tvmaze.com/e.jpg");
        assert_eq!((e.runtime, e.rating), (57, 8.1));
        // Episode lists are cached as JSON in `kv`. A blob written before
        // these fields existed must still deserialize, or the calendar
        // empties itself on upgrade.
        let old: EpInfo =
            serde_json::from_str(r#"{"season":2,"episode":3,"name":"x"}"#).unwrap();
        assert_eq!((old.season, old.episode, old.summary.as_str()), (2, 3, ""));
    }

    #[test]
    fn tvmaze_castcredits_parse() {
        let v: serde_json::Value = serde_json::from_str(
            r#"[{"_links":{"character":{"name":"Emily"}},
                 "_embedded":{"show":{"name":"The Odd Couple","premiered":"2015-02-19",
                                      "type":"Scripted"}}},
                {"_links":{},"_embedded":{"show":{"name":"Unaired","premiered":null}}},
                {"_embedded":{"show":{"name":""}}}]"#,
        )
        .unwrap();
        let f = parse_tvmaze_castcredits(&v);
        assert_eq!(f.len(), 2, "the nameless show is dropped");
        assert_eq!((f[0].title.as_str(), f[0].year, f[0].kind.as_str()),
                   ("The Odd Couple", 2015, "tv"));
        assert_eq!(f[0].character, "Emily");
        assert_eq!(f[1].date, "", "a null premiere is not a date");
    }

    #[test]
    fn sparql_filmography_filters_tv_and_sorts_undated_last() {
        let ent = |q: &str, label: &str, date: Option<&str>, class: &str| {
            let mut o = serde_json::json!({
                "film": {"value": format!("http://www.wikidata.org/entity/{q}")},
                "filmLabel": {"value": label},
                "class": {"value": format!("http://www.wikidata.org/entity/{class}")},
            });
            if let Some(d) = date {
                o["date"] = serde_json::json!({"value": d});
            }
            o
        };
        let v = serde_json::json!({"results": {"bindings": [
            // Two rows for one film: a second P31 and a later territory
            // release. Both must collapse to one entry at the EARLIEST date.
            ent("Q83495", "The Matrix", Some("+1999-03-31T00:00:00Z"), "Q11424"),
            ent("Q83495", "The Matrix", Some("+1999-06-11T00:00:00Z"), "Q24869"),
            // The measured noise: P161 is not film-specific, so a real
            // Keanu Reeves query brings back television.
            ent("Q1204", "The Fresh Prince of Bel-Air", Some("+1990-09-10T00:00:00Z"),
                "Q5398426"),
            // Undated, and a film - kept, but it must not head the list.
            ent("Q999", "Untitled Project", None, "Q11424"),
            // An unresolved label comes back as the bare Q-id. This is
            // what a `mul`-only item looked like before the query asked
            // for "en,mul" - see `resolve_labels`. It has to be dropped
            // rather than listed as "Q777", and the LIVE test is what
            // proves the query no longer produces these.
            ent("Q777", "Q777", Some("+2001-01-01T00:00:00Z"), "Q11424"),
        ]}});
        let f = parse_sparql_filmography(&v);
        let titles: Vec<&str> = f.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["The Matrix", "Untitled Project"]);
        assert_eq!(f[0].date, "1999-03-31", "kept the later territory release");
        assert_eq!(f[0].year, 1999);
        assert_eq!(f[1].date, "");
    }

    #[test]
    fn person_art_names_are_evictable_and_posters_are_not() {
        assert_eq!(person_art_name(42), "p42.jpg");
        assert!(is_person_art_name("p42.jpg"));
        assert!(is_person_art_name("thumb_p42.jpg"));
        // Posters and backdrops share the directory and must NEVER be
        // evicted - nothing re-fetches them on demand.
        for n in [
            "m_the_matrix_1999.jpg",
            "t_severance.bd.jpg",
            "thumb_m_the_matrix_1999.jpg",
            "p.jpg",
            "pilot.jpg",
            "p42.png",
        ] {
            assert!(!is_person_art_name(n), "{n} must not be evictable");
        }
    }

    /// Live smoke test for everything the person page needs, against the
    /// real TVmaze and Wikidata services:
    ///   cargo test -p nzbfast --bin nzbfast -- --ignored cast_and_filmography
    ///
    /// Same reasoning as `keyless_movie_chain_answers_live`, and the same
    /// failure it exists to catch: the movie provider this replaced died
    /// SILENTLY - HTTP 200 with an empty body - so every offline test
    /// above kept passing while the wall quietly stopped getting data.
    /// Parsing fixtures cannot tell you an endpoint stopped answering.
    #[test]
    #[ignore]
    fn cast_and_filmography_answer_live() {
        // 1. The embed call: one request, show + cast + crew.
        let m = tvmaze_lookup_full("Severance").expect("TVmaze found no show for Severance");
        println!(
            "Severance: id={} cast+crew={} actors={:?}",
            m.tmdb_id,
            m.credits.len(),
            m.actors
        );
        assert!(m.tmdb_id > 0, "no show id");
        let cast: Vec<&Credit> = m.credits.iter().filter(|c| c.role == "actor").collect();
        assert!(cast.len() >= 3, "embed returned no cast ({} credits)", m.credits.len());
        assert!(cast.iter().any(|c| c.tvmaze_id > 0), "no person ids - filmography is dead");
        assert!(cast.iter().any(|c| !c.character.is_empty()), "no character names");
        assert!(m.credits.iter().any(|c| c.role != "actor"), "crew embed returned nothing");
        assert!(!m.actors.is_empty(), "no credit line");
        std::thread::sleep(std::time::Duration::from_secs(2));

        // 2. Episode summaries - 19 of 19 on the probe that found this.
        let eps = tvmaze_episodes(m.tmdb_id);
        assert!(!eps.is_empty(), "no episodes");
        let with_summary = eps.iter().filter(|e| !e.summary.is_empty()).count();
        println!("  {} episodes, {with_summary} with a synopsis", eps.len());
        assert!(with_summary > 0, "every episode summary came back empty");
        std::thread::sleep(std::time::Duration::from_secs(2));

        // 3. The TV filmography endpoint, on a person id from step 1.
        let pid = cast.iter().find(|c| c.tvmaze_id > 0).unwrap().tvmaze_id;
        let tv = tvmaze_filmography(pid)
            .unwrap_or_else(|| panic!("castcredits did not answer for person {pid}"));
        println!("  person {pid}: {} TV credits", tv.len());
        assert!(!tv.is_empty(), "castcredits returned nothing for person {pid}");

        // 4. The film half: Wikidata SPARQL. Q43416 is Keanu Reeves -
        // the query whose noise (TV mixed into film results) the parser
        // filters, so a live run also proves the filter still fires.
        let films = wikidata_filmography("Q43416")
            .expect("the SPARQL endpoint did not answer at all");
        println!("  Q43416: {} film credits", films.len());
        assert!(films.len() >= 20, "SPARQL returned only {} films", films.len());
        assert!(
            films.iter().any(|f| f.title == "The Matrix"),
            "the best-known credit is missing - the P31 filter is too strict"
        );
        assert!(
            !films.iter().any(|f| f.title.contains("Fresh Prince")),
            "television leaked through the film filter"
        );

        // A `mul`-only item: Wikidata increasingly stores a film's title
        // ONCE under the multilingual code instead of per-language, and
        // Top Gun: Maverick (Q31202708) has no `en` label at all. Asking
        // for English alone silently dropped it and six others from Tom
        // Cruise's 60 credits - no error, no warning, just a shorter
        // list. Only a live call can catch that class of loss, which is
        // exactly why this test exists.
        let cruise = wikidata_filmography("Q37079")
            .expect("the SPARQL endpoint did not answer for Q37079");
        println!("  Q37079: {} film credits", cruise.len());
        assert!(
            cruise.iter().any(|f| f.title.contains("Maverick")),
            "a mul-only title vanished - the label service is being asked for 'en' only"
        );
        assert!(!cruise.iter().any(|f| f.title.starts_with('Q')), "raw Q-ids leaked as titles");
        // Undated rows exist and must be last, not first.
        if let Some(first_undated) = films.iter().position(|f| f.date.is_empty()) {
            assert!(
                films[first_undated..].iter().all(|f| f.date.is_empty()),
                "undated credits are interleaved rather than sorted last"
            );
        }
    }

    #[test]
    fn omdb_detail_and_search_parse() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"Title":"The Matrix","Year":"1999","Genre":"Action, Sci-Fi",
                "Actors":"Keanu Reeves, Laurence Fishburne","Plot":"Neo.",
                "Poster":"https://m.media-amazon.com/x.jpg","imdbRating":"8.7",
                "imdbVotes":"2,100,000","imdbID":"tt0133093","Type":"movie",
                "Response":"True"}"#,
        )
        .unwrap();
        let m = parse_omdb(&v).unwrap();
        assert_eq!(m.tmdb_id, 133093);
        assert_eq!(m.imdb, "tt0133093");
        assert_eq!(m.overview, "Neo.");
        assert_eq!(m.rating, 8.7);
        assert_eq!(m.genres, "Action, Sci-Fi");
        assert_eq!(m.actors, "Keanu Reeves, Laurence Fishburne");
        assert_eq!(m.poster_url, "https://m.media-amazon.com/x.jpg");

        // "N/A" padding reads as absent; a miss parses as None.
        let na: serde_json::Value = serde_json::from_str(
            r#"{"Title":"Obscure","Plot":"N/A","Poster":"N/A","imdbRating":"N/A",
                "Genre":"N/A","Actors":"N/A","imdbID":"tt0000123","Response":"True"}"#,
        )
        .unwrap();
        let m = parse_omdb(&na).unwrap();
        assert!(m.overview.is_empty() && m.poster_url.is_empty() && m.actors.is_empty());
        assert_eq!(m.rating, 0.0);
        let miss: serde_json::Value =
            serde_json::from_str(r#"{"Response":"False","Error":"Movie not found!"}"#).unwrap();
        assert!(parse_omdb(&miss).is_none());

        let s: serde_json::Value = serde_json::from_str(
            r#"{"Search":[
                {"Title":"The Matrix","Year":"1999","imdbID":"tt0133093","Type":"movie",
                 "Poster":"https://m.media-amazon.com/x.jpg"},
                {"Title":"The Matrix Revisited","Year":"2001–2003","imdbID":"tt0295432",
                 "Type":"movie","Poster":"N/A"}],
                "totalResults":"2","Response":"True"}"#,
        )
        .unwrap();
        let c = parse_omdb_search(&s);
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].id, c[0].year, c[0].imdb.as_str()), (133093, 1999, "tt0133093"));
        assert_eq!(c[0].provider, "omdb");
        assert_eq!(c[1].year, 2001, "year ranges take the first year");
        assert!(c[1].poster_url.is_empty());
    }

    #[test]
    fn omdb_signup_form_scrape() {
        // Shape of the LIVE form (fetched 19 Jul 2026): Patreon radio
        // checked by default, the free radio is an AutoPostBack.
        let step1 = r#"<html><body><form method="post" action="./apikey.aspx">
          <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="VS123" />
          <input type="hidden" name="__EVENTVALIDATION" value="EV456" />
          <input id="patreonAcct" type="radio" name="at" value="patreonAcct" checked="checked" />
          <input id="freeAcct" type="radio" name="at" value="freeAcct" onclick="javascript:setTimeout('__doPostBack(\'freeAcct\',\'\')', 0)" />
          <input name="Email" type="text" id="Email" class="form-control" />
          <input type="submit" name="Submit" value="Submit" id="Submit" />
        </form></body></html>"#;
        let (name, target, value, checked) = omdb_free_radio(step1).unwrap();
        assert_eq!((name.as_str(), target.as_str(), value.as_str()), ("at", "freeAcct", "freeAcct"));
        assert!(!checked, "live form defaults to the Patreon tier");
        // The radio-select postback carries state + the free radio but
        // must NOT press Submit.
        let f = omdb_signup_fields(step1, "user@example.com", false).unwrap();
        let get = |f: &[(String, String)], k: &str| {
            f.iter().find(|(n, _)| n.contains(k)).map(|(_, v)| v.to_string())
        };
        assert_eq!(get(&f, "__VIEWSTATE").as_deref(), Some("VS123"));
        assert_eq!(get(&f, "at").as_deref(), Some("freeAcct"));
        assert_eq!(get(&f, "Email").as_deref(), Some("user@example.com"));
        assert!(get(&f, "Submit").is_none());

        // Step 2: the re-rendered free-tier form (name/use fields).
        let step2 = r#"<form>
          <input type="hidden" name="__VIEWSTATE" value="VS999" />
          <input id="freeAcct" type="radio" name="at" value="freeAcct" checked="checked" />
          <input name="Email" type="text" />
          <input name="FirstName" type="text" />
          <input name="LastName" type="text" />
          <textarea name="Use"></textarea>
          <input type="submit" name="Submit" value="Submit" />
          <input type="submit" name="Other" value="Other" />
        </form>"#;
        assert!(omdb_free_radio(step2).unwrap().3, "free tier selected after postback");
        let f = omdb_signup_fields(step2, "user@example.com", true).unwrap();
        assert_eq!(get(&f, "__VIEWSTATE").as_deref(), Some("VS999"));
        assert_eq!(get(&f, "Email").as_deref(), Some("user@example.com"));
        assert_eq!(get(&f, "FirstName").as_deref(), Some("nzbfast"));
        assert_eq!(get(&f, "LastName").as_deref(), Some("user"));
        assert!(get(&f, "Use").unwrap().contains("Personal"));
        assert_eq!(get(&f, "Submit").as_deref(), Some("Submit"));
        assert!(get(&f, "Other").is_none(), "only the first submit posts");
        // A page without an email box is not the form we expect.
        assert!(omdb_signup_fields("<html><input name='q'></html>", "e@x", true).is_none());
        // Encoding round-trip stays urlencoded-safe.
        assert!(form_encode(&f).contains("__VIEWSTATE=VS999"));
        assert!(form_encode(&f).contains("user%40example.com"));
    }

    #[test]
    fn wikidata_candidate_picking_honors_year_and_p345() {
        let search: serde_json::Value = serde_json::from_str(
            r#"{"search":[{"id":"Q1"},{"id":"Q2"},{"id":"Q3"}]}"#,
        )
        .unwrap();
        let entities: serde_json::Value = serde_json::from_str(
            r#"{"entities":{
              "Q1":{"claims":{}},
              "Q2":{"claims":{"P345":[{"mainsnak":{"datavalue":{"value":"tt0000002"}}}],
                    "P577":[{"mainsnak":{"datavalue":{"value":{"time":"+2021-12-22T00:00:00Z"}}}}]}},
              "Q3":{"claims":{"P345":[{"mainsnak":{"datavalue":{"value":"tt0133093"}}}],
                    "P577":[{"mainsnak":{"datavalue":{"value":{"time":"+1999-03-31T00:00:00Z"}}}}]}}
            }}"#,
        )
        .unwrap();
        // Year steers past the wrong-year candidate (Q2) to Q3.
        assert_eq!(
            pick_wikidata_imdb(&search, &entities, 1999).as_deref(),
            Some("tt0133093")
        );
        // No year → first candidate WITH a P345 wins (Q1 has none).
        assert_eq!(
            pick_wikidata_imdb(&search, &entities, 0).as_deref(),
            Some("tt0000002")
        );
    }

    #[test]
    fn anilist_parses_and_rescales_score() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"data":{"Media":{"id":21,"description":"Pirates<br>adventure",
                "averageScore":86,"genres":["Action","Adventure"],
                "coverImage":{"large":"https://a/l.jpg","extraLarge":"https://a/xl.jpg"},
                "bannerImage":"https://a/b.jpg"}}}"#,
        )
        .unwrap();
        let m = parse_anilist(&v).unwrap();
        assert_eq!(m.tmdb_id, 21);
        assert_eq!(m.rating, 8.6);
        assert_eq!(m.overview, "Piratesadventure");
        assert_eq!(m.poster_url, "https://a/xl.jpg");
        assert_eq!(m.genres, "Action, Adventure");
    }

    #[test]
    fn imdb_ratings_tsv_parses_and_filters() {
        let tsv = "tconst\taverageRating\tnumVotes\n\
                   tt0133093\t8.7\t2100000\n\
                   tt0000001\t5.7\t42\n\
                   ttbroken\tx\ty\n\
                   tt0111161\t9.3\t3000000\n";
        let rows = parse_imdb_ratings(tsv, 100);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("tt0133093".into(), 8.7, 2_100_000));
        assert_eq!(rows[1], ("tt0111161".into(), 9.3, 3_000_000));
    }

    // --- Wikidata: the keyless movie provider (iTunes' replacement) ---

    /// wbsearchentities ranks these in order; Q3 is not a film, Q1 is
    /// the wrong year, Q2 is the film we want, Q4 is a film with no
    /// IMDb id.
    fn wikidata_fixture() -> (serde_json::Value, serde_json::Value) {
        let search = serde_json::json!({
            "search": [{"id":"Q3"},{"id":"Q1"},{"id":"Q2"},{"id":"Q4"}]
        });
        let film = |q: &str| serde_json::json!([{"mainsnak":{"datavalue":{"value":{"id":q}}}}]);
        let time = |t: &str| serde_json::json!([{"mainsnak":{"datavalue":{"value":{"time":t}}}}]);
        let s = |v: &str| serde_json::json!([{"mainsnak":{"datavalue":{"value":v}}}]);
        let entities = serde_json::json!({"entities":{
            // A video game, not a film - never eligible however well it ranks.
            "Q3": {"claims":{"P31": film("Q7889"), "P345": s("tt9999999")}},
            // Right title, wrong year.
            "Q1": {"claims":{"P31": film("Q11424"), "P577": time("+2021-12-22T00:00:00Z"),
                             "P345": s("tt10838180")}},
            // The match: film, right year, has an IMDb id.
            "Q2": {"labels":{"en":{"value":"The Matrix"}},
                   "descriptions":{"en":{"value":"1999 film by the Wachowskis"}},
                   "claims":{
                     "P31": film("Q11424"),
                     "P345": s("tt0133093"),
                     "P18": s("The Matrix poster.jpg"),
                     // Deliberately out of order: the earliest wins.
                     "P577": serde_json::json!([
                        {"mainsnak":{"datavalue":{"value":{"time":"+1999-05-07T00:00:00Z"}}}},
                        {"mainsnak":{"datavalue":{"value":{"time":"+1999-03-31T00:00:00Z"}}}}]),
                     "P136": serde_json::json!([
                        {"mainsnak":{"datavalue":{"value":{"id":"Q471839"}}}},
                        {"mainsnak":{"datavalue":{"value":{"id":"Q188473"}}}}]),
                     "P161": serde_json::json!([
                        {"mainsnak":{"datavalue":{"value":{"id":"Q40096"}}}},
                        {"mainsnak":{"datavalue":{"value":{"id":"Q102289"}}}}])}},
            // A film with art and a date but no IMDb id.
            "Q4": {"labels":{"en":{"value":"The Matrix (short)"}},
                   "claims":{"P31": film("Q24862"), "P577": time("+1999-08-01T00:00:00Z"),
                             "P18": s("Short.jpg")}},
        }});
        (search, entities)
    }

    #[test]
    fn wikidata_picks_the_right_film_and_builds_the_card() {
        let (search, entities) = wikidata_fixture();
        // Non-films are skipped even though Q3 ranks first, and the
        // wrong-year Q1 is filtered out by the year.
        let picked = pick_wikidata_film(&search, &entities, 1999).unwrap();
        assert_eq!(picked, "Q2");

        // Q188473 deliberately absent - an unresolved id must be
        // dropped, never rendered as a raw "Q188473" genre.
        let labels: HashMap<String, String> = [
            ("Q471839", "Science Fiction"),
            ("Q40096", "Keanu Reeves"),
            ("Q102289", "Laurence Fishburne"),
        ]
        .iter()
        .map(|(q, n)| (q.to_string(), n.to_string()))
        .collect();
        let m = parse_wikidata_film(&entities["entities"]["Q2"], &labels);
        assert_eq!(m.imdb, "tt0133093");
        assert_eq!(m.air_date, "1999-03-31", "earliest P577 wins");
        assert_eq!(m.genres, "Science Fiction");
        assert_eq!(m.actors, "Keanu Reeves, Laurence Fishburne");
        // P18 is never a poster - the caller pairs this with Wikipedia's
        // infobox image instead.
        assert_eq!(m.poster_url, "");
    }

    #[test]
    fn wikidata_falls_back_to_a_film_without_an_imdb_id() {
        let (search, entities) = wikidata_fixture();
        // With no IMDb id anywhere, the second pass still returns a
        // film: art, a date, genres and a cast beat the bare stem the
        // wall would show otherwise.
        let mut e = entities.clone();
        e["entities"]["Q2"]["claims"]["P345"] = serde_json::Value::Null;
        assert_eq!(pick_wikidata_film(&search, &e, 1999).unwrap(), "Q2");
        // And the pass reaches past the top-ranked entity when that one
        // is not a film at all - Q4 is the only 1999 film left here.
        let s = serde_json::json!({"search":[{"id":"Q3"},{"id":"Q1"},{"id":"Q4"}]});
        assert_eq!(pick_wikidata_film(&s, &e, 1999).unwrap(), "Q4");
    }

    #[test]
    fn wikidata_year_mismatch_finds_nothing_rather_than_the_wrong_film() {
        let (search, entities) = wikidata_fixture();
        assert_eq!(pick_wikidata_film(&search, &entities, 1975), None);
    }

    #[test]
    fn wikidata_candidates_filter_by_year_and_carry_the_description() {
        let (search, entities) = wikidata_fixture();
        let c = parse_wikidata_candidates(&search, &entities, 1999);
        // Q3 is not a film; Q1 is the wrong year; Q2 and Q4 survive.
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].title.as_str(), c[0].year), ("The Matrix", 1999));
        assert_eq!(c[0].overview, "1999 film by the Wachowskis");
        assert_eq!(c[0].provider, "wikidata");
        assert_eq!(c[0].imdb, "tt0133093");
        assert_eq!(c[1].title, "The Matrix (short)");
    }

    /// Live smoke test for the whole keyless movie chain, against the
    /// real Wikidata and Wikipedia APIs. `#[ignore]`d so no ordinary
    /// test run touches the network:
    ///   cargo test -p nzbfast keyless_movie_chain -- --ignored --nocapture
    ///
    /// This exists because the provider it replaced died silently: Apple
    /// kept answering HTTP 200 with an empty result set, so every test
    /// still passed while the wall quietly stopped getting posters. Only
    /// a live check catches that class of failure.
    #[test]
    #[ignore]
    fn keyless_movie_chain_answers_live() {
        for (title, year) in [
            ("The Matrix", 1999u32),
            ("Top Gun Maverick", 2022),
            ("Dune Part Two", 2024),
        ] {
            let m = wikidata_movie(title, year)
                .unwrap_or_else(|| panic!("wikidata found no film for {title} ({year})"));
            let w = wikipedia_page(title, year)
                .unwrap_or_else(|| panic!("wikipedia has no page for {title} ({year})"));
            println!(
                "{title}: imdb={} date={} genres={:?} cast={:?} poster={}",
                m.imdb,
                m.air_date,
                m.genres,
                m.actors,
                &w.image
            );
            assert!(m.imdb.starts_with("tt"), "{title}: no imdb id");
            assert!(!m.air_date.is_empty(), "{title}: no release date");
            assert!(!m.actors.is_empty(), "{title}: no cast");
            assert!(w.image.contains("upload.wikimedia.org"), "{title}: no poster");
            // Stay well inside Wikimedia's anonymous rate limit.
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }

    // ---- music + books --------------------------------------------------

    #[test]
    fn openlibrary_reranks_past_its_own_relevance_order() {
        // Measured against the live service: asking for title=Dune,
        // author=Frank Herbert answers with "Children of Dune" first and
        // the actual "Dune" seventh. Taking docs[0] would put the wrong
        // cover on the card for every book in a series, so this fixture
        // is the real ordering, not a convenient one.
        let v = serde_json::json!({"docs": [
            {"title":"Children of Dune","author_name":["Frank Herbert"],
             "first_publish_year":1976,"cover_i":6976407,"edition_count":77,
             "key":"/works/OL893516W","subject":["Science Fiction","Fiction in English"]},
            {"title":"God Emperor of Dune","author_name":["Frank Herbert"],
             "first_publish_year":1981,"cover_i":6711531,"edition_count":47,
             "key":"/works/OL893515W"},
            {"title":"Dune","author_name":["Frank Herbert","Френк Герберт"],
             "first_publish_year":1965,"cover_i":11481354,"edition_count":160,
             "key":"/works/OL893414W","ratings_average":4.2,
             "first_sentence":["A beginning is the time for taking the most delicate care."],
             "subject":["Science Fiction","Reading Level-Grade 7","Fiction",
                        "Dune (Imaginary Place)","New York Times Reviewed"]},
        ]});
        let m = parse_openlibrary(&v, "Dune").expect("no book picked");
        // The Cyrillic entry is the same author transliterated, not a
        // co-author - live OpenLibrary really does return both.
        assert_eq!(m.actors, "Frank Herbert", "author belongs in actors");
        assert_eq!(m.air_date, "1965");
        assert_eq!(m.poster_url, "https://covers.openlibrary.org/b/id/11481354-L.jpg");
        assert_eq!(m.overview, "Book by Frank Herbert");
        // OpenLibrary rates out of 5, the card's star is out of 10.
        assert!((m.rating - 8.4).abs() < 0.01, "rating not rescaled: {}", m.rating);
        // Shelving noise is not a genre.
        assert_eq!(m.genres, "Science Fiction, Fiction");
        // Nothing resembling the request → no card, rather than a wrong one.
        let other = serde_json::json!({"docs":[{"title":"A Totally Different Book",
            "author_name":["Someone"],"edition_count":5,"key":"/works/X"}]});
        assert!(parse_openlibrary(&other, "Dune").is_none());
    }

    #[test]
    fn musicbrainz_picks_the_titled_release_group() {
        let v = serde_json::json!({"release-groups": [
            {"id":"aaa","title":"The Dark Side of the Moon: Live","score":95,
             "primary-type":"Album","first-release-date":"1974-01-01",
             "artist-credit":[{"name":"Pink Floyd"}]},
            {"id":"f5093c06","title":"The Dark Side of the Moon","score":100,
             "primary-type":"Album","first-release-date":"1973-03-24",
             "artist-credit":[{"name":"Pink Floyd"}]},
        ]});
        let g = pick_release_group(&v, "The Dark Side of the Moon").expect("no group");
        assert_eq!(g["id"], "f5093c06", "a scored near-miss beat the exact title");
        let m = parse_release_group(&g).unwrap();
        assert_eq!(m.actors, "Pink Floyd", "artist belongs in actors");
        assert_eq!(m.air_date, "1973-03-24");
        assert_eq!(m.overview, "Album by Pink Floyd");
        assert!(m.tmdb_id != 0, "a match must set the found flag");
    }

    #[test]
    fn cover_art_prefers_the_front_thumbnail_over_the_full_scan() {
        // The archive serves http:// in its JSON; artwork must not be
        // fetched in the clear just because it was advertised that way.
        let v = serde_json::json!({"images": [
            {"front": false, "image": "http://coverartarchive.org/release/x/back.jpg",
             "thumbnails": {"500": "http://coverartarchive.org/release/x/back-500.jpg"}},
            {"front": true, "image": "http://coverartarchive.org/release/x/front.jpg",
             "thumbnails": {"500": "http://coverartarchive.org/release/x/front-500.jpg"}},
        ]});
        assert_eq!(
            parse_coverart(&v),
            "https://coverartarchive.org/release/x/front-500.jpg"
        );
        assert_eq!(parse_coverart(&serde_json::json!({"images": []})), "");
    }

    /// Live check, same reasoning as `keyless_movie_chain_answers_live`:
    /// the provider that path replaced (iTunes) died SILENTLY, answering
    /// HTTP 200 with an empty result set, so every offline test above
    /// kept passing while the wall quietly stopped getting artwork. Only
    /// a real call catches that.
    ///
    ///     cargo test -p nzbfast --bin nzbfast -- --ignored music_and_book
    #[test]
    #[ignore]
    fn music_and_book_chains_answer_live() {
        let mut any_genres = false;
        for (artist, album) in [
            ("Pink Floyd", "The Dark Side of the Moon"),
            ("Radiohead", "OK Computer"),
        ] {
            let m = musicbrainz_lookup(artist, album)
                .unwrap_or_else(|| panic!("musicbrainz found nothing for {artist} - {album}"));
            println!(
                "{artist} - {album}: date={} genres={:?} artist={:?} cover={}",
                m.air_date, m.genres, m.actors, m.poster_url
            );
            assert!(!m.air_date.is_empty(), "{album}: no first-release date");
            assert!(!m.actors.is_empty(), "{album}: no artist");
            assert!(
                m.poster_url.starts_with("https://"),
                "{album}: no cover art ({})",
                m.poster_url
            );
            any_genres |= !m.genres.is_empty();
        }
        // Genres come from a SECOND MusicBrainz call per album, and that
        // call is optional by design - a throttled response leaves the
        // field empty rather than losing the card. Asserting it per album
        // was stricter than the code's own contract and duly failed on a
        // transient. Requiring it from at least one album still catches
        // the case worth catching: the genre lookup being dead.
        assert!(any_genres, "no album returned genres - the release-group lookup is dead");
        for (author, title) in
            [("Frank Herbert", "Dune"), ("Andy Weir", "Project Hail Mary")]
        {
            let b = openlibrary_lookup(author, title)
                .unwrap_or_else(|| panic!("openlibrary found nothing for {author} - {title}"));
            println!(
                "{author} - {title}: year={} subjects={:?} author={:?} cover={}",
                b.air_date, b.genres, b.actors, b.poster_url
            );
            assert!(!b.air_date.is_empty(), "{title}: no publish year");
            assert!(!b.actors.is_empty(), "{title}: no author");
            assert!(
                b.poster_url.starts_with("https://covers.openlibrary.org/"),
                "{title}: no cover ({})",
                b.poster_url
            );
        }
    }

    #[test]
    fn wikidata_times_are_normalised() {
        // The mandatory leading sign would fail iso_date's digit check.
        assert_eq!(wikidata_iso("+1999-03-31T00:00:00Z"), "1999-03-31");
        assert_eq!(wikidata_iso("-0044-03-15T00:00:00Z"), "");
    }
}

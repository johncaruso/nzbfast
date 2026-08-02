use super::*;

/// Version we report to API clients. The *arrs feature-gate on the SAB
/// version string, so claim parity with the release whose API we match.
pub(super) const SAB_VERSION: &str = "4.5.0";

/// Minutes until a timed pause auto-resumes (SAB's `pause_int`).
pub(super) fn pause_int(d: &Daemon) -> String {
    d.pause_until
        .lock()
        .unwrap()
        .map(|t| {
            t.saturating_duration_since(Instant::now())
                .as_secs()
                .div_ceil(60)
        })
        .unwrap_or(0)
        .to_string()
}

/// The conditions worth interrupting someone about, in SAB's warning
/// shape (a client renders these verbatim).
///
/// `mode=warnings` was a permanent empty list, so the states a user most
/// needs to see were invisible in every remote app: nothing downloads
/// and nothing says why. Each entry here is a condition that is
/// currently true and currently stopping or degrading work - not a log
/// tail, and not history. Nothing that resolves itself is listed, or the
/// pane becomes noise nobody reads.
pub(super) fn sab_warnings(d: &Daemon, cfg_path: &std::path::Path) -> Vec<Value> {
    let mut out: Vec<String> = Vec::new();

    // Nothing can download at all. This is the first-run state, and the
    // one most likely to be met by someone who has just wired up Sonarr.
    // An unreadable config counts the same as an empty one here: either
    // way there is nothing to download from.
    let servers = nzbkit::config::Config::load(cfg_path)
        .map(|c| c.servers.len())
        .unwrap_or(0);
    if servers == 0 {
        out.push("No Usenet server is configured - add one in Settings before downloading".into());
    }

    // The queue is held by the low-disk guard: it re-checks every five
    // seconds and will not start anything until there is room.
    let min = d.min_free.load(Ordering::Relaxed);
    if min > 0
        && let Some(free) = free_bytes(&d.out_dir())
        && free < min
    {
        out.push(format!(
            "Queue held: {:.1} GB free is below the {:.1} GB minimum",
            free as f64 / 1e9,
            min as f64 / 1e9
        ));
    }

    // Jobs that have stopped and will not move without the user. A
    // password prompt is invisible to an *arr, which just sees a job
    // that never finishes.
    let waiting: Vec<String> = d
        .queue
        .lock()
        .unwrap()
        .iter()
        .filter_map(|j| {
            let g = j.lock_ok();
            g.password_required.then(|| g.name.clone())
        })
        .collect();
    for name in waiting.iter().take(5) {
        out.push(format!("{name} needs a password to unpack"));
    }
    if waiting.len() > 5 {
        out.push(format!(
            "...and {} more waiting for a password",
            waiting.len() - 5
        ));
    }

    out.into_iter()
        .map(|text| json!({"type": "WARNING", "text": text, "time": epoch_secs()}))
        .collect()
}

/// Escape for XML - and DROP what XML 1.0 cannot carry at all.
///
/// A C0 control byte reaching an attribute or element makes the whole
/// document not well-formed, so one hostile or merely malformed article
/// poisons every search that pages over its row: the `poster` field is
/// the raw OVER `From:` header, kept verbatim, and the API facades are
/// uncurated by design so no junk filter drops it. Escaping is not an
/// option - `&#1;` is equally illegal and expat/libxml2 reject it - and
/// emitting one would break nzbfast's own quick-xml reader, which
/// hard-errors on InvalidCharRef. Dropping is the only representable
/// answer. `char` already excludes surrogates, so the XML 1.0 `Char`
/// production reduces to: keep tab/LF/CR, drop the rest below U+0020,
/// drop the two permanently-unassigned noncharacters.
pub(super) fn esc_xml(s: &str) -> String {
    let clean: String = s.chars().filter(|&c| xml_char_ok(c)).collect();
    clean
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Is `c` representable in an XML 1.0 document at all? See [`esc_xml`].
pub(super) fn xml_char_ok(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{FFFE}' && c != '\u{FFFF}')
}

/// The four index kinds as newznab top-level category ids. The standard
/// tree is 1000 Console, 2000 Movies, 3000 Audio, 4000 PC, 5000 TV,
/// 6000 XXX, 7000 Books, 8000 Other - so software belongs under PC, and
/// Other is 8000, never 7000 (Prowlarr remaps/misfiles anything declared
/// under Books). A custom category has no id of its own and rides Other,
/// as `docs/DESIGN-user-categories.md` decided.
pub(super) fn cat_for_kind(kind: &str) -> Option<u32> {
    match kind {
        "movie" => Some(2000),
        "tv" => Some(5000),
        "software" => Some(4000),
        "other" => Some(8000),
        _ => None,
    }
}

/// Newznab top-level id → index kind, the inverse of [`cat_for_kind`].
/// Subcategories share their parent's thousand (5030 TV/SD → tv, 4050
/// PC/Games → software). The ids we carry no kind for (console, audio,
/// xxx, books) return None rather than being remapped to `other`: a
/// remap answered an audio search with obfuscated junk.
pub(super) fn kind_for_cat(cat: u32) -> Option<&'static str> {
    match cat / 1000 {
        2 => Some("movie"),
        4 => Some("software"),
        5 => Some("tv"),
        8 => Some("other"),
        _ => None,
    }
}

/// Newznab category for a result row. The stored classification decides
/// (so the id we report is the same one `cat=` filtered on); rows the
/// backfill has not reached carry no kind, and fall back to the stem:
/// episode marker → TV, year marker → Movies, else Other. Reuses the
/// M14f parser.
pub(super) fn newznab_category(kind: &str, stem: &str) -> u32 {
    if let Some(cat) = cat_for_kind(kind) {
        return cat;
    }
    // A custom category: labelled Other, though `cat=8000` (which
    // filters on kind='other' in SQL) will not select it.
    if !kind.is_empty() {
        return 8000;
    }
    match dupe_key(stem) {
        Some(k) if k.rsplit('/').next().is_some_and(|m| m.starts_with('s')) => 5000,
        Some(_) => 2000,
        None => 8000,
    }
}

/// Scheme + authority to build client-facing links from.
///
/// Behind a reverse proxy the `Host` header names the proxy and the TLS
/// was terminated there, so a plain `http://{Host}` link is mixed
/// content that Prowlarr and Sonarr refuse to fetch - the one thing an
/// HTTPS deployment cannot work around from its side. `X-Forwarded-Host`
/// wins over `Host`, `X-Forwarded-Proto` picks the scheme, and each is
/// a comma list when the request crossed more than one hop, of which the
/// first entry is the client-facing one. An unrecognised scheme falls
/// back to http rather than being echoed into a URL.
pub(super) fn public_base(req: &tiny_http::Request, port: u16) -> String {
    let hdr = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().to_string())
    };
    let first = |v: String| v.split(',').next().unwrap_or("").trim().to_string();
    let host = hdr("X-Forwarded-Host")
        .map(first)
        .filter(|h| !h.is_empty())
        .or_else(|| hdr("Host"))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| format!("127.0.0.1:{port}"));
    let scheme = hdr("X-Forwarded-Proto")
        .map(first)
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| "http".into());
    format!("{scheme}://{host}")
}

/// M12: the newznab facade - enough of the protocol for Sonarr/Radarr
/// to use the built-in index as an indexer (caps, search, tvsearch,
/// movie; results link to /getnzb/<id>).
pub(super) fn newznab_xml(
    d: &Daemon,
    params: &std::collections::HashMap<String, String>,
    base: &str,
    apikey: &str,
) -> String {
    let t = params.get("t").map(String::as_str).unwrap_or("");
    // The facade IS the index, published over newznab, so the master
    // switch closes it too - otherwise an *arr keeps a healthy indexer
    // entry pointed at something that can only ever answer zero results.
    // Code 101 is the spec's "account suspended", the nearest thing it
    // has to "this indexer is switched off"; Sonarr and Radarr surface
    // the description verbatim, so the description is the real message.
    // caps is refused as well, on purpose: it is what an *arr tests with,
    // so the failure shows up when someone adds us, not weeks later on a
    // search that quietly returns nothing.
    if d.indexer_off() {
        return newznab_error(
            101,
            "nzbfast's built-in indexer is switched off (Settings → Indexing)",
        );
    }
    if t == "caps" {
        return r#"<?xml version="1.0" encoding="UTF-8"?>
<caps>
  <server title="nzbfast" version="1.0"/>
  <limits max="200" default="100"/>
  <searching>
    <search available="yes" supportedParams="q,cat"/>
    <tv-search available="yes" supportedParams="q,season,ep,cat"/>
    <movie-search available="yes" supportedParams="q,imdbid,tmdbid,cat"/>
  </searching>
  <categories>
    <category id="2000" name="Movies"/>
    <category id="4000" name="PC"/>
    <category id="5000" name="TV"/>
    <category id="8000" name="Other"/>
  </categories>
</caps>"#
            .to_string();
    }
    // Function dispatch. Everything that searches shares one path; the
    // categories we carry no rows for get the spec's own "not available"
    // rather than falling through, which used to answer a Lidarr audio
    // search with the whole index. Errors ride HTTP 200 + an <error>
    // body, which is the newznab convention (only bad credentials, which
    // the caller handles, answer with a status code).
    match t {
        "" | "search" | "tvsearch" | "tv-search" | "movie" | "moviesearch" => {}
        "music" | "audio" | "book" | "bookssearch" | "booksearch" => {
            return newznab_error(203, "Function not available");
        }
        _ => return newznab_error(202, "No such function"),
    }
    let mut q = params.get("q").cloned().unwrap_or_default();
    // Season/episode narrowing. A *season-pack* search sends `season=`
    // with NO `ep=`, and dropping the season there answered with every
    // release of the series - so the season alone still narrows the
    // query. Two shapes deliberately do not: a season that is really a
    // year (daily series are filed by airdate, never SxxEyy) and an `ep`
    // that will not parse as a number (the `ep=07/28` daily form). Both
    // keep today's plain-title search, which Sonarr then date-filters,
    // instead of an `s2026` that can never match anything.
    let season = params.get("season").and_then(|v| v.parse::<u32>().ok());
    let ep = params.get("ep").and_then(|v| v.parse::<u32>().ok());
    let ep_given = params.get("ep").is_some_and(|v| !v.trim().is_empty());
    match (season, ep) {
        (Some(se), Some(ep)) if se < 100 => q = format!("{q} s{se:02}e{ep:02}").trim().to_string(),
        (Some(se), None) if se < 100 && !ep_given => q = format!("{q} s{se:02}").trim().to_string(),
        _ => {}
    }
    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(200);
    let offset: u32 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // cat= is a comma list of Newznab category ids (2xxx Movies, 4xxx
    // PC/software, 5xxx TV, 8xxx Other). When every requested id maps to
    // one kind, filter in SQL; mixed/absent = no kind filter.
    // Sonarr/Radarr only ever ask within their own top-level category.
    let cats: Vec<u32> = params
        .get("cat")
        .map(String::as_str)
        .unwrap_or("")
        .split(',')
        .filter_map(|c| c.trim().parse::<u32>().ok())
        .collect();
    let kinds: Vec<&str> = cats.iter().filter_map(|c| kind_for_cat(*c)).collect();
    let kind = match kinds.as_slice() {
        [first, rest @ ..] if rest.iter().all(|k| k == first) => Some(first.to_string()),
        // No usable `cat`, so let the OPERATION speak. `t=movie` and
        // `t=tvsearch` are each already a statement about which half of
        // the index is being asked for, and an id-only query - Radarr's
        // primary lookup - routinely carries no cat at all. Without
        // this, such a query was answered with no kind filter whatever,
        // so a movie search could come back holding TV.
        _ => match t {
            "movie" => Some("movie".to_string()),
            "tvsearch" => Some("tv".to_string()),
            _ => None,
        },
    };
    // Every requested id names a category we do not carry (audio, books,
    // console, xxx): the honest answer is an empty feed. Falling through
    // to an unfiltered query would answer a Lidarr audio search with our
    // whole index.
    let unavailable = !cats.is_empty() && kinds.is_empty();
    // `maxage` is the age ceiling in days, and the *arrs lean on it for
    // RSS sync. It filters on the same upload date the items report, so
    // a row can never be returned by a query that its own pubDate would
    // then fail.
    let newer_than = params
        .get("maxage")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|d| *d > 0)
        // Saturating on BOTH operations: the value is client-supplied and
        // unclamped, so `maxage=999999999999999` wrapped the product
        // large-negative and turned `newer_than` into a far-future cutoff
        // - a silently EMPTY feed where an unfiltered one was owed - and
        // the subtraction then overflowed independently. Saturated, a
        // huge age lands at i64::MIN, which browse() reads as "no age
        // filter", the same answer the maxage=99999 test already pins.
        // Normal values take the identical path they always did. Same
        // treatment as the neighbouring spot handler.
        .map(|days| (epoch_secs() as i64).saturating_sub(days.saturating_mul(86_400)))
        .unwrap_or(0);
    // An id-based search (Radarr's primary lookup) resolves through the
    // enriched titles table to the parse-key its releases carry. An id
    // we hold nothing for answers EMPTY: the old code ignored the param
    // entirely, so an id-only query - which has no q, no season and
    // often no cat - returned the whole index newest-first for the *arr
    // to title-match against.
    let mut id_missing = false;
    let title_key = ["imdbid", "tmdbid"].iter().find_map(|p| {
        let raw = params.get(*p)?.trim().to_string();
        if raw.is_empty() {
            return None;
        }
        let found = d.with_index_read(|ix| {
            if *p == "imdbid" {
                ix.title_key_for_imdb(&raw).ok().flatten()
            } else {
                ix.title_key_for_tmdb(raw.parse().unwrap_or(0))
                    .ok()
                    .flatten()
            }
        });
        id_missing = found.is_none();
        found
    });
    // Honest SQL pagination + complete-only in the query itself - the
    // old path pulled limit+offset rows and filtered/paged in memory,
    // so deep pages silently thinned out.
    let bq = nzbkit::index::BrowseQuery {
        q,
        kind,
        complete_only: true,
        newer_than,
        title_key,
        limit,
        offset,
        ..Default::default()
    };
    let (hits, total) = if unavailable || id_missing {
        (Vec::new(), 0)
    } else {
        d.with_index_read(|ix| ix.browse(&bq).ok())
            .unwrap_or_default()
    };
    let mut items = String::new();
    for r in hits.iter() {
        let link = format!("{base}/getnzb/{}.nzb?apikey={apikey}", r.id);
        // The name a *arr client parses, which for a release the pre
        // feed rescued is the real title rather than the random stem it
        // was posted under. Sonarr and Radarr match on this string and
        // nothing else, so an obfuscated stem here is a release they can
        // never accept.
        let name = r.display_name();
        let cat = newznab_category(&r.kind, name);
        // pubDate is the UPLOAD date, not when we happened to index it.
        // Sonarr and Radarr derive a release's age from it and reject on
        // that age twice over (retention, and the minimum-age hold that
        // lets a bad post get replaced before they grab it) - answering
        // with first_seen advertises every backfilled release as posted
        // today, so the minimum-age hold never fires. first_posted 0 is
        // the live sentinel for "the OVER Date did not parse"; emitting
        // it bare would date those rows to 1970, which reads as
        // infinitely old and is rejected wholesale, so they keep
        // first_seen.
        let posted = if r.first_posted > 0 {
            r.first_posted
        } else {
            r.first_seen
        };
        // The extended attrs cost one row each and are what the *arrs
        // and Prowlarr show without re-fetching the NZB. `usenetdate`
        // repeats pubDate deliberately: clients that treat pubDate as
        // the indexing date read age off this one instead.
        let mut extra = String::new();
        if r.files > 0 {
            extra.push_str(&format!(
                "      <newznab:attr name=\"files\" value=\"{}\"/>\n",
                r.files
            ));
        }
        if !r.grp.is_empty() {
            extra.push_str(&format!(
                "      <newznab:attr name=\"group\" value=\"{}\"/>\n",
                esc_xml(&r.grp)
            ));
        }
        if !r.poster.is_empty() {
            extra.push_str(&format!(
                "      <newznab:attr name=\"poster\" value=\"{}\"/>\n",
                esc_xml(&r.poster)
            ));
        }
        items.push_str(&format!(
            r#"    <item>
      <title>{title}</title>
      <guid isPermaLink="false">nzbfast-{id}</guid>
      <link>{link}</link>
      <pubDate>{date}</pubDate>
      <enclosure url="{link}" length="{size}" type="application/x-nzb"/>
      <newznab:attr name="category" value="{cat}"/>
      <newznab:attr name="size" value="{size}"/>
      <newznab:attr name="usenetdate" value="{date}"/>
{extra}    </item>
"#,
            title = esc_xml(name),
            id = r.id,
            link = esc_xml(&link),
            date = httpdate(posted),
            size = r.total_bytes,
        ));
    }
    // <newznab:response> is how a client knows whether to ask for
    // another page. Without it Prowlarr and Sonarr treat every response
    // as the last one, so a search never went past its first 100 rows -
    // and browse() had the real total all along, it was being discarded.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:newznab="http://www.newznab.com/DTD/2010/feeds/attributes/">
  <channel>
    <title>nzbfast</title>
    <description>nzbfast built-in index</description>
    <newznab:response offset="{offset}" total="{total}"/>
{items}  </channel>
</rss>"#
    )
}

/// A newznab error body. The spec puts these on HTTP 200 with the code
/// in the payload, which is what every client parses.
pub(super) fn newznab_error(code: u32, desc: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<error code=\"{code}\" description=\"{}\"/>",
        esc_xml(desc)
    )
}

/// RFC 2822-ish date from a unix timestamp (what RSS pubDate wants).
pub(super) fn httpdate(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, day) = civil_from_days(days);
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        WD[days.rem_euclid(7) as usize],
        day,
        MO[(m - 1) as usize],
        y,
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// SAB accepts the priority as a number OR a word - the *arrs send
/// numbers, but nzb360-class clients send the token. An unknown string
/// used to fall through to the -100 "not given" sentinel and silently
/// become Normal.
pub(super) fn parse_priority_token(v: &str) -> Option<i32> {
    if let Ok(n) = v.parse() {
        return Some(n);
    }
    match v.to_ascii_lowercase().as_str() {
        "force" => Some(2),
        "high" => Some(1),
        "normal" => Some(0),
        "low" => Some(-1),
        "paused" => Some(-2),
        _ => None,
    }
}

pub(super) fn param_priority(params: &std::collections::HashMap<String, String>) -> i32 {
    params
        .get("priority")
        .and_then(|v| parse_priority_token(v))
        .unwrap_or(-100)
}

/// SABnzbd's `timeleft`, in the shape its own API emits.
///
/// Sonarr deserialises this field straight into a .NET `TimeSpan`, whose
/// `hh:mm:ss` form rejects an hours component above 23. We used to emit
/// `s / 3600` unbounded, so a slow enough job produced "27:46:12" and
/// Sonarr failed to parse the WHOLE `mode=queue` response - reporting
/// "Unable to retrieve queue and history items from SABnzbd" and losing
/// track of every download, not just the slow one, for as long as the
/// ETA stayed over a day. Past 24h SAB switches to a leading days field,
/// which `TimeSpan` reads as `d:hh:mm:ss`.
pub(super) fn sab_timeleft(secs: f64) -> String {
    let s = if secs.is_finite() && secs > 0.0 {
        secs as u64
    } else {
        0
    };
    let (d, h, m, sec) = (s / 86_400, s / 3600 % 24, s / 60 % 60, s % 60);
    if d > 0 {
        format!("{d}:{h:02}:{m:02}:{sec:02}")
    } else {
        format!("{h}:{m:02}:{sec:02}")
    }
}

/// SAB's `to_units`: binary steps with a one-letter unit ("998 ",
/// "417 K", "1.2 M"). NZB Unity parses `queue.speed` with
/// `/([\d.]+)\s+(\w+)/` and multiplies by the unit letter, so the
/// bare-KB-with-a-trailing-space format this used to send always read
/// as 0 B/s there.
pub(super) fn sab_units(n: f64) -> String {
    const K: f64 = 1024.0;
    if n < K {
        format!("{n:.0} ")
    } else if n < K * K {
        format!("{:.0} K", n / K)
    } else if n < K * K * K {
        format!("{:.1} M", n / (K * K))
    } else {
        format!("{:.1} G", n / (K * K * K))
    }
}

pub(super) fn queue_json(d: &Daemon, params: &std::collections::HashMap<String, String>) -> Value {
    // The running job's live archive shape, straight off its extractor -
    // the badge updates the moment the first volume's headers parse, long
    // before anything is latched onto the Job at completion. Taken before
    // the queue lock so the hub's lock is never nested inside it, and read
    // once for the whole payload (it is matched to its owning slot below).
    let live_shape = d
        .hub
        .extractor
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|(owner, ex)| ex.archive_shape().map(|sh| (owner.clone(), sh.tag())));
    // §77: is the health sink switched on at all? Read once for the
    // whole payload rather than per slot.
    let health_defer = d.post_health_defer.load(Ordering::Relaxed);
    let q = d.queue.lock_ok();
    let done = d.progress.load(Ordering::Relaxed);
    let total = d.active_total.load(Ordering::Relaxed).max(1);
    // Live speed over a ~5 s rolling window (see current_speed_bps): a
    // whole-job average hid stalls; idle or a fresh window reports 0,
    // never `bytes / ~zero elapsed`.
    let speed_bps = d.current_speed_bps();
    // Prefetch sidecar state, matched by nzo_id per slot below.
    let sc = d
        .sidecar
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| (s.nzo_id.clone(), s.progress.load(Ordering::Relaxed)));
    // Whole-queue bytes still to fetch, for the top-level sizeleft /
    // timeleft SAB carries (mirrors the per-slot mbleft arithmetic).
    let remaining_bytes: u64 = q
        .iter()
        .map(|j| {
            let j = j.lock_ok();
            match j.state {
                JobState::Downloading => total.saturating_sub(done),
                JobState::Completed => 0,
                _ => j.total_bytes,
            }
        })
        .sum();
    // SAB's queue call takes the same category filter as history (the
    // *arrs pass category=<their cat> when one is configured).
    let cat_filter = params
        .get("category")
        .filter(|c| !c.is_empty() && *c != "*");
    let ids = nzo_ids_param(params);
    let slots: Vec<Value> = q
        .iter()
        .enumerate()
        .filter(|(_, j)| {
            let g = j.lock_ok();
            cat_filter.is_none_or(|c| g.category == *c)
                && ids.as_ref().is_none_or(|s| s.contains(g.nzo_id.as_str()))
        })
        .map(|(i, j)| {
            let j = j.lock_ok();
            let (pct, mbleft) = if j.state == JobState::Downloading {
                (
                    (done * 100 / total).min(100),
                    (total.saturating_sub(done)) as f64 / API_MB,
                )
            } else if j.state == JobState::Completed {
                // The bytes are all in; what is left is the local tail
                // (repair hand-off, unlock, rename, move). Reporting 0%
                // with everything still to fetch made a finished download
                // look like it had gone backwards.
                (100, 0.0)
            } else {
                (0, j.total_bytes as f64 / API_MB)
            };
            let timeleft = if j.state == JobState::Downloading && speed_bps > 1.0 {
                sab_timeleft((total.saturating_sub(done)) as f64 / speed_bps)
            } else {
                "0:00:00".to_string()
            };
            // Live shape for the job that is actually downloading; the
            // latched one otherwise (a queued job that already ran once,
            // or a paused one).
            let shape = live_shape
                .as_ref()
                .filter(|(owner, _)| *owner == j.nzo_id)
                .map(|(_, tag)| tag.clone())
                .unwrap_or_else(|| j.archive_shape.clone());
            json!({
                "nzo_id": j.nzo_id,
                "filename": j.name,
                // Ours, not SAB's: the *arrs ignore unknown keys, and
                // "why is this here / where is its NZB" was unanswerable
                // from the UI.
                "origin": j.origin,
                "nzb_path": j.nzb_path.to_string_lossy(),
                "cat": if j.category.is_empty() { "*" } else { &j.category },
                "status": match j.state {
                    // A pause-suspended job reads Paused the moment the
                    // user hits pause - not Downloading until the
                    // pipeline finishes unwinding and parks it.
                    JobState::Downloading if j.suspended => "Paused",
                    JobState::Downloading => "Downloading",
                    _ if j.paused => "Paused",
                    // `Completed` is set when the NETWORK leg ends, well
                    // before repair hand-off, unlock, rename and the move
                    // to the destination. Reporting that tail as "Queued"
                    // at 0% made a job that had just shown 100% appear to
                    // regress and sit stuck - a 90 GB move to a NAS reads
                    // as ten minutes of "Queued 0%", and users delete it
                    // mid-move. SAB reports the tail as its own states,
                    // which the *arrs know to keep waiting through.
                    JobState::Completed => "Moving",
                    _ => "Queued",
                },
                "index": i,
                "percentage": format!("{pct}"),
                "mb": format!("{:.2}", j.total_bytes as f64 / API_MB),
                "mbleft": format!("{mbleft:.2}"),
                "timeleft": timeleft,
                "priority": priority_name(j.priority),
                "duplicate_key": j.dupe_key.as_deref().unwrap_or(""),
                "deferred": j.deferred,
                "defer_reason": j.defer_reason,
                // TODO §77 pre-flight verdict, ours like `origin` and
                // `deferred` beside it - SAB has no such field and the
                // *arrs ignore what they don't know. Null until the
                // prober has sampled the job (and forever if the
                // operator turned it off), which renders no badge.
                //
                // `sunk` is the verdict's only scheduling consequence,
                // resolved here rather than in the client: whether the
                // optional auto-defer is actually holding THIS job
                // behind healthier ones depends on the live setting and
                // on the job's own priority, and a queue row that has
                // to explain why it is not starting must not have to
                // guess at either.
                "health": j.health.as_ref().map(|h| {
                    let mut v = crate::health::health_json(h);
                    if let Some(o) = v.as_object_mut() {
                        o.insert(
                            "sunk".into(),
                            json!(health_defer && j.priority < 2 && h.sinks()),
                        );
                    }
                    v
                }),
                "zip_packed": j.zip_packed,
                "archive_shape": shape,
                // §76. Ours, not SAB's, like the keys above it: what the
                // main video's own header says it is, and anything the
                // name claims that those bytes deny. Null until the
                // prober has an answer.
                "media": j.media,
                "prefetching": sc.as_ref().is_some_and(|(id, _)| *id == j.nzo_id),
                "prefetched_mb": sc
                    .as_ref()
                    .filter(|(id, _)| *id == j.nzo_id)
                    .map(|(_, b)| format!("{:.2}", *b as f64 / API_MB))
                    .unwrap_or_default(),
            })
        })
        .collect();
    let n = slots.len();
    // Minutes until a timed pause auto-resumes (SAB's pause_int).
    let pause_int = d
        .pause_until
        .lock()
        .unwrap()
        .map(|t| {
            t.saturating_duration_since(Instant::now())
                .as_secs()
                .div_ceil(60)
        })
        .unwrap_or(0);
    // Watch-folder rejects: shown in the Queue card with a Delete button
    // (mode=watch_failed_delete). Sorted for a stable render. Built
    // outside json! - the macro can't parse a typed let binding.
    let watch_failed: Vec<Value> = {
        let wf = d.watch_failed.lock_ok();
        let mut v: Vec<_> = wf
            .iter()
            .map(|(p, (_, _, err))| {
                (
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    err.clone(),
                )
            })
            .collect();
        v.sort();
        v.into_iter()
            .map(|(name, error)| json!({"name": name, "error": error}))
            .collect()
    };
    json!({"queue": {
        "paused": d.paused.load(Ordering::Relaxed),
        // Deliberately NOT folded into "paused": the dashboard polls this
        // and has to show which of the two states it is in. They look the
        // same from the queue's point of view and mean different things -
        // paused keeps indexing and keeps the account occupied, offline
        // does neither - so a single flag would leave the user unable to
        // tell why nothing is downloading.
        "offline": d.offline.load(Ordering::Relaxed),
        "pause_int": format!("{pause_int}"),
        // Update banner state: the dashboard already polls the queue
        // every second, so the chip appears without a dedicated poll.
        "update_version": d
            .update_manifest
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|m| m.get("version").cloned())
            .unwrap_or(Value::Null),
        // Notify-only since 1.0.5: the update chip always links to the
        // download page; no install offered anywhere.
        "bundled": bundled_install(),
        // In a container the download page is the wrong advice - the
        // image is the update channel. The dashboard shows the container
        // recipe instead when this is set.
        "container": container_install(),
        // The launcher owns the port: the settings field is disabled and
        // says where to change it instead (see `port_locked`).
        "port_locked": d.port_locked,
        // Keyless state, for the dashboard's open-API notice. Telling an
        // unauthenticated caller "there is no key here" leaks nothing:
        // when it is true every endpoint is already answering them, and
        // when it is false this response needed a key to reach.
        //
        // The opt-in half matters as much as the flag. An operator who
        // set NZBFAST_OPEN=1 chose this, usually behind another auth
        // layer, and nagging them forever would teach everyone to ignore
        // the notice - including the people who did not choose it.
        "open_api": d.apikey.lock_ok().is_none(),
        "open_optin": std::env::var("NZBFAST_OPEN").is_ok_and(|v| v == "1"),
        "diskspace1": format!("{:.2}", free_bytes(&d.out_dir()).unwrap_or(0) as f64 / 1e9),
        "speedlimit_abs": d.hub.rate.get(),
        "auto_speed": d.auto_speed.load(Ordering::Relaxed),
        "watch_failed": watch_failed,
        // Direct id selection bypasses the start/limit window (SAB
        // semantics; see nzo_ids_param).
        "slots": if ids.is_some() { slots } else { paginate(slots, params) },
        "speed": sab_units(speed_bps),
        "kbpersec": format!("{:.0}", speed_bps / 1e3),
        // SAB's own suffix convention: to_units(bytes) + "B".
        "sizeleft": format!("{}B", sab_units(remaining_bytes as f64)),
        "timeleft": if speed_bps > 1.0 && remaining_bytes > 0 {
            sab_timeleft(remaining_bytes as f64 / speed_bps)
        } else {
            "0:00:00".to_string()
        },
        "noofslots": n,
        "status": if d.paused.load(Ordering::Relaxed) {
            "Paused"
        } else if n == 0 {
            "Idle"
        } else {
            "Downloading"
        },
    }})
}

// ---------------------------------------------------------------------------
// M21: NZBGet JSON-RPC facade (remote-app compatibility)
// ---------------------------------------------------------------------------

/// Minimal standard-alphabet base64 decode (NZBGet `append` payloads).
pub(super) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// "SABnzbd_nzo_nzbfast42" → 42 (NZBGet uses integer NZBIDs).
pub(super) fn nzo_int(nzo: &str) -> i64 {
    nzo.chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

pub(super) fn lohi(bytes: u64) -> (u32, u32) {
    ((bytes & 0xFFFF_FFFF) as u32, (bytes >> 32) as u32)
}

pub(super) fn size_fields(prefix: &str, bytes: u64) -> serde_json::Map<String, Value> {
    let (lo, hi) = lohi(bytes);
    let mut m = serde_json::Map::new();
    m.insert(format!("{prefix}SizeLo"), json!(lo));
    m.insert(format!("{prefix}SizeHi"), json!(hi));
    m.insert(format!("{prefix}SizeMB"), json!(bytes / API_MB_U));
    m
}

/// NZBGet-shaped post-processing parameter list for a job
/// ([{Name, Value}] - the *arrs match their downloads by the `drone`
/// entry they appended with).
pub(super) fn pp_params_json(g: &Job) -> Value {
    Value::Array(
        g.pp_params
            .iter()
            .map(|(n, v)| json!({"Name": n, "Value": v}))
            .collect(),
    )
}

pub(super) fn handle_jsonrpc(
    d: &Arc<Daemon>,
    mut req: tiny_http::Request,
    apikey: Option<&str>,
    nzbkey: Option<&str>,
) {
    // Basic auth: the password must match a configured key. Gate on ANY
    // configured key - the old code only checked `apikey`, so an install
    // with only the add-only nzbkey set (apikey None) skipped auth entirely
    // and ran full-control editqueue/append unauthenticated. Accept either
    // key here (like /stream); the surface is only fully open when NEITHER
    // is set.
    let keys: Vec<&str> = [apikey, nzbkey].into_iter().flatten().collect();
    // Which remote-control app is talking to us, for an appended job's
    // origin. Read before the body is, since that consumes the reader.
    let ua_hdr = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    // Tier tracking: the facade is FULL only for the primary apikey (or a
    // keyless/open install). A caller presenting the add-only nzbkey gets
    // the same restricted surface as the /api add-only tier - otherwise
    // /jsonrpc is a side door around it, escalating an add-only key to
    // editqueue/pause/rate/config (GroupFinalDelete wipes the queue).
    let mut full_auth = keys.is_empty();
    if !keys.is_empty() {
        let cred_pw = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| h.value.as_str().strip_prefix("Basic ").map(str::to_string))
            .and_then(|b| b64_decode(&b))
            .and_then(|raw| String::from_utf8(raw).ok())
            .and_then(|cred| cred.split_once(':').map(|(_, p)| p.to_string()));
        // ct_eq, matching every other auth comparison in this file (/api,
        // /stream, /getnzb, /newznab). This facade was the one that stayed on
        // `==`, which short-circuits on the first differing byte.
        let matched = cred_pw
            .as_deref()
            .is_some_and(|p| keys.iter().any(|k| ct_eq(p, k)));
        if !matched {
            if d.note_auth_failure(peer_ip(&req), "basic auth") {
                let _ = req.respond(
                    tiny_http::Response::from_string("too many bad keys").with_status_code(429),
                );
                return;
            }
            let _ = req.respond(
                tiny_http::Response::from_string("Unauthorized")
                    .with_status_code(401)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"WWW-Authenticate"[..],
                            &b"Basic realm=\"nzbfast\""[..],
                        )
                        .unwrap(),
                    ),
            );
            return;
        }
        // FULL only when the presented password IS the primary apikey.
        // apikey unset + nzbkey matched => add-only tier (not full).
        // Also ct_eq: this decides the TIER (full admin vs add-only), so a
        // timing difference here leaks which of the two keys was presented.
        full_auth = apikey.is_some_and(|ak| cred_pw.as_deref().is_some_and(|p| ct_eq(p, ak)));
    }
    // NZBGet's append carries the whole NZB base64-encoded in the params,
    // so this one needs a big-file cap, not a JSON-sized one.
    let raw = read_body_capped(req.as_reader(), 256 << 20);
    // Re-decide against the key as of NOW, not as of the request line.
    // That body is client-paced: a caller authenticated with key A can
    // stream whitespace, wait out a rotation to key B, and only then
    // finish a destructive editqueue - executing on a credential the
    // owner has already revoked. `/api` re-reads after its body for
    // exactly this reason, and the manual promises rotation takes
    // effect immediately. The tier is re-derived too, so a key demoted
    // from full to add-only mid-body cannot keep its old reach.
    if !keys.is_empty() {
        let now_apikey = d.apikey.lock_ok().clone();
        let now_nzbkey = d.nzbkey.lock_ok().clone();
        let now_keys: Vec<&str> = [now_apikey.as_deref(), now_nzbkey.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        let cred_pw = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| h.value.as_str().strip_prefix("Basic ").map(str::to_string))
            .and_then(|b| b64_decode(&b))
            .and_then(|raw| String::from_utf8(raw).ok())
            .and_then(|cred| cred.split_once(':').map(|(_, p)| p.to_string()));
        let still_ok = !now_keys.is_empty()
            && cred_pw
                .as_deref()
                .is_some_and(|p| now_keys.iter().any(|k| ct_eq(p, k)));
        if !still_ok {
            let _ = req.respond(
                tiny_http::Response::from_string("Unauthorized")
                    .with_status_code(401)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"WWW-Authenticate"[..],
                            &b"Basic realm=\"nzbfast\""[..],
                        )
                        .unwrap(),
                    ),
            );
            return;
        }
        full_auth = now_apikey
            .as_deref()
            .is_some_and(|ak| cred_pw.as_deref().is_some_and(|p| ct_eq(p, ak)));
    }
    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    // Method from the body, or from a GET /jsonrpc/<method> path.
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            req.url()
                .split('/')
                .nth(2)
                .map(|m| m.split('?').next().unwrap_or(m).to_string())
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    let params = body
        .get("params")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let id = body.get("id").cloned().unwrap_or(json!(1));

    // Add-only tier (nzbkey): mirror the /api add_only allowlist. Only
    // adding a job and the harmless read methods a client polls after an
    // append are permitted; anything that mutates the queue/config/rate is
    // full-key only. Keep this list tight - it is the security boundary.
    const ADD_ONLY_JSONRPC: &[&str] = &["append", "version", "status"];
    if !full_auth && !ADD_ONLY_JSONRPC.contains(&method.as_str()) {
        let _ = req.respond(
            tiny_http::Response::from_string(
                "Forbidden: this method requires the full API key, not the add-only key",
            )
            .with_status_code(403),
        );
        return;
    }

    let unix_now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };
    // Set by any arm that cannot honour the call; turns the reply into a
    // JSON-RPC error instead of a result.
    let mut rpc_error: Option<String> = None;
    let result: Value = match method.as_str() {
        "version" => json!("21.0"),
        "status" => {
            let done = d.progress.load(Ordering::Relaxed);
            let total = d.active_total.load(Ordering::Relaxed);
            let remaining_active = total.saturating_sub(done);
            let queued_remaining: u64 = d
                .queue
                .lock()
                .unwrap()
                .iter()
                .filter(|j| j.lock_ok().state == JobState::Queued)
                .map(|j| j.lock_ok().total_bytes)
                .sum();
            let remaining = remaining_active + queued_remaining;
            let rate = d.current_speed_bps() as u64;
            let (disk_free, _) = disk_stat_walk(&d.out_dir()).unwrap_or((0, 0));
            let paused = d.paused.load(Ordering::Relaxed);
            let mut o = serde_json::Map::new();
            for (k, v) in size_fields("Remaining", remaining) {
                o.insert(k, v);
            }
            for (k, v) in size_fields("Downloaded", done) {
                o.insert(k, v);
            }
            // NZBGet's disk fields do NOT carry "Size" in the name.
            let (dlo, dhi) = lohi(disk_free);
            o.insert("FreeDiskSpaceLo".into(), json!(dlo));
            o.insert("FreeDiskSpaceHi".into(), json!(dhi));
            o.insert("FreeDiskSpaceMB".into(), json!(disk_free / API_MB_U));
            o.extend([
                ("DownloadRate".to_string(), json!(rate)),
                ("AverageDownloadRate".to_string(), json!(rate)),
                (
                    "DownloadLimit".to_string(),
                    json!(d.speed_ceiling.load(Ordering::Relaxed)),
                ),
                ("DownloadPaused".to_string(), json!(paused)),
                ("Download2Paused".to_string(), json!(paused)),
                ("PostPaused".to_string(), json!(false)),
                ("ScanPaused".to_string(), json!(false)),
                ("ServerStandBy".to_string(), json!(rate == 0)),
                ("ServerTime".to_string(), json!(unix_now())),
                ("UpTimeSec".to_string(), json!(0)),
                ("DownloadTimeSec".to_string(), json!(0)),
                (
                    "ThreadCount".to_string(),
                    json!(d.connections.load(Ordering::Relaxed)),
                ),
                ("ParJobCount".to_string(), json!(0)),
                ("PostJobCount".to_string(), json!(0)),
                ("UrlCount".to_string(), json!(0)),
                ("FeedActive".to_string(), json!(false)),
                ("QueueScriptCount".to_string(), json!(0)),
                ("NewsServers".to_string(), json!([])),
            ]);
            Value::Object(o)
        }
        "listgroups" => {
            let done = d.progress.load(Ordering::Relaxed);
            let total = d.active_total.load(Ordering::Relaxed).max(1);
            let groups: Vec<Value> = d
                .queue
                .lock()
                .unwrap()
                .iter()
                .map(|j| {
                    let g = j.lock_ok();
                    let downloading = g.state == JobState::Downloading;
                    let (dl, rem) = if downloading {
                        (done, total.saturating_sub(done))
                    } else {
                        (0, g.total_bytes)
                    };
                    let mut o = serde_json::Map::new();
                    for (k, v) in size_fields("File", g.total_bytes) {
                        o.insert(k, v);
                    }
                    for (k, v) in size_fields("Remaining", rem) {
                        o.insert(k, v);
                    }
                    for (k, v) in size_fields("Downloaded", dl) {
                        o.insert(k, v);
                    }
                    for (k, v) in size_fields("Paused", 0) {
                        o.insert(k, v);
                    }
                    o.extend([
                        ("NZBID".to_string(), json!(nzo_int(&g.nzo_id))),
                        ("NZBName".to_string(), json!(g.name)),
                        ("NZBNicename".to_string(), json!(g.name)),
                        ("Kind".to_string(), json!("NZB")),
                        (
                            "Status".to_string(),
                            json!(if downloading {
                                "DOWNLOADING"
                            } else if g.paused {
                                "PAUSED"
                            } else {
                                "QUEUED"
                            }),
                        ),
                        ("Category".to_string(), json!(g.category)),
                        ("Priority".to_string(), json!(g.priority * 50)),
                        ("MaxPriority".to_string(), json!(g.priority * 50)),
                        ("MinPostTime".to_string(), json!(0)),
                        ("MaxPostTime".to_string(), json!(0)),
                        (
                            "ActiveDownloads".to_string(),
                            json!(if downloading {
                                d.connections.load(Ordering::Relaxed)
                            } else {
                                0
                            }),
                        ),
                        ("Health".to_string(), json!(1000)),
                        ("CriticalHealth".to_string(), json!(900)),
                        ("DupeMode".to_string(), json!("SCORE")),
                        ("DupeScore".to_string(), json!(0)),
                        (
                            "DupeKey".to_string(),
                            json!(g.dupe_key.clone().unwrap_or_default()),
                        ),
                        ("MessageCount".to_string(), json!(0)),
                        ("RemainingFileCount".to_string(), json!(0)),
                        ("RemainingParCount".to_string(), json!(0)),
                        ("Parameters".to_string(), pp_params_json(&g)),
                        ("PostInfoText".to_string(), json!("")),
                        ("PostStageProgress".to_string(), json!(0)),
                    ]);
                    Value::Object(o)
                })
                .collect();
            json!(groups)
        }
        "history" => {
            let entries: Vec<Value> = d
                .history
                .lock()
                .unwrap()
                .iter()
                .rev()
                .map(|j| {
                    let g = j.lock_ok();
                    let (status, par_status, unpack_status) = nzbget_status(&g);
                    // Prefer the wall clock: `finished_at` is monotonic
                    // and process-local, so after a restart it was None
                    // and every row reported an age of zero - a week of
                    // history all "finished seconds ago", re-sorted
                    // wrongly and re-notified as new on every restart.
                    let ago = g
                        .finished_unix
                        .map(|t| (unix_now() - t).max(0))
                        .or_else(|| g.finished_at.map(|t| t.elapsed().as_secs() as i64))
                        .unwrap_or(0);
                    let mut o = serde_json::Map::new();
                    for (k, v) in size_fields("File", g.total_bytes) {
                        o.insert(k, v);
                    }
                    o.extend([
                        ("NZBID".to_string(), json!(nzo_int(&g.nzo_id))),
                        ("Name".to_string(), json!(g.name)),
                        ("NZBName".to_string(), json!(g.name)),
                        ("NZBNicename".to_string(), json!(g.name)),
                        ("Kind".to_string(), json!("NZB")),
                        ("Status".to_string(), json!(status)),
                        ("ParStatus".to_string(), json!(par_status)),
                        ("UnpackStatus".to_string(), json!(unpack_status)),
                        ("ScriptStatus".to_string(), json!("NONE")),
                        // Absent = deserialized as "" by the *arrs, which is
                        // outside their {SUCCESS, NONE} success set → every
                        // finished item shows Warning. NONE = "no move ran".
                        ("MoveStatus".to_string(), json!("NONE")),
                        ("DeleteStatus".to_string(), json!("NONE")),
                        ("MarkStatus".to_string(), json!("NONE")),
                        ("UrlStatus".to_string(), json!("NONE")),
                        ("Category".to_string(), json!(g.category)),
                        ("HistoryTime".to_string(), json!(unix_now() - ago)),
                        ("DestDir".to_string(), json!(g.out_dir.to_string_lossy())),
                        ("FinalDir".to_string(), json!(g.out_dir.to_string_lossy())),
                        (
                            "DownloadedSizeMB".to_string(),
                            json!(g.downloaded_bytes / API_MB_U),
                        ),
                        ("DownloadTimeSec".to_string(), json!(g.elapsed_secs as u64)),
                        ("PostTotalTimeSec".to_string(), json!(0)),
                        ("ParTimeSec".to_string(), json!(0)),
                        ("RepairTimeSec".to_string(), json!(0)),
                        ("UnpackTimeSec".to_string(), json!(0)),
                        ("MessageCount".to_string(), json!(0)),
                        ("Health".to_string(), json!(1000)),
                        ("CriticalHealth".to_string(), json!(900)),
                        ("Parameters".to_string(), pp_params_json(&g)),
                    ]);
                    Value::Object(o)
                })
                .collect();
            json!(entries)
        }
        "pausedownload" | "pausedownload2" => {
            timed_pause(d, 0, true); // remote-app pause winds down gracefully
            json!(true)
        }
        "resumedownload" | "resumedownload2" => {
            d.paused.store(false, Ordering::Relaxed);
            d.pause_gen.fetch_add(1, Ordering::Relaxed);
            *d.pause_until.lock_ok() = None;
            persist_pause(d);
            json!(true)
        }
        "rate" => {
            // NZBGet rate is KB/s; 0 = unlimited.
            let kb = params.first().and_then(Value::as_u64).unwrap_or(0);
            d.set_speed_ceiling(kb * 1024);
            json!(true)
        }
        "append" => {
            // v13+ order: [NZBFilename, Content(b64), Category, Priority,
            // AddToTop, AddPaused, DupeKey, DupeScore, DupeMode].
            // Legacy:   [NZBFilename, Category, Priority, AddToTop, Content].
            let strs: Vec<&str> = params.iter().filter_map(Value::as_str).collect();
            let name = strs.first().copied().unwrap_or("remote.nzb");
            let content = strs
                .iter()
                .skip(1)
                .max_by_key(|s| s.len())
                .copied()
                .unwrap_or_default();
            let category = strs
                .iter()
                .skip(1)
                .find(|s| s.len() < 64 && !s.contains('='))
                .copied()
                .unwrap_or("");
            let prio_ng = params.iter().filter_map(Value::as_i64).next().unwrap_or(0);
            let mut priority = if prio_ng >= 900 {
                2
            } else if prio_ng > 0 {
                1
            } else if prio_ng < 0 {
                -1
            } else {
                0
            };
            // AddPaused was accepted and thrown away: Radarr on the nzbget
            // client type with "Add Paused" enabled got an immediate full
            // download, which is the opposite of what the user asked for
            // and can matter on a metered line.
            //
            // The v13+ order carries two booleans, AddToTop then
            // AddPaused; the legacy shape has only AddToTop. So a lone
            // boolean is never a pause, and the second one is. -2 is
            // already the internal "add paused" priority (see the
            // `paused:` field in enqueue), which is also how the SAB
            // facade spells it, so both front doors agree.
            let bools: Vec<bool> = params.iter().filter_map(Value::as_bool).collect();
            let add_to_top = bools.first().copied().unwrap_or(false);
            if bools.len() >= 2 && bools[1] {
                priority = -2;
            }
            // v13+ trailing PPParameters. Two wire shapes exist:
            // [{Name, Value}, …] (nzbget docs) and a flat alternating
            // ["name", "value", …] (what Sonarr/Radarr actually send).
            // The *arrs tag every add with a `drone` GUID here and match
            // queue/history items ONLY by it, so both must parse.
            let pp: Vec<(String, String)> = params
                .iter()
                .rev()
                .find_map(Value::as_array)
                .map(|a| {
                    if a.iter().all(Value::is_string) {
                        a.chunks(2)
                            .filter_map(|c| {
                                Some((
                                    c.first()?.as_str()?.to_string(),
                                    c.get(1)?.as_str()?.to_string(),
                                ))
                            })
                            .collect()
                    } else {
                        a.iter()
                            .filter_map(|p| {
                                let name = p.get("Name")?.as_str()?.to_string();
                                let value = match p.get("Value")? {
                                    Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                };
                                Some((name, value))
                            })
                            .collect()
                    }
                })
                .unwrap_or_default();
            match b64_decode(content).filter(|b| !b.is_empty()) {
                None => json!(0),
                Some(bytes) => match d.enqueue(
                    &bytes,
                    name,
                    category,
                    priority,
                    None,
                    &api_origin(&ua_hdr, "arr"),
                    false,
                ) {
                    Ok(nzo) => {
                        if !pp.is_empty() {
                            for j in d.queue.lock_ok().iter() {
                                let mut g = j.lock_ok();
                                if g.nzo_id == nzo {
                                    g.pp_params = pp.clone();
                                }
                            }
                        }
                        // AddToTop was parsed and discarded alongside
                        // AddPaused. Moving the job to the head of the
                        // queue is what the flag means; priority ordering
                        // still applies on top of it, as it does for any
                        // other job.
                        if add_to_top {
                            let mut q = d.queue.lock_ok();
                            if let Some(i) = q.iter().position(|j| j.lock_ok().nzo_id == nzo)
                                && let Some(j) = q.remove(i)
                            {
                                q.push_front(j);
                            }
                        }
                        if !pp.is_empty() || add_to_top {
                            d.save_queue();
                        }
                        json!(nzo_int(&nzo))
                    }
                    Err(e) => {
                        warn!(target: "jsonrpc", "append: {e}");
                        json!(0)
                    }
                },
            }
        }
        "editqueue" => {
            // [Command, Param, IDs] (v13+) or [Command, Offset, Text, IDs].
            let cmd = params.first().and_then(Value::as_str).unwrap_or("");
            let ids: Vec<i64> = params
                .iter()
                .rev()
                .find_map(|p| p.as_array())
                .map(|a| a.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default();
            let param_str = params
                .iter()
                .skip(1)
                .find_map(Value::as_str)
                .unwrap_or("")
                .to_string();
            // NZBGet addresses jobs by the numeric half of the nzo_id.
            let hit_id = |id: &str| ids.contains(&nzo_int(id));
            let mut ok = false;
            match cmd {
                "GroupPause" | "GroupResume" => {
                    if cmd == "GroupPause" {
                        // Pausing a job also stops its prefetch (same as
                        // the /api handler): the sidecar is the one part
                        // of a "paused" job that would keep downloading.
                        d.poke_sidecar(hit_id);
                    }
                    for j in d.queue.lock_ok().iter() {
                        let mut g = j.lock_ok();
                        if ids.contains(&nzo_int(&g.nzo_id)) {
                            g.paused = cmd == "GroupPause";
                            ok = true;
                        }
                    }
                    // The flag alone only bites when the job next enters
                    // the queue, so pausing the item that is actually
                    // downloading did nothing while answering success.
                    if cmd == "GroupPause" {
                        d.suspend_matching(true, |g| ids.contains(&nzo_int(&g.nzo_id)));
                    }
                }
                "GroupDelete" | "GroupDupeDelete" | "GroupFinalDelete" | "GroupParkDelete" => {
                    // A deleted job's prefetch sidecar must stop writing to
                    // its directory - the *arrs delete through here, so this
                    // is an ordinary path, not a corner of one.
                    d.poke_sidecar(hit_id);
                    let mut stopped_active = false;
                    let mut q = d.queue.lock_ok();
                    let before = q.len();
                    q.retain(|j| {
                        let mut g = j.lock_ok();
                        if ids.contains(&nzo_int(&g.nzo_id)) {
                            if g.state == JobState::Downloading {
                                // park() drops the record and its spooled .nzb.
                                g.tombstone = true;
                                stopped_active = true;
                            } else {
                                // Non-active record gone for good - drop its
                                // spooled NZB (retry only applies to history).
                                // Tombstoned too: a queued job can still be
                                // running in the prefetch sidecar, and an Ok
                                // that lands after this would otherwise run
                                // the whole completion tail and park the
                                // deleted job into history.
                                g.tombstone = true;
                                let _ = std::fs::remove_file(&g.nzb_path);
                            }
                            false
                        } else {
                            true
                        }
                    });
                    ok = q.len() < before;
                    drop(q);
                    if stopped_active {
                        if let Some(f) = d.hub.abort.lock_ok().as_ref() {
                            f.store(true, Ordering::Relaxed);
                        }
                        if let Some(c) = d.hub.queue_ctl.lock_ok().as_ref() {
                            c.abort();
                        }
                    }
                }
                "GroupMoveTop" | "GroupMoveBottom" => {
                    let mut q = d.queue.lock_ok();
                    let (mut hit, rest): (VecDeque<_>, VecDeque<_>) = q
                        .drain(..)
                        .partition(|j| ids.contains(&nzo_int(&j.lock_ok().nzo_id)));
                    ok = !hit.is_empty();
                    if cmd == "GroupMoveTop" {
                        hit.extend(rest);
                        *q = hit;
                    } else {
                        let mut rest = rest;
                        rest.extend(hit.drain(..));
                        *q = rest;
                    }
                }
                "GroupSetCategory" => {
                    // Untrusted category must never escape out_root at
                    // completion (tv_organize joins it onto the root). Force
                    // a single contained path component, like enqueue and
                    // history set_cat - this was the one write path skipping
                    // sanitize, allowing "../../.." traversal via editqueue.
                    let cat = if param_str.trim().is_empty() {
                        String::new()
                    } else {
                        nzbkit::disk::sanitize_filename(param_str.trim())
                    };
                    for j in d.queue.lock_ok().iter() {
                        let mut g = j.lock_ok();
                        if ids.contains(&nzo_int(&g.nzo_id)) {
                            g.category = cat.clone();
                            ok = true;
                        }
                    }
                    // Only when it actually landed on a job, matching the SAB
                    // change_cat precedent. Unconditional, a loop of
                    // editqueue calls naming ids that do not exist grows the
                    // persisted category list without bound and pollutes the
                    // list the *arrs validate against.
                    if ok {
                        d.register_cat(&cat);
                    }
                }
                "GroupSetPriority" => {
                    // The SAB facade has had this since M26 and this side
                    // never did, so which of the two client types the user
                    // picked in Sonarr decided whether priority worked at
                    // all - and an unknown command answered `false`, which
                    // is also what "no such job" answers.
                    let prio = nzbget_priority(param_str.trim().parse::<i64>().unwrap_or(0));
                    for j in d.queue.lock_ok().iter() {
                        let mut g = j.lock_ok();
                        if ids.contains(&nzo_int(&g.nzo_id)) {
                            g.priority = prio;
                            // Explicit priority overrides a watchdog
                            // deferral, exactly as on the SAB side.
                            g.deferred = false;
                            ok = true;
                        }
                    }
                }
                "HistoryDelete" | "HistoryFinalDelete" => {
                    let mut h = d.history.lock_ok();
                    let before = h.len();
                    h.retain(|j| {
                        let g = j.lock_ok();
                        let hit = ids.contains(&nzo_int(&g.nzo_id));
                        if hit {
                            // Record deleted for good - drop its spooled .nzb.
                            let _ = std::fs::remove_file(&g.nzb_path);
                        }
                        !hit
                    });
                    ok = h.len() < before;
                }
                "HistoryRedownload" | "HistoryReturn" | "HistoryRetry" => {
                    let jobs: Vec<String> = d
                        .history
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|j| ids.contains(&nzo_int(&j.lock_ok().nzo_id)))
                        .map(|j| j.lock_ok().nzo_id.clone())
                        .collect();
                    for nzo in jobs {
                        ok |= d.retry(&nzo);
                    }
                }
                other => {
                    // `false` was also the answer for "no such job", so a
                    // client could not tell a command we do not implement
                    // from one that simply matched nothing.
                    rpc_error = Some(format!("unsupported editqueue command {other:?}"));
                }
            }
            if rpc_error.is_none() {
                d.save_queue();
            }
            json!(ok)
        }
        "listfiles" => json!([]),
        "postqueue" => json!([]),
        // We have one pause, covering the whole pipeline - there is no
        // separate post-processing or scan queue to hold. Answering true
        // is honest for a caller asking us to stop doing that work.
        "pausepost" | "resumepost" | "pausescan" | "resumescan" => json!(true),
        "servervolumes" => json!([]),
        "log" | "loadlog" => {
            let n = params.get(1).and_then(Value::as_u64).unwrap_or(100) as usize;
            let lines = nzbkit::logtee::tail(n.min(1000));
            let now = unix_now();
            let entries: Vec<Value> = lines
                .iter()
                .enumerate()
                .map(|(i, l)| json!({"ID": i as u64 + 1, "Kind": "INFO", "Time": now, "Text": l}))
                .collect();
            json!(entries)
        }
        "writelog" | "scanupdate" | "resetservervolume" => json!(true),
        "config" | "loadconfig" => {
            // The *arrs' Test() validates their configured category against
            // CategoryN.Name entries and sanity-checks KeepHistory, so the
            // config dump must carry both or the nzbget client type fails
            // with "Category does not exist".
            //
            // KeepHistory is DELIBERATELY a non-zero literal, and must
            // stay one. We keep history indefinitely, which NZBGet spells
            // `0` - but Sonarr and Radarr reject a client reporting 0
            // ("KeepHistory should be greater than 0", their guard against
            // a downloader that forgets a job before they can import it),
            // and again above 25000. So the honest number is the one value
            // they refuse. 7 says "history sticks around for a while",
            // which is true, and the SAB facade's own
            // `history_retention_option: "all"` is the accurate answer for
            // the clients that ask in that dialect.
            let mut cfg = vec![
                json!({"Name": "ControlPort", "Value": d.port.to_string()}),
                json!({"Name": "DestDir", "Value": d.out_dir().to_string_lossy()}),
                json!({"Name": "AppVersion", "Value": "21.0"}),
                json!({"Name": "KeepHistory", "Value": "7"}),
            ];
            for (i, c) in d
                .cats
                .lock()
                .unwrap()
                .iter()
                .filter(|c| *c != "*")
                .enumerate()
            {
                let n = i + 1;
                cfg.push(json!({"Name": format!("Category{n}.Name"), "Value": c}));
                cfg.push(json!({
                    "Name": format!("Category{n}.DestDir"),
                    "Value": d.out_dir().join(c).to_string_lossy(),
                }));
            }
            json!(cfg)
        }
        other => {
            // A null result is indistinguishable from "succeeded, nothing
            // to report", so an unimplemented method looked like a
            // working one that had no answer. JSON-RPC has a code for
            // this and NZBGet itself uses it.
            rpc_error = Some(format!("no such method {other:?}"));
            Value::Null
        }
    };
    let resp = match rpc_error {
        Some(message) => json!({
            "version": "1.1",
            "result": Value::Null,
            "error": {"name": "JSONRPCError", "code": -32601, "message": message},
            "id": id,
        }),
        None => json!({"version": "1.1", "result": result, "error": Value::Null, "id": id}),
    };
    let _ = req.respond(json_resp(resp));
}

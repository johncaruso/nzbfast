//! M35 pull search: the external-indexer runtime state (caps cache,
//! per-day usage, limit backoff, the token->result cache that keeps the
//! user's indexer apikey out of the browser) and NZBLNK resolution.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// M35 pull-search runtime state, one lock for all of it: the caps
/// cache, the per-day usage counters, limit backoffs, and the
/// token->result cache. The result cache is the security seam: an
/// external result's NZB link embeds the user's indexer apikey, so the
/// browser only ever sees an opaque token and `indexer_grab` will fetch
/// exactly the URLs a search stored - never one the client supplies.
#[derive(Default)]
pub(super) struct IndexerRuntime {
    /// M35 phase 2: what each indexer's `t=caps` said, so an id search
    /// is only ever sent to a site that advertises the parameter. A
    /// FAILED probe is cached too (as None) - an indexer that cannot
    /// answer caps must not be re-probed on every keystroke-driven
    /// search - just for much less time than a success.
    ///
    /// Keyed by [`IndexerConfig::identity`] - the far end - and NOT by
    /// name: caps describe a site and an account, while the name is a
    /// label the user edits, reuses and types into unsaved drafts.
    /// See that method for what keying on the name cost.
    ///
    /// [`IndexerConfig::identity`]: crate::newznab::IndexerConfig::identity
    pub(super) caps: std::collections::HashMap<String, (Instant, Option<crate::newznab::Caps>)>,
    /// Indexers backing off after a limit error, by name. The name is
    /// right here: a budget/backoff belongs to the configured ENTRY the
    /// user set limits on, and only a saved entry ever runs a search.
    pub(super) penalty_until: std::collections::HashMap<String, Instant>,
    pub(super) usage: crate::newznab::Usage,
    #[cfg(feature = "indexer")]
    pub(super) results: std::collections::HashMap<String, IndexerHit>,
    /// Insertion order, for capping `results`.
    #[cfg(feature = "indexer")]
    pub(super) order: std::collections::VecDeque<String>,
}

/// One cached external search result, grabbable by token.
#[cfg(feature = "indexer")]
#[derive(Clone)]
pub(super) struct IndexerHit {
    pub(super) url: String,
    pub(super) title: String,
    pub(super) indexer: String,
    pub(super) at: Instant,
}

/// How far back the `addnzblnk` rate gate looks.
pub(super) const NZBLNK_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Link resolutions allowed per window before the endpoint refuses. A
/// person clicking board links does a handful a minute; a page in a loop
/// does not stop.
pub(super) const NZBLNK_MAX: usize = 20;
/// ...and how many of those may reach the user's indexers. Lower,
/// because this is the threshold that guards a metered account rather
/// than our own CPU. Past it the ladder still runs, local-only.
pub(super) const NZBLNK_EXTERNAL_MAX: usize = 6;

/// A grab token stays valid this long after its search.
#[cfg(feature = "indexer")]
pub(super) const INDEXER_HIT_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How long a pull search will wait for an xREL slot before giving up on
/// the id enrichment. Their search budget is 2 calls per 5 s, so a
/// second search inside that window finds the bucket empty - and a
/// search that returns its releases a beat sooner without an IMDb id is
/// a better answer than one that returns everything late.
#[cfg(feature = "indexer")]
pub(super) const XREL_UI_WAIT: std::time::Duration = std::time::Duration::from_millis(400);
/// Ceiling on cached external results across all searches.
#[cfg(feature = "indexer")]
pub(super) const INDEXER_HIT_CAP: usize = 5000;
/// Ceiling on one search/caps response body. A 100-item page of XML is
/// well under 1 MB; 8 MB is runaway-response territory, same idea as
/// [`FETCH_MAX_BYTES`].
pub(super) const INDEXER_BODY_MAX: u64 = 8 * 1024 * 1024;
/// How long a limit error (daily quota, HTTP 429) parks an indexer.
pub(super) const INDEXER_LIMIT_BACKOFF: std::time::Duration =
    std::time::Duration::from_secs(60 * 60);
/// How long a successful `t=caps` answer stays fresh. Capabilities
/// change when a site is upgraded, which is rare.
#[cfg(feature = "indexer")]
pub(super) const INDEXER_CAPS_TTL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);
/// How long a FAILED caps probe is remembered. Short, because the cause
/// is usually transient (the site was down), but not zero, because the
/// alternative is a caps request in front of every search.
#[cfg(feature = "indexer")]
pub(super) const INDEXER_CAPS_FAIL_TTL: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);

/// The one agent every pull-search call goes out through: SSRF-guarded
/// like every other daemon fetch, 15 s ceiling per call so a dead
/// indexer costs one timeout, not a wedged search.
pub(super) fn shared_indexer_agent() -> ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| ssrf_safe_agent(4, 15)).clone()
}

/// GET one indexer API URL, capped. Transport-level limit answers (a
/// real HTTP 429/503) map to `Limit` here; protocol errors ship as
/// HTTP 200 XML and are the caller's `parse_error` pass.
/// Blank the `apikey=` value anywhere in a string. A transport error's
/// Display carries the URL it failed on, and that URL carries the user's
/// key - which then rode into a toast, a rendered error row and anything
/// the user pasted into a bug report. M35's contract is that the key
/// never reaches a browser or a log, so it is scrubbed at the one choke
/// point every indexer error passes through.
pub(super) fn redact_apikey(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find("apikey=") {
        out.push_str(&rest[..p + "apikey=".len()]);
        out.push_str("***");
        // The value runs to the next query separator or to whatever ends
        // the URL inside a longer sentence.
        let tail = &rest[p + "apikey=".len()..];
        let end = tail
            .find(|c: char| c == '&' || c == '#' || c.is_whitespace())
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Cut every URL in a message down to `scheme://host`, dropping userinfo,
/// path and query.
///
/// [`redact_apikey`] guards the SEARCH path, where we built the URL and
/// therefore know the credential is spelled `apikey=`. The GRAB path has
/// no such guarantee: the NZB link comes out of the indexer's own XML,
/// and sites spell their credential `apikey`, `api_key`, `r`, `i`, or
/// put it in the path. Blanking one parameter name there is a guess.
/// The host is the only part of such a URL worth showing a user anyway -
/// it names who failed - so everything after it goes.
pub(crate) fn redact_url_creds(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    // Whichever scheme comes first, when both appear.
    while let Some(p) = match (rest.find("http://"), rest.find("https://")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    } {
        out.push_str(&rest[..p]);
        let url = &rest[p..];
        let scheme_len = if url.starts_with("https://") { 8 } else { 7 };
        // The authority ends at the first path/query/fragment character,
        // or at whatever ends the URL inside a longer sentence.
        let after = &url[scheme_len..];
        let end = after
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(after.len());
        let authority = &after[..end];
        // Userinfo (user:pass@host) is a credential too.
        let host = authority.rsplit('@').next().unwrap_or(authority);
        out.push_str(&url[..scheme_len]);
        out.push_str(host);
        // Anything else attached to the URL is dropped, up to whitespace.
        let tail = &after[end..];
        let stop = tail.find(char::is_whitespace).unwrap_or(tail.len());
        if stop > 0 {
            out.push_str("/...");
        }
        rest = &tail[stop..];
    }
    out.push_str(rest);
    out
}

pub(super) fn indexer_fetch(
    url: &str,
) -> std::result::Result<String, crate::newznab::NewznabError> {
    use crate::newznab::NewznabError;
    use std::io::Read as _;
    let resp = match shared_indexer_agent().get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code @ (429 | 503), _)) => {
            return Err(NewznabError::Limit(code, format!("HTTP {code}")));
        }
        Err(ureq::Error::Status(code, _)) => {
            return Err(NewznabError::Api(code, format!("HTTP {code}")));
        }
        Err(e) => return Err(NewznabError::Api(0, redact_apikey(&e.to_string()))),
    };
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(INDEXER_BODY_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| NewznabError::Api(0, redact_apikey(&e.to_string())))?;
    if bytes.len() as u64 > INDEXER_BODY_MAX {
        return Err(NewznabError::Api(0, "response too large".into()));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// One search against one indexer.
pub(super) fn indexer_search_one(
    cfg: &crate::newznab::IndexerConfig,
    q: &crate::newznab::SearchQuery,
) -> std::result::Result<Vec<crate::newznab::SearchResult>, crate::newznab::NewznabError> {
    let body = indexer_fetch(&crate::newznab::search_url(cfg, q))?;
    if let Some(e) = crate::newznab::parse_error(&body) {
        return Err(e);
    }
    Ok(crate::newznab::parse_results(&body))
}

/// This indexer's caps, from the cache when fresh, else probed. A probe
/// failure caches None (briefly) and the caller then plans a plain
/// free-text search, so caps trouble degrades the search rather than
/// failing it.
///
/// Only called when a query actually carries an id worth planning
/// around: a plain free-text search needs no caps at all, and must not
/// pay for a probe.
#[cfg(feature = "indexer")]
pub(super) fn indexer_caps_cached(
    d: &Daemon,
    cfg: &crate::newznab::IndexerConfig,
) -> Option<crate::newznab::Caps> {
    let id = cfg.identity();
    if let Some((at, caps)) = d.indexer_rt.lock_ok().caps.get(&id) {
        let ttl = if caps.is_some() {
            INDEXER_CAPS_TTL
        } else {
            INDEXER_CAPS_FAIL_TTL
        };
        if at.elapsed() < ttl {
            return caps.clone();
        }
    }
    let got = indexer_caps_one(cfg).ok();
    d.indexer_rt
        .lock()
        .unwrap()
        .caps
        .insert(id, (Instant::now(), got.clone()));
    got
}

/// One `t=caps` against one indexer, with a sanity check that the far
/// end is a Newznab API at all (a parked domain answers 200 with HTML,
/// which parses to an all-default Caps).
pub(super) fn indexer_caps_one(
    cfg: &crate::newznab::IndexerConfig,
) -> std::result::Result<crate::newznab::Caps, crate::newznab::NewznabError> {
    let body = indexer_fetch(&crate::newznab::caps_url(cfg))?;
    if let Some(e) = crate::newznab::parse_error(&body) {
        return Err(e);
    }
    let caps = crate::newznab::parse_caps(&body);
    if !caps.search && caps.server.is_empty() && caps.categories.is_empty() {
        return Err(crate::newznab::NewznabError::Api(
            0,
            "not a newznab API (no caps)".into(),
        ));
    }
    Ok(caps)
}

/// Persist the day's hit/grab counters; best-effort, tiny file.
/// Persist the day's indexer hit/grab counters.
///
/// The snapshot and the write are ONE critical section, and the write is
/// atomic. Both matter, and neither used to hold: the clone happened
/// under the runtime lock, the lock was then released, and a bare
/// `fs::write` followed. Two concurrent grabs could therefore snapshot 1
/// and 2 and land in that order or the other, so the file could end up
/// recording 1 after 2 was already counted - and a same-day restart
/// reloads whatever is on disk, handing back budget the user's paid
/// account had already spent. The bare write could also leave a
/// half-truncated file that reloads as no counters at all.
pub(super) fn save_indexer_usage(d: &Daemon) {
    // Separate from indexer_rt: this is held across file I/O, and
    // indexer_rt is on the search path.
    static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = IO.lock_ok();
    let u = d.indexer_rt.lock_ok().usage.clone();
    if let Ok(b) = serde_json::to_vec(&u)
        && let Err(e) = crate::persist::write_atomic(&d.spool.join("indexer-usage.json"), &b)
    {
        warn!(target: "indexer", "could not persist usage counters: {e}");
    }
}

/// Turn one parsed NZBLNK into a queued job, or say why not.
///
/// The ladder is our own index first (free, offline, and it can emit the
/// NZB straight from the segment ids the scan stored) and the user's
/// configured indexers second (one API hit each, under the same daily
/// budgets and limit backoff the pull search obeys).
///
/// A local hit that is INCOMPLETE does not short-circuit the ladder: a
/// synthesized NZB missing parts downloads and then fails repair, so the
/// indexers get their turn first and the partial release is only used
/// when nothing else answered - with a note saying so, because "queued,
/// and we already know parts are missing" is not the same promise as
/// "queued".
pub(super) fn resolve_nzblnk(
    d: &Daemon,
    l: &nzbkit::nzblnk::NzbLnk,
    cat: &str,
    prio: i32,
    password: Option<&str>,
    dupe_ok: bool,
) -> serde_json::Value {
    let mut notes: Vec<serde_json::Value> = Vec::new();

    // ---- The rate gate. ---------------------------------------------
    // Two thresholds off one sliding window, because the two things a
    // loop can spend are not equally scarce. Local resolution costs CPU
    // (rung 3 of find_by_header is an unindexed scan); asking the
    // indexers costs the user's metered account. So the cheap half stays
    // available far longer than the expensive one, and passing the
    // second threshold DEGRADES to local-only rather than failing - a
    // link our own index can answer is answered.
    let recent = {
        let mut q = d.nzblnk_recent.lock_ok();
        let now = Instant::now();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > NZBLNK_WINDOW)
        {
            q.pop_front();
        }
        if q.len() >= NZBLNK_MAX {
            return json!({"status": false, "reason": "toofast",
                "error": "too many links at once - wait a moment and try again"});
        }
        q.push_back(now);
        q.len()
    };
    let may_ask_indexers = recent <= NZBLNK_EXTERNAL_MAX;

    // ---- Rung 1: our own header index. ------------------------------
    // Ranking, strongest first: complete beats partial, a release in a
    // group the link named beats one somewhere else, then size. `>` and
    // not `>=`, so ties keep find_by_header's own ordering (exact stem
    // ahead of a filename match).
    #[cfg(feature = "indexer")]
    let rank = |r: &nzbkit::index::Release| {
        (
            r.complete,
            l.groups.is_empty() || l.groups.iter().any(|g| g.eq_ignore_ascii_case(&r.grp)),
            r.total_bytes,
        )
    };
    // with_index_read on both index calls: this is an interactive
    // handler, and rung 3 of find_by_header is a table scan. On the
    // read-write connection a catch-up ingest or maintenance pass would
    // park the paste for as long as it holds the mutex (measured at 62s
    // for wall2 before the read-only connection existed).
    #[cfg(feature = "indexer")]
    let local = d.with_index_read(|ix| {
        let mut best: Option<nzbkit::index::Release> = None;
        for r in ix.find_by_header(&l.header, 8).ok()? {
            if best.as_ref().is_none_or(|b| rank(&r) > rank(b)) {
                best = Some(r);
            }
        }
        best
    });
    #[cfg(feature = "indexer")]
    let queue_local = |r: &nzbkit::index::Release,
                       partial: bool,
                       notes: &Vec<serde_json::Value>| {
        let xml = match d.with_index_read(|ix| ix.make_nzb(r.id).ok()) {
            Some(x) => x,
            None => {
                return json!({"status": false, "error": "the index could not rebuild that post"});
            }
        };
        let name = if l.title.is_empty() {
            r.stem.clone()
        } else {
            l.title.clone()
        };
        match d.enqueue(
            xml.as_bytes(),
            &name,
            cat,
            prio,
            password,
            "nzblnk",
            dupe_ok,
        ) {
            Ok(nzo) => {
                // Same protection a wall grab gets: the row this job came
                // from must survive the index size cap.
                d.touch_opened_release(r.id);
                json!({"status": true, "nzo_ids": [nzo], "name": name, "via": "index",
                       "partial": partial, "notes": notes})
            }
            Err(e) => json!({"status": false, "error": e.to_string()}),
        }
    };
    #[cfg(feature = "indexer")]
    if let Some(r) = local.as_ref().filter(|r| r.complete) {
        return queue_local(r, false, &notes);
    }
    #[cfg(feature = "indexer")]
    if local.is_some() {
        notes.push(json!({"index": "found the post, but parts are still missing"}));
    }

    // ---- Rung 2: the user's indexers, over the M35 client. -----------
    // A header is free text, so this is a plain `t=search` - no caps
    // probe (an id-less query never needs one) and no category filter,
    // because an obfuscated release name tells nobody what it is.
    let list: Vec<crate::newznab::IndexerConfig> = if may_ask_indexers {
        d.indexers
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.enabled)
            .cloned()
            .collect()
    } else {
        notes.push(json!({"indexers":
            "skipped: too many link lookups just now, so only the local index was searched"}));
        Vec::new()
    };
    let mut runnable = Vec::new();
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(unix_now());
        let now = Instant::now();
        for i in list {
            if rt.penalty_until.get(&i.name).is_some_and(|t| *t > now) {
                notes.push(json!({"indexer": i.name,
                    "skipped": "backing off after a limit error"}));
            } else if !rt.usage.hit_allowed(&i) {
                notes.push(json!({"indexer": i.name, "skipped": "daily API budget reached"}));
            } else {
                rt.usage.count_hit(&i.name);
                runnable.push(i);
            }
        }
    }
    if !runnable.is_empty() {
        save_indexer_usage(d);
    }
    let query = crate::newznab::SearchQuery {
        q: l.header.clone(),
        limit: 100,
        ..Default::default()
    };
    let outcomes: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = runnable
            .into_iter()
            .map(|i| {
                let query = query.clone();
                s.spawn(move || {
                    let r = indexer_search_one(&i, &query);
                    (i, r)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    // A header identifies ONE posting, so this picks a single winner
    // rather than building a result list: a title that actually contains
    // the header beats one that merely matched some token of it, then
    // indexer priority, then the newest upload.
    let norm = |s: &str| {
        s.to_ascii_lowercase()
            .replace(['.', '_', '-'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let want = norm(&l.header);
    let mut best: Option<(u8, i32, i64, crate::newznab::SearchResult, String)> = None;
    {
        let mut rt = d.indexer_rt.lock_ok();
        let now = Instant::now();
        for (cfg, outcome) in outcomes {
            match outcome {
                Ok(items) => {
                    for item in items {
                        let k = (
                            u8::from(!norm(&item.title).contains(&want)),
                            cfg.priority,
                            -item.posted,
                        );
                        if best.as_ref().is_none_or(|b| k < (b.0, b.1, b.2)) {
                            best = Some((k.0, k.1, k.2, item, cfg.name.clone()));
                        }
                    }
                }
                Err(e) => {
                    if matches!(e, crate::newznab::NewznabError::Limit(..)) {
                        rt.penalty_until
                            .insert(cfg.name.clone(), now + INDEXER_LIMIT_BACKOFF);
                    }
                    notes.push(json!({"indexer": cfg.name, "error": e.to_string()}));
                }
            }
        }
    }
    if let Some((_, _, _, item, indexer)) = best {
        let allowed = {
            let mut rt = d.indexer_rt.lock_ok();
            rt.usage.roll(unix_now());
            d.indexers
                .lock()
                .unwrap()
                .iter()
                .find(|i| i.name == indexer)
                .is_none_or(|c| rt.usage.grab_allowed(c))
        };
        if !allowed {
            notes.push(json!({"indexer": indexer, "skipped": "daily grab budget reached"}));
        } else {
            let name = if l.title.is_empty() {
                item.title.clone()
            } else {
                l.title.clone()
            };
            match fetch_url(&item.link)
                .map_err(|e| e.to_string())
                .and_then(|f| {
                    d.enqueue_fetched(&f, &name, cat, prio, password, 0, "nzblnk", dupe_ok)
                        .map_err(|e| e.to_string())
                }) {
                Ok(nzo) => {
                    d.indexer_rt.lock_ok().usage.count_grab(&indexer);
                    save_indexer_usage(d);
                    return json!({"status": true, "nzo_ids": [nzo], "name": name,
                                  "via": indexer, "partial": false, "notes": notes});
                }
                // The NZB link itself failed. Not fatal to the ladder -
                // a partial local copy may still be better than nothing.
                //
                // redact_url_creds: fetch_url names the URL it failed on,
                // and that URL is the enclosure link out of the indexer's
                // XML, which carries the user's account credential. This
                // string goes straight into the dashboard's notes.
                Err(e) => notes.push(json!({"indexer": indexer, "error": redact_url_creds(&e)})),
            }
        }
    }

    // ---- Last resort: the partial local hit, honestly labelled. ------
    #[cfg(feature = "indexer")]
    if let Some(r) = local.as_ref() {
        return queue_local(r, true, &notes);
    }
    json!({"status": false, "reason": "notfound", "notes": notes,
           "error": "nothing found for that link - the post may be too new to be indexed, \
                     or too old to still be on your server"})
}

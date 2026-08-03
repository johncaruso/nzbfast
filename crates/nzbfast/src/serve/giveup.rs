//! §96.3: the per-target give-up breaker.
//!
//! An *arr whose grab fails blocklists that RELEASE and immediately
//! searches for another - and for content that is simply dead on Usenet
//! (every copy DMCA'd, an abandoned obfuscated post) that loop never
//! terminates: each replacement fails the same way, our re-grab backoff
//! only slows the cadence, and the block account pays for every lap. The
//! same storm exists on our own watchlist: `Slot.failed` stops a dead
//! release being re-picked, but nothing ever concludes "this EPISODE is
//! not obtainable, stop".
//!
//! The breaker counts final failures per TARGET (an episode, a movie, a
//! dated show) across both grab paths, and at a configurable threshold
//! gives the target up:
//!
//!  - jobs an *arr sent us: unmonitor the target in the *arr FIRST, then
//!    drop its queue record with blocklist-and-NO-re-search. The order is
//!    load-bearing - the *arr's own poll cycle races us to the failed
//!    record, and its failed-download handling re-searches only a
//!    MONITORED target, so unmonitoring first makes losing the race
//!    harmless (AltMount's `import_failure.go` shipped this shape).
//!    Only the instance that PROVES it sent the grab (its history holds
//!    our downloadId) is touched - see the ownership gate on
//!    `arr_give_up`.
//!  - watchlist grabs: the watchlist pass skips every candidate whose
//!    parsed target is given up. That IS the unmonitor - there is no
//!    second grab path to close (see memory `nzbfast-watchlist`).
//!
//! Below the threshold nothing changes: the *arr's normal
//! blocklist-and-re-search is exactly right while alternatives remain.
//! The threshold defaults to 0 = off; talking to the user's *arr on our
//! own initiative is opt-in, not a surprise.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::wall::{Kind, Parsed};

/// One configured *arr the breaker may act on (settings key
/// `arr_instances`). The apikey is a credential: `get_config` exposes
/// only `has_key`, and the settings writer merges a blank key onto the
/// stored one, same contract as `notify_targets` tokens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArrInstance {
    #[serde(default)]
    pub name: String,
    /// "sonarr" or "radarr". Lidarr/Readarr are out: our parser has no
    /// album/book identity a counter could key on.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub apikey: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Failures accumulated against one target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetFails {
    /// Distinct release stems that FINALLY failed for this target - the
    /// count that trips the breaker. Distinct, because a retry of the
    /// same dead release is one piece of evidence, not two.
    #[serde(default)]
    pub stems: Vec<String>,
    #[serde(default)]
    pub last_unix: i64,
    /// The *arr-side give-up already fired for this target. Latched so
    /// one storm produces one unmonitor call, and so a user who
    /// deliberately RE-monitors is not fought at the very next failure -
    /// only a completed download (which clears the entry) re-arms it.
    #[serde(default)]
    pub actioned: bool,
    /// Which incarnation of this target the entry is (Codex sweep 2,
    /// 3 Aug M3). The *arr give-up runs on a spawned thread holding
    /// cloned keys, and a slow Sonarr leaves a wide window in which the
    /// user can press "Try again" and re-monitor the target - after
    /// which the stale worker used to complete and unmonitor it all
    /// over again. Every entry gets a process-unique number at
    /// creation, the worker captures it, and both the destructive calls
    /// and the failure repair check it is still the live one.
    ///
    /// Not persisted: a restart has no in-flight workers to fool, and a
    /// number that survived one would be the one thing that could
    /// collide.
    #[serde(skip)]
    pub generation: u64,
}

/// Source of [`TargetFails::generation`]. Process-lifetime and strictly
/// increasing, so a removed-and-recreated target never reuses the
/// number a worker is still holding - which is exactly what a
/// per-entry counter reset by `remove` would do.
static NEXT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The (key, generation) pairs a spawned give-up worker carries, so it
/// can ask whether the targets it was launched for are still the ones
/// the user has.
pub type ActionToken = Vec<(String, u64)>;

/// The persisted counter store (.spool/giveup-state.json).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GiveupState {
    #[serde(default)]
    pub targets: HashMap<String, TargetFails>,
}

/// Evidence this old is forgotten: content that failed six weeks ago may
/// simply exist by now (a repost), and an unbounded store would grow for
/// the life of the install.
const EXPIRE_SECS: i64 = 45 * 24 * 3600;

/// Stems kept per target. Only the count up to the threshold ever
/// decides anything; the cap stops a pathological storm growing one
/// entry without bound.
const MAX_STEMS: usize = 64;

/// The target keys a release counts against - empty when the name
/// carries no identity worth counting (obfuscated, unparsed, music).
///
/// Episode-level on purpose: "the *arr keeps re-grabbing THIS episode"
/// is the storm being broken, and a season key would let eight different
/// episodes' honest one-off failures add up to a false trip. A
/// multi-episode release counts against every episode it covers, so a
/// storm that alternates single and double posts still converges on one
/// counter.
pub fn target_keys(p: &Parsed) -> Vec<String> {
    if p.title.is_empty() {
        return Vec::new();
    }
    match p.kind {
        Kind::Movie => vec![p.key.clone()],
        Kind::Tv => {
            if let Some(d) = &p.date {
                return vec![format!("{}:d{}", p.key, d)];
            }
            match (p.season, p.episode) {
                (Some(s), Some(e)) => {
                    // A junk-parsed "E01-E99" span must not mint 99
                    // counters; real multi-episode posts cover 2-3.
                    let last = p.episode2.filter(|e2| *e2 > e && e2 - e <= 12).unwrap_or(e);
                    (e..=last)
                        .map(|ep| format!("{}:s{:02}e{:02}", p.key, s, ep))
                        .collect()
                }
                // A season pack is its own target: it fails as one thing.
                (Some(s), None) => vec![format!("{}:s{:02}", p.key, s)],
                _ => vec![p.key.clone()],
            }
        }
        _ => Vec::new(),
    }
}

impl GiveupState {
    /// The entry for `key`, minting a fresh generation if it is new.
    /// Every creation site goes through this - an entry born through a
    /// bare `or_default()` would carry generation 0 and match a stale
    /// worker's captured 0.
    fn entry(&mut self, key: &str) -> &mut TargetFails {
        self.targets
            .entry(key.to_string())
            .or_insert_with(|| TargetFails {
                generation: NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                ..Default::default()
            })
    }

    /// Record one FINAL failure of `stem` against `keys`. Returns the
    /// highest failure count any of the keys now holds (0 when `keys`
    /// is empty), after expiring stale entries.
    pub fn record_failure(&mut self, keys: &[String], stem: &str, now: i64) -> usize {
        self.prune(now);
        let mut worst = 0;
        for k in keys {
            let t = self.entry(k);
            t.last_unix = now;
            if !t.stems.iter().any(|s| s == stem) && t.stems.len() < MAX_STEMS {
                t.stems.push(stem.to_string());
            }
            worst = worst.max(t.stems.len());
        }
        worst
    }

    /// A completed download settles the question - the content was
    /// obtainable after all. Clears the counters (and re-arms the
    /// latched action) for every key the release covers. Returns whether
    /// anything was actually recorded against them - the common case is
    /// nothing, and the caller skips a state-file write on it.
    pub fn record_success(&mut self, keys: &[String]) -> bool {
        let mut any = false;
        for k in keys {
            any |= self.targets.remove(k).is_some();
        }
        any
    }

    /// Is this parsed release's target given up? True once any covered
    /// key reached the threshold (or was already actioned in the *arr).
    /// `threshold` 0 = the breaker is off, nothing is ever given up.
    pub fn tripped(&self, p: &Parsed, threshold: u32) -> bool {
        if threshold == 0 {
            return false;
        }
        target_keys(p).iter().any(|k| {
            self.targets
                .get(k)
                .is_some_and(|t| t.actioned || t.stems.len() >= threshold as usize)
        })
    }

    /// Latch "the *arr-side give-up fired" on `keys`. Returns false when
    /// every key was already actioned - the caller must not fire again.
    pub fn latch_action(&mut self, keys: &[String]) -> bool {
        let mut fresh = false;
        for k in keys {
            let t = self.entry(k);
            if !t.actioned {
                t.actioned = true;
                fresh = true;
            }
        }
        fresh
    }

    /// Snapshot which incarnation of each key the caller is acting on.
    /// Taken under the same lock as [`Self::latch_action`], and carried
    /// by the worker for the life of its remote calls.
    pub fn action_token(&self, keys: &[String]) -> ActionToken {
        keys.iter()
            .map(|k| {
                (
                    k.clone(),
                    self.targets.get(k).map(|t| t.generation).unwrap_or(0),
                )
            })
            .collect()
    }

    /// Is every key in `token` still the incarnation that was latched -
    /// still present, still the same generation, still actioned?
    ///
    /// ALL of them, not any: the keys were latched together, so they
    /// only diverge when the user has cleared one, and clearing even
    /// one episode of a multi-episode target is an explicit "chase this
    /// again". Standing down on the whole action is the cautious
    /// reading, and the caller's action is destructive and remote.
    pub fn action_current(&self, token: &[(String, u64)]) -> bool {
        !token.is_empty()
            && token.iter().all(|(k, want)| {
                self.targets
                    .get(k)
                    .is_some_and(|t| t.generation == *want && t.actioned)
            })
    }

    /// Release the latch on `token`: the remote give-up did NOT happen
    /// (every owning instance errored), so the next final failure must
    /// try again. The failure counts stay - locally the target remains
    /// given up either way, this only re-arms the *arr call.
    ///
    /// Generation-checked, or a worker whose calls all failed would
    /// clear the latch of a target the user reset and a fresh storm
    /// re-created while it was still running - re-arming an action the
    /// new generation had deliberately just taken.
    ///
    /// Narrower than [`Self::clear_target`], which forgets the target
    /// outright: this is the automatic repair for a failed remote call,
    /// that one is the user pressing "try again".
    pub fn clear_action(&mut self, token: &[(String, u64)]) {
        for (k, want) in token {
            if let Some(t) = self.targets.get_mut(k)
                && t.generation == *want
            {
                t.actioned = false;
            }
        }
    }

    /// Forget everything recorded against `key` - the "try again" the
    /// dashboard offers on a given-up target. Same semantics as a
    /// completed download settling the question: the counters go and the
    /// action latch re-arms, so the next storm can act once more.
    /// Returns whether there was anything to clear.
    pub fn clear_target(&mut self, key: &str) -> bool {
        self.targets.remove(key).is_some()
    }

    /// The give-up list as the dashboard reads it: one row per target,
    /// given-up ones first, then most recently touched. Reporting ONLY -
    /// nothing here decides a grab (the watchlist keeps its single grab
    /// path; see the module note).
    pub fn status_rows(&self, threshold: u32) -> Vec<Value> {
        let mut rows: Vec<(bool, i64, &String, &TargetFails)> = self
            .targets
            .iter()
            .map(|(k, t)| {
                let tripped = threshold > 0 && (t.actioned || t.stems.len() >= threshold as usize);
                (tripped, t.last_unix, k, t)
            })
            .collect();
        // Given up first (they are the actionable ones), newest first
        // within each group, key last so the order never depends on hash
        // iteration - a list that reshuffles under the cursor is worse
        // than one in a dull order.
        rows.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.cmp(b.2))
        });
        rows.into_iter()
            .map(|(tripped, last_unix, key, t)| {
                json!({
                    "key": key,
                    "label": target_label(key),
                    "stems": t.stems.len(),
                    // The last release that failed: the key names the
                    // episode, this names the copy of it, which is what
                    // a user recognises.
                    "last_stem": t.stems.last().cloned().unwrap_or_default(),
                    "actioned": t.actioned,
                    "last_unix": last_unix,
                    "tripped": tripped,
                })
            })
            .collect()
    }

    fn prune(&mut self, now: i64) {
        self.targets.retain(|_, t| now - t.last_unix < EXPIRE_SECS);
    }
}

/// A readable name for a target key. The key is machine-made
/// (`m:the matrix:1999`, `t:some show:s01e05`, `t:some show:d20260721`),
/// and its parts are identifiers rather than prose - so this assembles
/// them rather than being translated, exactly like a release name.
/// Anything unrecognised is shown as-is: a wrong guess would be worse
/// than the raw key.
pub fn target_label(key: &str) -> String {
    let mut parts = key.splitn(3, ':');
    let (kind, title, tail) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    if title.is_empty() {
        return key.to_string();
    }
    let name = title_case(title);
    match kind {
        "m" if tail.is_empty() => name,
        "m" => format!("{name} ({tail})"),
        "t" if tail.is_empty() => name,
        "t" => match tail.strip_prefix('d') {
            // A daily's date reads as the night it aired.
            Some(d) if d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit()) => {
                format!("{name} {}-{}-{}", &d[..4], &d[4..6], &d[6..])
            }
            _ => format!("{name} {}", tail.to_uppercase()),
        },
        _ => key.to_string(),
    }
}

/// Title-case a normalised title ("some show" → "Some Show"). The keys
/// are lowercased by `norm_title`, and a list of lowercase titles beside
/// properly-cased release names reads like a bug.
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

// ---------------------------------------------------------------------------
// The *arr side: unmonitor, then blocklist without re-search
// ---------------------------------------------------------------------------

/// HTTP agent for *arr calls: SSRF-guarded like every other outbound
/// fetch (the guard deliberately permits the LAN and loopback addresses
/// an *arr actually lives on), no redirects, short timeout - these are
/// LAN round-trips and the caller is on the blocking pool.
fn agent() -> ureq::Agent {
    super::ssrf_safe_agent(0, 10)
}

fn api_get(a: &ureq::Agent, inst: &ArrInstance, path: &str) -> Result<Value, String> {
    let url = format!("{}{}", inst.url.trim().trim_end_matches('/'), path);
    let text = a
        .get(&url)
        .set("X-Api-Key", &inst.apikey)
        .call()
        .map_err(err_str)?
        .into_string()
        .map_err(|e| format!("read from {}: {e}", inst.name))?;
    serde_json::from_str(&text).map_err(|e| format!("bad json from {}: {e}", inst.name))
}

fn api_send(
    a: &ureq::Agent,
    inst: &ArrInstance,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(), String> {
    let url = format!("{}{}", inst.url.trim().trim_end_matches('/'), path);
    let req = a.request(method, &url).set("X-Api-Key", &inst.apikey);
    match body {
        Some(b) => req
            .set("Content-Type", "application/json")
            .send_string(&b.to_string()),
        None => req.call(),
    }
    .map(|_| ())
    .map_err(err_str)
}

/// ureq transport errors Display the full URL, query included. Nothing
/// here carries the apikey in the query (it travels in a header), but
/// the rebuilt message is still the readable form.
fn err_str(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("HTTP {code}"),
        ureq::Error::Transport(t) => format!(
            "{}{}",
            t.kind(),
            t.message().map(|m| format!(": {m}")).unwrap_or_default()
        ),
    }
}

/// Give a target up in one *arr: find the failed grab, unmonitor its
/// episode(s)/movie, then delete the *arr's queue record with
/// blocklist=true and skipRedownload=true (blocklist WITHOUT re-search).
///
/// OWNERSHIP GATE, load-bearing: the job records no configured-instance
/// identity (its origin is just `arr`/`arr:<ua>`), so before anything
/// destructive the instance must PROVE it sent this grab - its own
/// history must hold a record for our `downloadId`. Only the *arr that
/// grabbed a download ever writes such a record; a sibling instance that
/// merely monitors the same show (or merely shares us as a download
/// client) has none, and its parser recognising the title is not
/// evidence it owns the download. Without this gate the parse fallback
/// below would unmonitor the target in every configured instance, and a
/// job added by curl (whose UA classifies as `arr:curl`) could unmonitor
/// targets no *arr ever asked us for.
///
/// Resolution is by `downloadId` - the nzo_id the *arr got back from our
/// add call - which is exact. When the *arr's poll already swept the
/// queue record away (the race this whole design survives), fall back to
/// its own release-name parser to find the target and still unmonitor;
/// that is safe only BECAUSE ownership is already proven. The blocklist
/// half is skipped then, because the poll that swept the record has
/// already blocklisted the release itself.
///
/// `still_wanted` is re-asked immediately before each destructive step,
/// never merely on the way in (Codex sweep 2, 3 Aug M3). Everything
/// before step 2 is remote GETs against an *arr that may be slow, and
/// the user can press "Try again" and re-monitor the target throughout
/// that window - a check taken at the top would be exactly as stale as
/// no check at all. Answering false stands the give-up down as
/// Ok(None): nothing happened, and nothing needs retrying.
///
/// Returns Ok(Some(summary)) after acting, Ok(None) when this instance
/// does not own the grab (the ordinary answer for every instance but
/// one) or the target was reset under us, and Err only for a real
/// failure - transport, auth, bad JSON - that the caller may retry.
pub fn arr_give_up(
    inst: &ArrInstance,
    nzo_id: &str,
    release: &str,
    still_wanted: &dyn Fn() -> bool,
) -> Result<Option<String>, String> {
    let base = inst.url.trim().trim_end_matches('/');
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err("url must start with http:// or https://".into());
    }
    let sonarr = match inst.kind.as_str() {
        "sonarr" => true,
        "radarr" => false,
        k => return Err(format!("unknown kind {k:?}")),
    };
    let a = agent();

    // 0. Ownership: does this instance's history know our downloadId?
    let h = api_get(
        &a,
        inst,
        &format!(
            "/api/v3/history?page=1&pageSize=50&downloadId={}",
            urlencode(nzo_id)
        ),
    )?;
    let owns = h
        .get("records")
        .and_then(Value::as_array)
        .is_some_and(|r| !r.is_empty());
    if !owns {
        return Ok(None);
    }

    // 1. The *arr's queue records for this grab. One per episode for a
    //    multi-episode release, all sharing our nzo_id as downloadId.
    let q = api_get(
        &a,
        inst,
        // includeUnknownSeriesItems: a queue record whose series mapping
        // failed still carries the downloadId we are looking for.
        &format!(
            "/api/v3/queue?page=1&pageSize=1000{}",
            if sonarr {
                "&includeUnknownSeriesItems=true"
            } else {
                ""
            }
        ),
    )?;
    let empty = Vec::new();
    let records: Vec<&Value> = q
        .get("records")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter(|r| {
            r.get("downloadId")
                .and_then(Value::as_str)
                .is_some_and(|d| d.eq_ignore_ascii_case(nzo_id))
        })
        .collect();

    let mut episode_ids: Vec<i64> = Vec::new();
    let mut movie_id: Option<i64> = None;
    let mut queue_ids: Vec<i64> = Vec::new();
    for r in &records {
        if let Some(id) = r.get("id").and_then(Value::as_i64) {
            queue_ids.push(id);
        }
        if sonarr {
            if let Some(e) = r.get("episodeId").and_then(Value::as_i64) {
                episode_ids.push(e);
            }
        } else if movie_id.is_none() {
            movie_id = r.get("movieId").and_then(Value::as_i64);
        }
    }

    // Swept already? Ask the *arr's own parser who this release was.
    if episode_ids.is_empty() && movie_id.is_none() {
        let parsed = api_get(
            &a,
            inst,
            &format!("/api/v3/parse?title={}", urlencode(release)),
        )?;
        if sonarr {
            episode_ids = parsed
                .get("episodes")
                .and_then(Value::as_array)
                .unwrap_or(&empty)
                .iter()
                .filter_map(|e| e.get("id").and_then(Value::as_i64))
                .collect();
        } else {
            movie_id = parsed
                .get("movie")
                .and_then(|m| m.get("id"))
                .and_then(Value::as_i64);
        }
    }
    if episode_ids.is_empty() && movie_id.is_none() {
        return Err("target not found".into());
    }

    // 2. Unmonitor FIRST - after this, losing any race with the *arr's
    //    poll costs nothing, because failed-download handling only
    //    re-searches a monitored target.
    //
    // Last chance to stand down: every call above was a GET against a
    // possibly-slow *arr, and this is the first one that changes
    // anything the user can see.
    if !still_wanted() {
        return Ok(None);
    }
    if sonarr {
        api_send(
            &a,
            inst,
            "PUT",
            "/api/v3/episode/monitor",
            Some(&json!({"episodeIds": episode_ids, "monitored": false})),
        )?;
    } else {
        let id = movie_id.unwrap();
        let mut movie = api_get(&a, inst, &format!("/api/v3/movie/{id}"))?;
        movie["monitored"] = json!(false);
        api_send(
            &a,
            inst,
            "PUT",
            &format!("/api/v3/movie/{id}"),
            Some(&movie),
        )?;
    }

    // 3. Then drop the queue record(s): blocklist the release so it is
    //    never grabbed again, skipRedownload so no search replaces it,
    //    removeFromClient=false because on our side the job is already
    //    parked in history (and a delete callback here would be a loop).
    //
    // Re-asked: the unmonitor above is one more remote round-trip of
    // window, and blocklisting is the half the user cannot undo from
    // our side at all.
    if !still_wanted() {
        return Ok(Some(format!(
            "{}: unmonitored, then stood down before blocklisting - the target was \
             reset while the call was in flight",
            inst.name
        )));
    }
    for id in &queue_ids {
        api_send(
            &a,
            inst,
            "DELETE",
            &format!(
                "/api/v3/queue/{id}?removeFromClient=false&blocklist=true&skipRedownload=true"
            ),
            None,
        )?;
    }

    Ok(Some(format!(
        "{}: unmonitored {} and dropped {} queue record(s), blocklisted without re-search",
        inst.name,
        if sonarr {
            format!("{} episode(s)", episode_ids.len())
        } else {
            "the movie".into()
        },
        queue_ids.len()
    )))
}

/// Query-string percent-encoding, strict: everything outside the
/// unreserved set is encoded, so a release name full of spaces and
/// brackets survives the trip.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wall::parse_release;

    fn keys(name: &str) -> Vec<String> {
        target_keys(&parse_release(name))
    }

    /// The revalidation hook for tests that are not about it: the
    /// target is still wanted throughout. The stand-down path has its
    /// own state-side test above.
    fn wanted() -> bool {
        true
    }

    #[test]
    fn target_keys_name_the_episode_not_the_release() {
        // Two different releases of one episode share a key - that is
        // the whole point.
        assert_eq!(
            keys("Show.S01E05.1080p.WEB.H264-AAA"),
            keys("Show.S01E05.720p.HDTV.x264-BBB")
        );
        assert_eq!(keys("Show.S01E05.1080p.WEB.H264-AAA").len(), 1);
        // A neighbouring episode does not.
        assert_ne!(
            keys("Show.S01E05.1080p.WEB.H264-AAA"),
            keys("Show.S01E06.1080p.WEB.H264-AAA")
        );
    }

    /// Codex sweep 2, 3 Aug M3. The *arr give-up runs on a spawned
    /// thread; "Try again" runs on the request thread. With a slow
    /// Sonarr the second finishes first, and the worker then
    /// unmonitored a target the user had just re-monitored.
    #[test]
    fn a_reset_target_stands_down_the_action_already_in_flight() {
        let k = keys("Show.S01E05.1080p.WEB.H264-AAA");
        let mut st = GiveupState::default();
        st.record_failure(&k, "Show.S01E05.1080p.WEB.H264-AAA", 1_000);
        assert!(st.latch_action(&k));
        // What the worker carries away with it.
        let token = st.action_token(&k);
        assert!(st.action_current(&token), "the action starts out live");

        // The user presses "Try again" while the worker is inside its
        // *arr round-trips.
        assert!(st.clear_target(&k[0]));
        assert!(
            !st.action_current(&token),
            "a cleared target must stand the in-flight action down"
        );

        // A fresh storm re-creates the target and takes its own latch.
        st.record_failure(&k, "Show.S01E05.720p.HDTV.x264-BBB", 2_000);
        assert!(st.latch_action(&k));
        assert!(
            !st.action_current(&token),
            "the recreated target is a new incarnation, not the old one - \
             a per-entry counter reset by remove() would have collided here"
        );
        let fresh = st.action_token(&k);
        assert!(st.action_current(&fresh));

        // ...and the stale worker's failure repair must not re-arm the
        // NEW generation's latch.
        st.clear_action(&token);
        assert!(
            st.targets[&k[0]].actioned,
            "clear_action from a stale generation must not touch the live latch"
        );
        st.clear_action(&fresh);
        assert!(
            !st.targets[&k[0]].actioned,
            "the live generation's own repair still works"
        );
    }

    #[test]
    fn multi_episode_counts_against_every_covered_episode() {
        let k = keys("Show.S02E03E04.1080p.WEB.H264-GRP");
        assert_eq!(k.len(), 2);
        assert!(k.contains(&keys("Show.S02E03.1080p.WEB-X")[0]));
        assert!(k.contains(&keys("Show.S02E04.1080p.WEB-X")[0]));
    }

    #[test]
    fn movies_and_packs_and_dailies_key_sensibly() {
        // A movie is one target regardless of quality.
        assert_eq!(
            keys("Some.Film.2023.2160p.BluRay.x265-AAA"),
            keys("Some.Film.2023.1080p.WEB.H264-BBB")
        );
        // A season pack is its own target, not the episodes'.
        let pack = keys("Show.S03.1080p.WEB.H264-GRP");
        assert_eq!(pack.len(), 1);
        assert_ne!(pack, keys("Show.S03E01.1080p.WEB.H264-GRP"));
        // A daily keys on its date.
        assert_ne!(
            keys("The.Daily.Show.2026.07.21.1080p.WEB.h264-A"),
            keys("The.Daily.Show.2026.07.22.1080p.WEB.h264-A")
        );
    }

    #[test]
    fn the_counter_counts_distinct_releases_and_success_clears() {
        let mut st = GiveupState::default();
        let k = keys("Show.S01E05.1080p.WEB.H264-AAA");
        assert_eq!(
            st.record_failure(&k, "Show.S01E05.1080p.WEB.H264-AAA", 100),
            1
        );
        // The same dead release retried is one failure, not two.
        assert_eq!(
            st.record_failure(&k, "Show.S01E05.1080p.WEB.H264-AAA", 200),
            1
        );
        assert_eq!(
            st.record_failure(&k, "Show.S01E05.720p.HDTV.x264-BBB", 300),
            2
        );
        let p = parse_release("Show.S01E05.480p.x264-CCC");
        assert!(!st.tripped(&p, 3), "below threshold");
        assert!(st.tripped(&p, 2), "at threshold");
        assert!(!st.tripped(&p, 0), "0 = off, never tripped");
        // A completed download settles it.
        st.record_success(&k);
        assert!(!st.tripped(&p, 2));
    }

    #[test]
    fn the_action_latch_fires_once_until_a_success_rearms_it() {
        let mut st = GiveupState::default();
        let k = keys("Film.2020.1080p.WEB-GRP");
        st.record_failure(&k, "Film.2020.1080p.WEB-GRP", 100);
        assert!(st.latch_action(&k), "first trip acts");
        assert!(
            !st.latch_action(&k),
            "second failure of a tripped target does not"
        );
        // Latched counts as given up even if the threshold is later raised
        // above the recorded count - the unmonitor already happened.
        assert!(st.tripped(&parse_release("Film.2020.720p.WEB-X"), 50));
        st.record_success(&k);
        st.record_failure(&k, "Film.2020.1080p.WEB-GRP", 200);
        assert!(st.latch_action(&k), "a success re-arms the breaker");
    }

    #[test]
    fn the_status_list_names_targets_and_puts_the_given_up_ones_first() {
        let mut st = GiveupState::default();
        let ep = keys("Show.S01E05.1080p.WEB.H264-AAA");
        st.record_failure(&ep, "Show.S01E05.1080p.WEB.H264-AAA", 100);
        st.record_failure(&ep, "Show.S01E05.720p.HDTV.x264-BBB", 200);
        let film = keys("Some.Film.2023.1080p.WEB-GRP");
        st.record_failure(&film, "Some.Film.2023.1080p.WEB-GRP", 300);

        let rows = st.status_rows(2);
        assert_eq!(rows.len(), 2);
        // The tripped episode leads even though the film failed later.
        assert_eq!(rows[0]["label"], "Show S01E05");
        assert_eq!(rows[0]["stems"], 2);
        assert_eq!(rows[0]["tripped"], true);
        assert_eq!(rows[0]["actioned"], false);
        assert_eq!(rows[0]["last_stem"], "Show.S01E05.720p.HDTV.x264-BBB");
        assert_eq!(rows[0]["last_unix"], 200);
        assert_eq!(rows[1]["label"], "Some Film (2023)");
        assert_eq!(rows[1]["tripped"], false, "one failure, threshold 2");

        // Off = nothing is given up, and the latch is what keeps a
        // target tripped once the *arr was actually told.
        assert!(st.status_rows(0).iter().all(|r| r["tripped"] == false));
        st.latch_action(&film);
        assert_eq!(st.status_rows(9)[0]["label"], "Some Film (2023)");
        assert_eq!(st.status_rows(9)[0]["tripped"], true);
    }

    #[test]
    fn clearing_a_target_re_arms_it_exactly_like_a_success() {
        let mut st = GiveupState::default();
        let k = keys("Show.S02E01.1080p.WEB-GRP");
        st.record_failure(&k, "Show.S02E01.1080p.WEB-GRP", 100);
        st.latch_action(&k);
        let p = parse_release("Show.S02E01.720p.WEB-X");
        assert!(st.tripped(&p, 5));

        assert!(st.clear_target(&k[0]), "there was something to clear");
        assert!(!st.tripped(&p, 1), "counters and latch both gone");
        assert!(st.status_rows(1).is_empty());
        // Re-armed: the next storm may act again.
        st.record_failure(&k, "Show.S02E01.1080p.WEB-GRP", 200);
        assert!(st.latch_action(&k));
        // Clearing something that was never counted is a no-op.
        assert!(!st.clear_target("t:nothing here:s01e01"));
    }

    #[test]
    fn target_labels_read_as_the_thing_that_was_given_up() {
        assert_eq!(target_label("t:some show:s01e05"), "Some Show S01E05");
        assert_eq!(target_label("t:some show:s03"), "Some Show S03");
        assert_eq!(
            target_label("t:the daily show:d20260721"),
            "The Daily Show 2026-07-21"
        );
        assert_eq!(target_label("m:the matrix:1999"), "The Matrix (1999)");
        assert_eq!(target_label("m:untitled"), "Untitled");
        // Nothing recognisable: show the key rather than guess.
        assert_eq!(target_label("weird"), "weird");
        assert_eq!(target_label(""), "");
    }

    #[test]
    fn stale_evidence_expires() {
        let mut st = GiveupState::default();
        let k = keys("Old.Film.2019.1080p.WEB-GRP");
        st.record_failure(&k, "a", 0);
        // 46 days later the old entry is gone; the new failure starts over.
        let later = 46 * 24 * 3600;
        assert_eq!(st.record_failure(&k, "b", later), 1);
    }

    #[test]
    fn unparseable_names_count_nothing() {
        assert!(keys("d41d8cd98f00b204e9800998ecf8427e").is_empty());
        let mut st = GiveupState::default();
        assert_eq!(st.record_failure(&[], "whatever", 0), 0);
    }

    // -- the *arr client, against a real socket ---------------------------
    // Same rationale as notify.rs's capture_one: the thing worth pinning
    // is the bytes an *arr actually receives, and above all the ORDER -
    // unmonitor must land before the blocklisting queue delete.

    /// Serve canned responses; record "METHOD path" + body per request,
    /// in arrival order. Connection: close so ureq re-dials per request
    /// and the accept loop stays trivially sequential.
    fn arr_mock(
        routes: Vec<(&'static str, String)>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { return };
                sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break raw.len(),
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                    if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let want: usize = head
                    .to_ascii_lowercase()
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                while raw.len() < head_end + want {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let line = head.lines().next().unwrap_or_default();
                let (method, rest) = line.split_once(' ').unwrap_or_default();
                let path = rest.split(' ').next().unwrap_or_default();
                let body = String::from_utf8_lossy(&raw[head_end..]).to_string();
                log.lock().unwrap().push(format!("{method} {path} {body}"));
                let reply = routes
                    .iter()
                    .find(|(prefix, _)| path.starts_with(prefix))
                    .map(|(_, b)| b.clone())
                    .unwrap_or_else(|| "{}".into());
                let _ = sock.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                );
                let _ = sock.flush();
            }
        });
        (url, seen)
    }

    fn inst(kind: &str, url: String) -> ArrInstance {
        ArrInstance {
            name: format!("test-{kind}"),
            kind: kind.into(),
            url,
            apikey: "k".into(),
            enabled: true,
        }
    }

    /// A history page proving this instance grabbed the download - the
    /// ownership evidence step 0 requires before anything destructive.
    fn owns() -> (&'static str, String) {
        (
            "/api/v3/history?",
            json!({"records": [{"eventType": "grabbed", "downloadId": "NZO"}]}).to_string(),
        )
    }

    #[test]
    fn sonarr_unmonitors_before_it_blocklists() {
        let (url, seen) = arr_mock(vec![
            owns(),
            (
                "/api/v3/queue?",
                json!({"records": [
                    {"id": 5, "episodeId": 88, "downloadId": "NZO_X", "title": "t"},
                    {"id": 6, "episodeId": 89, "downloadId": "nzo_x", "title": "t"},
                    {"id": 7, "episodeId": 90, "downloadId": "other", "title": "t"},
                ]})
                .to_string(),
            ),
        ]);
        let out = arr_give_up(&inst("sonarr", url), "nzo_x", "Show.S01E01E02.WEB", &wanted)
            .unwrap()
            .expect("owner acts");
        assert!(out.contains("2 episode(s)"), "{out}");
        let seen = seen.lock().unwrap();
        let monitor = seen
            .iter()
            .position(|r| r.starts_with("PUT /api/v3/episode/monitor"))
            .expect("unmonitor call");
        assert!(
            seen[monitor].contains(r#""monitored":false"#)
                && seen[monitor].contains("88")
                && seen[monitor].contains("89")
                && !seen[monitor].contains("90"),
            "{}",
            seen[monitor]
        );
        let deletes: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|(_, r)| r.starts_with("DELETE /api/v3/queue/"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(deletes.len(), 2, "{seen:?}");
        // THE ordering this feature exists for.
        assert!(
            deletes.iter().all(|d| *d > monitor),
            "unmonitor must precede the blocklisting delete: {seen:?}"
        );
        assert!(
            seen[deletes[0]].contains("removeFromClient=false&blocklist=true&skipRedownload=true"),
            "{}",
            seen[deletes[0]]
        );
    }

    /// Codex sweep 2, 3 Aug M3, the wire half: a target reset while the
    /// *arr round-trips are in flight must leave the *arr untouched.
    /// The check has to sit immediately before the unmonitor, not at
    /// the top of the call - everything before it is GETs against an
    /// *arr that may be slow, which is the whole window the user gets
    /// to press "Try again" in.
    #[test]
    fn a_target_reset_mid_call_never_reaches_the_destructive_step() {
        let (url, seen) = arr_mock(vec![
            owns(),
            (
                "/api/v3/queue?",
                json!({"records": [
                    {"id": 5, "episodeId": 88, "downloadId": "nzo_r", "title": "t"},
                ]})
                .to_string(),
            ),
        ]);
        // The user got there first. `still_wanted` is only ever asked
        // at the destructive checkpoints, so the two GETs below landing
        // on the mock is itself the proof that the reads ran first and
        // the check sits after them.
        let reset = || false;
        let out = arr_give_up(&inst("sonarr", url), "nzo_r", "Show.S01E01.WEB", &reset).unwrap();
        assert!(
            out.is_none(),
            "a stood-down give-up reports nothing to retry, got {out:?}"
        );
        let seen = seen.lock().unwrap();
        assert!(
            seen.iter().all(|r| r.starts_with("GET ")),
            "nothing but reads may reach the *arr: {seen:?}"
        );
    }

    #[test]
    fn radarr_unmonitors_the_movie_then_drops_the_record() {
        let (url, seen) = arr_mock(vec![
            owns(),
            (
                "/api/v3/queue?",
                json!({"records": [
                    {"id": 9, "movieId": 7, "downloadId": "nzo_m", "title": "t"},
                ]})
                .to_string(),
            ),
            (
                "/api/v3/movie/7",
                json!({"id": 7, "title": "Film", "monitored": true}).to_string(),
            ),
        ]);
        arr_give_up(
            &inst("radarr", url),
            "NZO_M",
            "Film.2020.1080p.WEB",
            &wanted,
        )
        .unwrap()
        .expect("owner acts");
        let seen = seen.lock().unwrap();
        let put = seen
            .iter()
            .position(|r| r.starts_with("PUT /api/v3/movie/7"))
            .expect("movie update");
        assert!(seen[put].contains(r#""monitored":false"#), "{}", seen[put]);
        let del = seen
            .iter()
            .position(|r| r.starts_with("DELETE /api/v3/queue/9?"))
            .expect("queue delete");
        assert!(del > put, "unmonitor first: {seen:?}");
    }

    #[test]
    fn a_swept_queue_still_gets_unmonitored_via_parse() {
        // The *arr's poll won the race and the queue record is gone -
        // history still proves the grab, so the fallback resolves the
        // target by name and unmonitors it anyway; no queue record means
        // nothing to delete.
        let (url, seen) = arr_mock(vec![
            owns(),
            ("/api/v3/queue?", json!({"records": []}).to_string()),
            (
                "/api/v3/parse?",
                json!({"episodes": [{"id": 42}]}).to_string(),
            ),
        ]);
        arr_give_up(&inst("sonarr", url), "nzo_g", "Show.S04E04.WEB", &wanted)
            .unwrap()
            .expect("owner acts");
        let seen = seen.lock().unwrap();
        assert!(
            seen.iter()
                .any(|r| r.starts_with("PUT /api/v3/episode/monitor") && r.contains("42")),
            "{seen:?}"
        );
        assert!(
            !seen.iter().any(|r| r.starts_with("DELETE")),
            "nothing to delete: {seen:?}"
        );
    }

    #[test]
    fn a_non_owner_is_left_entirely_alone() {
        // No history record for our downloadId = this instance never
        // sent the grab. Even though its parser would recognise the
        // title (the parse route is armed below), NOTHING may be
        // touched - this is the two-Sonarrs-one-show case.
        let (url, seen) = arr_mock(vec![
            ("/api/v3/history?", json!({"records": []}).to_string()),
            (
                "/api/v3/queue?",
                json!({"records": [
                    {"id": 3, "episodeId": 77, "downloadId": "nzo_q", "title": "t"},
                ]})
                .to_string(),
            ),
            (
                "/api/v3/parse?",
                json!({"episodes": [{"id": 77}]}).to_string(),
            ),
        ]);
        let out = arr_give_up(&inst("sonarr", url), "nzo_q", "Show.S04E04.WEB", &wanted).unwrap();
        assert!(out.is_none(), "non-owner must not act: {out:?}");
        let seen = seen.lock().unwrap();
        assert!(
            seen.iter()
                .all(|r| !r.starts_with("PUT") && !r.starts_with("DELETE")),
            "non-owner mutated something: {seen:?}"
        );
    }

    #[test]
    fn an_owner_whose_target_vanished_reports_not_found() {
        let (url, _seen) = arr_mock(vec![
            owns(),
            ("/api/v3/queue?", json!({"records": []}).to_string()),
            ("/api/v3/parse?", "{}".to_string()),
        ]);
        assert!(
            arr_give_up(&inst("radarr", url), "nzo_z", "Show.S01E01.WEB", &wanted)
                .unwrap_err()
                .contains("target not found")
        );
    }

    #[test]
    fn a_remote_failure_releases_the_latch_for_retry() {
        // State-side contract behind the daemon's "no instance acted
        // and something errored" path: clear_action re-arms the *arr
        // call while the local trip (count >= threshold) stands.
        let mut st = GiveupState::default();
        let k = keys("Show.S01E05.1080p.WEB.H264-AAA");
        st.record_failure(&k, "a", 100);
        st.record_failure(&k, "b", 200);
        assert!(st.latch_action(&k));
        st.clear_action(&st.action_token(&k));
        assert!(
            st.tripped(&parse_release("Show.S01E05.720p.WEB-X"), 2),
            "still locally given up by count"
        );
        assert!(st.latch_action(&k), "released latch fires again");
    }
}

//! Where a job came from: the spool-stem sanitiser that names its file,
//! and the user-agent parsing that records which client asked.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

/// A release stem reduced to something safe and recognisable as part of a
/// spool filename. Deliberately strict: this string reaches the
/// filesystem, so anything that is not plainly a name character becomes a
/// dash, and the result is length-capped so a long release name plus the
/// job id cannot approach a path limit.
pub(super) fn safe_spool_stem(stem: &str) -> String {
    let mut out = String::with_capacity(48);
    for c in stem.chars() {
        if out.chars().count() >= 60 {
            break;
        }
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    // Never a leading dot (hidden file) and never an empty stem.
    let out = out.trim_matches(['-', '.'].as_slice()).to_string();
    if out.is_empty() { "job".into() } else { out }
}

/// Which caller an API-added job came from. The *arrs and the dashboard
/// both post to addfile, so the distinguishing evidence is the SAB API
/// key parameters the *arrs send and the browser does not.
pub(super) fn origin_of(params: &std::collections::HashMap<String, String>) -> &'static str {
    if params.contains_key("nzbname") || params.get("mode").map(String::as_str) == Some("addurl") {
        return "arr";
    }
    "dashboard"
}

/// Was this job grabbed by an *arr (or an *arr-shaped client)?
///
/// The recorded origin is either the bare `arr` fallback or the
/// `arr:<client>` shape `api_origin` writes, so both spellings answer
/// yes. One predicate because two callers now turn on it and they must
/// agree: the give-up breaker (§96.3, which acts on the *arr) and
/// `storage_deleted` (§96 item 2, which deliberately does NOT).
pub(super) fn is_arr_origin(origin: &str) -> bool {
    origin == "arr" || origin.starts_with("arr:")
}

/// Name the client behind an API call from its User-Agent, or `None`.
///
/// Every automation that adds jobs leads its UA with a standard product
/// token - `Sonarr/4.0.19.2979 (macos 10.0)`, `Radarr/6.3.0.10514
/// (macos 10.0)`, `nzb360/...` - so taking the substring before the
/// first `/` or space names clients we have never heard of, for free. A
/// hardcoded list of known names would only ever name the ones we
/// thought of, so the list stays out of the classifier and is used for
/// display only.
///
/// The UA is attacker-controlled, and the name is persisted into
/// `queue.json` and rendered in the drawer. Sanitising to `[a-z0-9-]`
/// with a 24-char cap right here, at the point of classification, is the
/// whole defence - nothing downstream re-checks it.
///
/// `None` for a browser (any `mozilla` token, which covers our own
/// dashboard's upload) and for a UA that leaves nothing usable. Callers
/// fall back to the parameter heuristic, so behaviour is unchanged for
/// everyone who does not identify themselves.
pub(super) fn api_client(user_agent: &str) -> Option<String> {
    let token: String = user_agent
        .trim_start()
        .split(['/', ' '])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(24)
        .collect();
    if token.is_empty() || token == "mozilla" {
        return None;
    }
    Some(token)
}

/// Origin to record for an API-added job: `arr:<client>` when the caller
/// named itself, else `fallback`.
///
/// The `prefix:detail` shape is the one `rss:<feed-url>` already uses, so
/// nothing needs a new `Job` field or a `queue.json` migration: records
/// written before this keep plain `arr` and still render.
pub(super) fn api_origin(user_agent: &str, fallback: &str) -> String {
    match api_client(user_agent) {
        Some(client) => format!("arr:{client}"),
        None => fallback.to_string(),
    }
}

#[cfg(test)]
#[path = "origin_tests.rs"]
mod origin_tests;

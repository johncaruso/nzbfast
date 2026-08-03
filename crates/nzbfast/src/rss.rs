//! M14k: RSS/newznab feed automation - poll feeds, filter with
//! NZBGet-style rules, auto-enqueue accepted items.
//!
//! Feed config (`--feeds feeds.json`):
//! ```json
//! [{
//!   "url": "https://indexer/rss?apikey=...",
//!   "interval_secs": 900,
//!   "category": "tv",
//!   "rules": [
//!     "Require: size>200M",
//!     "Reject: *480p*",
//!     "Accept: *1080p*",
//!     "Accept: *2160p*"
//!   ]
//! }]
//! ```
//! Rule semantics (the useful subset of NZBGet's language):
//! - `Require:` - every Require must match or the item is skipped.
//! - `Reject:`  - any match skips the item.
//! - `Accept:`  - if any Accept rules exist, the item must match one.
//! - Patterns are case-insensitive wildcards (`*`, `?`) against the
//!   title; a pattern without wildcards matches as a substring.
//! - `size>N` / `size<N` (K/M/G/T suffixes) compare the item's size.
//! Duplicate detection (M14f) then holds anything already queued or done.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeedConfig {
    pub url: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub rules: Vec<String>,
}

fn default_interval() -> u64 {
    900
}

/// What the last poll of one feed actually did.
///
/// The poller used to fold every fetch and parse failure into an empty
/// item list, so a revoked apikey, a typo'd host, a 403 and an indexer
/// that had simply gone away all looked identical to a feed with nothing
/// new to say: silent, forever, with the settings row still reading like
/// a healthy feed. This is the difference, kept per feed url and shipped
/// beside the feed in `get_config`.
///
/// Never build one of these by hand from a raw fetch error - use
/// [`FeedHealth::failed`], which strips the url. A feed url essentially
/// always carries the indexer's `apikey=`, and the fetch layer's errors
/// lead with the url they were given.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FeedHealth {
    /// Unix seconds when the last poll attempt finished. 0 = never
    /// polled (a feed added a moment ago, or a daemon just started).
    pub last_poll: i64,
    /// The last failure, with the url taken out. Empty when the last
    /// poll succeeded.
    pub last_error: String,
    /// Items the last SUCCESSFUL parse produced, before the rules ran.
    /// A feed that fetches fine and yields nothing is a rules or a
    /// retention question, not a connection one, and the two must not
    /// read the same on the row.
    pub items_seen: usize,
}

impl FeedHealth {
    /// A poll that fetched and parsed.
    pub fn ok(now: i64, items_seen: usize) -> FeedHealth {
        FeedHealth {
            last_poll: now,
            last_error: String::new(),
            items_seen,
        }
    }

    /// A poll that failed, with `redact` applied to the message. The
    /// caller passes the daemon's url redactor rather than this module
    /// growing its own copy of it.
    pub fn failed(now: i64, err: &str, redact: impl Fn(&str) -> String) -> FeedHealth {
        let msg = redact(err);
        let msg = msg.trim();
        FeedHealth {
            last_poll: now,
            // Bounded: an indexer that answers a 500 with a whole HTML
            // error page would otherwise put all of it in get_config
            // and in the settings row.
            last_error: msg.chars().take(200).collect(),
            items_seen: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct FeedItem {
    pub title: String,
    /// NZB download URL (enclosure url, else <link>).
    pub link: String,
    pub size: u64,
    /// Dedupe identity: <guid>, else the link.
    pub guid: String,
}

/// Case-insensitive `*`/`?` wildcard match (iterative, with backtracking).
pub fn glob_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = s.to_ascii_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// One pattern term against an item: either a size comparison or a
/// title wildcard/substring.
fn term_matches(term: &str, item: &FeedItem) -> bool {
    let term = term.trim();
    for (op, gt) in [(">", true), ("<", false)] {
        if let Some(rest) = term
            .strip_prefix("size")
            .and_then(|r| r.trim_start().strip_prefix(op))
        {
            if let Some(n) = crate::serve::parse_size(rest.trim()) {
                return if gt { item.size > n } else { item.size < n };
            }
            return false;
        }
    }
    if term.contains('*') || term.contains('?') {
        glob_match(term, &item.title)
    } else {
        item.title
            .to_ascii_lowercase()
            .contains(&term.to_ascii_lowercase())
    }
}

/// Apply a feed's rule list; true = download this item.
pub fn rules_accept(rules: &[String], item: &FeedItem) -> bool {
    let mut has_accept = false;
    let mut accepted = false;
    for rule in rules {
        let Some((kind, expr)) = rule.split_once(':') else {
            continue;
        };
        let hit = term_matches(expr, item);
        match kind.trim().to_ascii_lowercase().as_str() {
            "require" => {
                if !hit {
                    return false;
                }
            }
            "reject" => {
                if hit {
                    return false;
                }
            }
            "accept" => {
                has_accept = true;
                accepted |= hit;
            }
            _ => {}
        }
    }
    !has_accept || accepted
}

pub(crate) fn tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = xml.find(&format!("<{tag}"))?;
    let start = xml[open..].find('>')? + open + 1;
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

pub(crate) fn unescape(s: &str) -> String {
    // &amp; MUST be decoded LAST: doing it first turns `&amp;lt;` (an escaped
    // literal "&lt;") into `&lt;`, which the later pass then wrongly decodes
    // to "<", corrupting the title/link (and its dedupe identity).
    s.replace("<![CDATA[", "")
        .replace("]]>", "")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

pub(crate) fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!("{name}=\"");
    let start = tag.find(&pat)? + pat.len();
    let end = tag[start..].find('"')? + start;
    Some(&tag[start..end])
}

/// A body that came back HTTP 200 and is not a feed at all.
#[derive(Debug, Clone)]
pub struct FeedParseError(pub String);

impl std::fmt::Display for FeedParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// [`parse_feed`], but refusing a body that is not a feed (Codex sweep
/// 2, 3 Aug ML1).
///
/// The tolerant parser answers an empty list for anything it does not
/// recognise, which is the RIGHT answer for junk INSIDE a feed and the
/// wrong one for a body that is not a feed at all. An indexer whose
/// apikey was revoked serves an HTTP 200 login page, and every caller
/// then recorded "healthy, zero items" - the feed's settings row went
/// on saying it was fine while it silently stopped grabbing anything.
///
/// The check is deliberately shallow: a recognizable feed root and
/// nothing more. A genuinely empty feed is valid and must stay healthy,
/// and the parser's tolerance for namespace prefixes, junk elements and
/// half-formed items is load-bearing - feeds in the wild are messy.
pub fn parse_feed_checked(xml: &str) -> Result<Vec<FeedItem>, FeedParseError> {
    // Byte-limited scan: only the document's opening needs looking at,
    // and a multi-megabyte body of HTML must not be lowercased whole.
    let head: String = xml.chars().take(4096).collect::<String>().to_lowercase();
    let looks_like_a_feed = ["<rss", "<feed", "<rdf:rdf", "<channel"]
        .iter()
        .any(|root| head.contains(root));
    if !looks_like_a_feed {
        // Name what it looks like instead - "not a feed" alone sends a
        // user hunting in the wrong place, and a login page is by far
        // the most common answer here.
        let what = if head.contains("<html") || head.contains("<!doctype html") {
            "the server answered with a web page, not a feed - \
             the url is probably wrong, or the apikey has been revoked \
             and this is a login page"
        } else if head.trim().is_empty() {
            "the server answered with an empty body"
        } else {
            "the server's answer is not an RSS or Atom feed"
        };
        return Err(FeedParseError(what.into()));
    }
    Ok(parse_feed(xml))
}

/// Minimal RSS 2.0 parser: <item> blocks with title, enclosure/link,
/// size (enclosure length, else newznab size attr), guid. Tolerant of
/// namespaces and junk - feeds in the wild are messy.
///
/// Callers that RECORD FEED HEALTH want [`parse_feed_checked`]: this
/// one cannot tell an empty feed from a body that is not a feed.
pub fn parse_feed(xml: &str) -> Vec<FeedItem> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find("<item") {
        let Some(close) = rest[open..].find("</item>") else {
            break;
        };
        let item = &rest[open..open + close];
        let title = tag_text(item, "title").map(unescape).unwrap_or_default();
        let enclosure = item.find("<enclosure").map(|p| {
            let end = item[p..].find('>').map(|e| p + e).unwrap_or(item.len());
            &item[p..end]
        });
        let link = enclosure
            .and_then(|e| attr(e, "url"))
            .map(str::to_string)
            .or_else(|| tag_text(item, "link").map(str::to_string))
            .map(|l| unescape(&l))
            .unwrap_or_default();
        let size = enclosure
            .and_then(|e| attr(e, "length"))
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                // newznab: <newznab:attr name="size" value="123"/>
                item.split("<newznab:attr").skip(1).find_map(|a| {
                    let a = &a[..a.find('>').unwrap_or(a.len())];
                    (attr(a, "name") == Some("size"))
                        .then(|| attr(a, "value")?.parse().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        let guid = tag_text(item, "guid")
            .map(unescape)
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| link.clone());
        if !title.is_empty() && !link.is_empty() {
            out.push(FeedItem {
                title,
                link,
                size,
                guid,
            });
        }
        rest = &rest[open + close + 7..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(title: &str, size: u64) -> FeedItem {
        FeedItem {
            title: title.into(),
            link: "http://x/nzb".into(),
            size,
            guid: "g".into(),
        }
    }

    #[test]
    fn globs() {
        assert!(glob_match("*1080p*", "Show.S01E02.1080p.WEB"));
        assert!(!glob_match("*1080p*", "Show.S01E02.720p.WEB"));
        assert!(glob_match("show*web", "Show.S01E02.1080p.WEB"));
        assert!(glob_match("s??e02", "S01E02"));
        assert!(!glob_match("s??e02", "S1E02"));
    }

    #[test]
    fn rule_semantics() {
        let rules = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Accept-list: must match one.
        let r = rules(&["Accept: *1080p*", "Accept: *2160p*"]);
        assert!(rules_accept(&r, &item("A.2160p.REMUX", 0)));
        assert!(!rules_accept(&r, &item("A.720p", 0)));
        // Reject beats accept.
        let r = rules(&["Reject: *HDCAM*", "Accept: *1080p*"]);
        assert!(!rules_accept(&r, &item("A.1080p.HDCAM", 0)));
        // Require size window.
        let r = rules(&["Require: size>700M", "Require: size<10G"]);
        assert!(rules_accept(&r, &item("A", 5_000_000_000)));
        assert!(!rules_accept(&r, &item("A", 100_000_000)));
        assert!(!rules_accept(&r, &item("A", 50_000_000_000)));
        // No rules → accept everything.
        assert!(rules_accept(&[], &item("anything", 0)));
        // Substring term (no wildcard).
        let r = rules(&["Reject: hdcam"]);
        assert!(!rules_accept(&r, &item("A.HDCAM.x264", 0)));
    }

    #[test]
    fn parses_rss() {
        let xml = r#"<?xml version="1.0"?><rss><channel>
<item><title>Show.S01E02.1080p.WEB</title>
<guid isPermaLink="false">abc-123</guid>
<enclosure url="https://idx/get/abc?apikey=k" length="3221225472" type="application/x-nzb"/>
<newznab:attr name="category" value="5040"/>
</item>
<item><title>Movie &amp; More.2026.720p</title>
<link>https://idx/get/def</link>
<newznab:attr name="size" value="1500000000"/>
</item>
</channel></rss>"#;
        let items = parse_feed(xml);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Show.S01E02.1080p.WEB");
        assert_eq!(items[0].link, "https://idx/get/abc?apikey=k");
        assert_eq!(items[0].size, 3_221_225_472);
        assert_eq!(items[0].guid, "abc-123");
        assert_eq!(items[1].title, "Movie & More.2026.720p");
        assert_eq!(items[1].size, 1_500_000_000);
        assert_eq!(items[1].guid, "https://idx/get/def");
    }

    /// Codex sweep 2, 3 Aug ML1: an HTTP 200 that is not a feed used to
    /// parse to an empty list and be recorded as "healthy, no items",
    /// so a revoked apikey's login page looked exactly like a quiet
    /// feed - for as long as the user left it there.
    #[test]
    fn a_body_that_is_not_a_feed_is_a_failure_not_an_empty_feed() {
        let login = "<!DOCTYPE html><html><head><title>Sign in</title></head>\
                     <body><form><input name=\"user\"></form></body></html>";
        let e = parse_feed_checked(login).expect_err("a login page is not a feed");
        assert!(e.to_string().contains("web page"), "{e}");
        // Nothing of the body itself is echoed - it is attacker-shaped
        // text on its way to the settings row.
        assert!(!e.to_string().contains("Sign in"), "{e}");

        assert!(
            parse_feed_checked("").is_err(),
            "an empty body is not a feed"
        );
        assert!(
            parse_feed_checked("{\"error\":\"bad apikey\"}").is_err(),
            "a JSON error body is not a feed"
        );

        // ...and the tolerance that matters is untouched: a genuinely
        // EMPTY feed is valid and stays healthy, junk inside a feed is
        // still skipped rather than failing the whole poll, and Atom
        // and RDF roots are feeds too.
        let empty = "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>\
                     <title>Nothing new</title></channel></rss>";
        assert_eq!(parse_feed_checked(empty).unwrap().len(), 0);
        let junky = "<?xml version=\"1.0\"?><rss><channel>\
                     <item><title>no link at all</title></item>\
                     <item><title>Good.Release</title><link>https://x/1</link></item>\
                     </channel></rss>";
        assert_eq!(parse_feed_checked(junky).unwrap().len(), 1);
        assert!(parse_feed_checked("<feed xmlns=\"http://www.w3.org/2005/Atom\"/>").is_ok());
        assert!(parse_feed_checked("<rdf:RDF><channel/></rdf:RDF>").is_ok());
    }

    /// §G. The recorded failure crosses to the browser and sits on the
    /// settings row, so it goes through the url redactor on the way in -
    /// a feed url essentially always carries the indexer's apikey, and
    /// the fetch layer's errors lead with the url they were handed.
    #[test]
    fn a_recorded_feed_failure_carries_no_apikey() {
        let raw = "https://idx.example/rss?apikey=DEADBEEF&t=tv: status code 403";
        let h = FeedHealth::failed(99, raw, crate::serve::redact_url_creds);
        assert!(!h.last_error.contains("DEADBEEF"), "{}", h.last_error);
        assert!(!h.last_error.contains("apikey"), "{}", h.last_error);
        // Still worth reading: the host and what went wrong survive.
        assert!(h.last_error.contains("idx.example"), "{}", h.last_error);
        assert!(h.last_error.contains("403"), "{}", h.last_error);
        assert_eq!(h.last_poll, 99);
        assert_eq!(h.items_seen, 0, "a failed poll saw nothing");
    }

    #[test]
    fn a_feed_error_cannot_grow_without_bound() {
        // An indexer answering a 500 with a whole HTML error page must
        // not put all of it in get_config and in the row.
        let h = FeedHealth::failed(1, &"x".repeat(5000), str::to_string);
        assert_eq!(h.last_error.chars().count(), 200);
    }

    #[test]
    fn a_feed_that_fetched_but_matched_nothing_is_not_an_error() {
        // The distinction the row is for: zero items with no error is a
        // rules or retention question; zero items WITH one is a broken
        // feed, and they used to look identical.
        let h = FeedHealth::ok(5, 0);
        assert!(h.last_error.is_empty());
        assert_eq!(h.items_seen, 0);
        assert_eq!(h.last_poll, 5);
    }
}

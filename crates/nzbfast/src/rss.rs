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
        item.title.to_ascii_lowercase().contains(&term.to_ascii_lowercase())
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

fn tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = xml.find(&format!("<{tag}"))?;
    let start = xml[open..].find('>')? + open + 1;
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

fn unescape(s: &str) -> String {
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

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!("{name}=\"");
    let start = tag.find(&pat)? + pat.len();
    let end = tag[start..].find('"')? + start;
    Some(&tag[start..end])
}

/// Minimal RSS 2.0 parser: <item> blocks with title, enclosure/link,
/// size (enclosure length, else newznab size attr), guid. Tolerant of
/// namespaces and junk - feeds in the wild are messy.
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
            out.push(FeedItem { title, link, size, guid });
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
}

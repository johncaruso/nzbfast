//! Differential fuzz of nzbkit::urlauth (`url_host` / `url_netloc`)
//! against the `url` crate - the parser ureq actually dials with.
//!
//! Why this exists (M12 follow-up): the daemon's origin-bound fetch
//! rules compare `url_netloc(origin_url)` against the netloc ureq hands
//! its resolver, which ureq builds from the `url` crate's parse
//! (`host_str():port_or_known_default()`). If the hand-rolled parser
//! drifts from that spelling, the origin comparison silently never
//! matches and every private target is refused - a "guard works!" that
//! has actually broken every LAN indexer. And in the port-blind
//! `url_host` direction, a divergence where OURS names the origin while
//! ureq dials somewhere else is the backslash-authority bug shape all
//! over again. The unit tests pin the known cases; this target covers
//! the class.
//!
//! Known, accepted divergences (each skipped below, matching the docs
//! on `url_netloc`): the `url` crate punycodes IDN hosts,
//! percent-decodes authorities, strips tabs/newlines/leading controls,
//! coerces numeric-tailed hosts to IPv4 (`0x7f.1` -> `127.0.0.1`),
//! canonicalizes IPv6 literals, and skips any extra slashes after the
//! scheme (`http:///x` reads its authority from `x`; ours sees an
//! empty one). In every one of those, ours answers
//! empty-or-different and the origin match FAILS - the safe direction,
//! a refusal, never a wave-through.

#![no_main]
use libfuzzer_sys::fuzz_target;
use nzbkit::urlauth::{url_host, url_netloc};

/// Is this host spelling one the WHATWG parser rewrites (so ours is
/// allowed to disagree - safe direction, see module docs)?
fn rewritten_host_shape(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[') {
        // IPv6: only a literal that is already in canonical spelling
        // (and not v4-embedded, whose serialization differs between
        // parsers) is expected to round-trip.
        let Some(inner) = inner.strip_suffix(']') else {
            return true;
        };
        return inner.contains('.')
            || inner
                .parse::<std::net::Ipv6Addr>()
                .map(|ip| ip.to_string() != inner)
                .unwrap_or(true);
    }
    // A canonical dotted-quad round-trips identically. Any OTHER host
    // whose last label leads with a digit is IPv4-coercion territory
    // ("0x7f.1", "1.2.3.4.5", trailing-zero forms) and gets rewritten
    // or refused by the WHATWG parser - whose ends-in-a-number check
    // also ignores ONE trailing dot ("7.0.0." -> 7.0.0.0), so strip it
    // before looking at the last label.
    let (trimmed, had_dot) = match host.strip_suffix('.') {
        Some(t) => (t, true),
        None => (host, false),
    };
    if !had_dot && host.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }
    trimmed
        .rsplit('.')
        .next()
        .and_then(|label| label.chars().next())
        .is_some_and(|c| c.is_ascii_digit())
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let host = url_host(s);
    let netloc = url_netloc(s);

    // Internal contract, on EVERY input: netloc is exactly host plus a
    // ':port' that parsed (or defaulted) to a u16, host never leaks an
    // authority terminator or userinfo, and both are lowercased.
    if host.is_empty() {
        assert!(
            netloc.is_empty(),
            "netloc without a host: {s:?} -> {netloc:?}"
        );
    } else {
        assert!(
            netloc.starts_with(&host),
            "netloc does not extend its host: {s:?} -> {host:?} / {netloc:?}"
        );
        let port = netloc[host.len()..]
            .strip_prefix(':')
            .unwrap_or_else(|| panic!("netloc without ':port': {s:?} -> {netloc:?}"));
        port.parse::<u16>()
            .unwrap_or_else(|_| panic!("non-u16 port: {s:?} -> {netloc:?}"));
        assert!(
            !host.contains(['/', '?', '#', '\\', '@']),
            "authority terminator or userinfo in host: {s:?} -> {host:?}"
        );
        assert_eq!(
            host,
            host.to_ascii_lowercase(),
            "host not lowercased: {s:?}"
        );
    }

    // Differential half. Ours only speaks strict-prefix http(s) URLs -
    // anything else answers empty by construction, which refuses every
    // private target (safe), so there is nothing to compare.
    let pfx8 = s.len() >= 8 && s.as_bytes()[..8].eq_ignore_ascii_case(b"https://");
    let pfx7 = s.len() >= 7 && s.as_bytes()[..7].eq_ignore_ascii_case(b"http://");
    if !(pfx7 || pfx8) {
        assert!(
            netloc.is_empty(),
            "authority from a non-http(s) URL: {s:?} -> {netloc:?}"
        );
        return;
    }
    let Ok(u) = url::Url::parse(s) else {
        // ureq refuses this URL outright (this is also where our
        // unparseable-port default lands), so the netloc is never
        // compared to anything.
        return;
    };
    // The authority as ours delimits it, for the skip checks: the
    // WHATWG parser rewrites percent-encoding, IDN, and embedded
    // controls, all in the refused-not-waved-through direction.
    let after = &s[if pfx8 { 8 } else { 7 }..];
    // WHATWG's special-authority-ignore-slashes state: extra '/' or
    // '\' after the scheme are skipped and the authority read from
    // whatever follows; ours reads an empty authority and refuses.
    if after.starts_with(['/', '\\']) {
        return;
    }
    let auth = after.split(['/', '?', '#', '\\']).next().unwrap_or("");
    if !auth.is_ascii()
        || auth.contains('%')
        || auth.bytes().any(|b| b <= 0x20 || b == 0x7f)
        || rewritten_host_shape(&host)
    {
        return;
    }
    // No known divergence applies: ours must now agree exactly with the
    // spelling ureq dials and hands its resolver. An empty answer here
    // is NOT acceptable - that is the every-LAN-indexer-refused drift.
    let their_host = u.host_str().unwrap_or("");
    let their_port = u.port_or_known_default().unwrap_or(0);
    assert_eq!(
        host, their_host,
        "url_host disagrees with the parser ureq dials with: {s:?}"
    );
    assert_eq!(
        netloc,
        format!("{their_host}:{their_port}"),
        "url_netloc disagrees with ureq's resolver spelling: {s:?}"
    );
});

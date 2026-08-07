//! Server-side URL fetches of user-supplied links: the SSRF guard and
//! the agents built on it, the NZB-vs-error body sniff, the failure-link
//! allowlist, and the regrab chain's inheritance rules.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// SSRF guard for server-side fetches of user/attacker-supplied URLs
/// (addurl, /watch, poster-from-URL).
///
/// Scope is deliberate: this is a SELF-HOSTED app whose normal job is to
/// talk to indexers on loopback and the LAN (Prowlarr/nzbhydra, or
/// nzbfast's own newznab endpoint), and to be reached over Tailscale
/// (CGNAT 100.64/10). Blocking those would break the common single-box /
/// single-LAN topology. So loopback, RFC1918 and CGNAT are ALLOWED.
///
/// What is refused is the class that is never a legitimate fetch target
/// and is the high-value SSRF prize: the cloud-metadata endpoint and the
/// rest of link-local (169.254/16, fe80::/10), plus unspecified/broadcast.
/// That kills instance-credential theft on AWS/GCP/Azure without breaking
/// local indexers.
pub(crate) fn is_forbidden_fetch_ip(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    match ip {
        IpAddr::V4(a) => {
            a.is_link_local()   // 169.254/16, incl. 169.254.169.254 metadata
                || a.is_unspecified() // 0.0.0.0
                || a.is_broadcast()
                || a.octets()[0] == 0 // 0.0.0.0/8 "this network"
                // Alibaba Cloud metadata lives at 100.100.100.200, which is
                // INSIDE the 100.64/10 CGNAT range we otherwise allow for
                // Tailscale - block just that host.
                || a == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_forbidden_fetch_ip(IpAddr::V4(v4));
            }
            let s = a.segments();
            a.is_unspecified()
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                // AWS IPv6 IMDS is fd00:ec2::/32, inside the fc00::/7 ULA
                // range we otherwise allow for v6 LANs - block that block.
                || (s[0] == 0xfd00 && s[1] == 0x0ec2)
        }
    }
}

/// ureq resolver that refuses to hand back any internal address. Because
/// ureq connects to exactly the SocketAddrs returned here (no second
/// lookup), this closes the DNS-rebinding window AND re-checks on every
/// redirect hop, since each hop resolves through it.
pub(super) struct SsrfGuardResolver;
impl ureq::Resolver for SsrfGuardResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address",
            ));
        }
        if addrs.iter().any(|a| is_forbidden_fetch_ip(a.ip())) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to fetch an internal address ({netloc})"),
            ));
        }
        Ok(addrs)
    }
}

/// An agent whose every connection (initial + each redirect) is filtered
/// through the SSRF guard. Use for ANY fetch of a user/attacker-supplied
/// URL. `redirects` is capped by the caller.
pub(crate) fn ssrf_safe_agent(redirects: u32, timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .resolver(SsrfGuardResolver)
        .redirects(redirects)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
}

/// The ONE outbound HTTP agent the wall enricher shares (plan §4 C2).
///
/// In ureq the Agent *is* the connection pool, so `ureq::get(...)` -
/// which builds a throwaway agent per call - reconnects and re-does the
/// TLS handshake for every single request. The enricher makes several
/// requests per title (search, entity, summary, art) and runs over
/// thousands of titles a scan, all to a handful of hosts, so it was
/// paying a full handshake where a pooled connection costs nothing.
///
/// One agent, kept for the process's life, and callers still set their
/// own per-request `.timeout()` - which is why a single shared agent can
/// serve a 10 s metadata lookup and a 120 s dataset download alike.
///
/// It carries the SSRF resolver for the same reason the NZB fetcher
/// does: these hosts are ours today, but user-supplied sources are the
/// stated direction for this code, and a pool that guards by default
/// cannot be forgotten later.
pub(crate) fn shared_enrich_agent() -> ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| ssrf_safe_agent(4, 30)).clone()
}

/// An NZB fetched by URL, plus what the indexer said about it in the
/// response headers.
pub struct Fetched {
    pub bytes: Vec<u8>,
    /// `X-DNZB-Failure`: where to report this download failing, and where
    /// the indexer hands back a replacement NZB for the same title. See
    /// [`Daemon::report_failure`].
    pub failure_link: String,
    /// Host of the URL that was REQUESTED (not the last redirect hop):
    /// the only host `failure_link` may point back at. See
    /// [`Daemon::report_failure`].
    pub host: String,
    /// Was the REQUESTED url https? A failure link may not downgrade the
    /// scheme it was handed over. See [`failure_link_allowed`].
    pub https: bool,
    /// `X-DNZB-Category`, when the indexer sends one. Parsed, but never
    /// used to route a download: the category picks the output subfolder,
    /// the library flag and the move-completed destination, and those are
    /// the user's choice, not the responding server's. Kept (and
    /// asserted on) so the header parse stays covered if a future caller
    /// has a legitimate use for it.
    #[allow(dead_code)]
    pub category: String,
    /// Filename from the response's `Content-Disposition`, or empty.
    /// This is where indexers put the real release name - a grab
    /// proxied by Prowlarr with its per-indexer Redirect setting
    /// arrives as `addurl` with no `nzbname` and a download URL whose
    /// last path segment is the indexer's NZB id hash, so this header
    /// is the only place the human name exists (issue #26).
    pub filename: String,
}

/// The filename out of a `Content-Disposition` header, or None. Handles
/// the three shapes in the wild: `filename="quoted"`, a bare
/// `filename=token`, and RFC 5987 `filename*=UTF-8''percent-encoded`
/// (which wins over `filename` when both appear, per RFC 6266).
///
/// The value is attacker-influenced (it comes from whatever answered the
/// fetch), so any path components are shorn and an outsized value is
/// refused; the enqueue path re-sanitizes before anything touches the
/// filesystem, same as `nzbname`.
pub(crate) fn content_disposition_filename(hdr: &str) -> Option<String> {
    let mut plain: Option<String> = None;
    let mut ext: Option<String> = None;
    for part in split_disposition_params(hdr) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if key == "filename*" {
            // ext-value = charset "'" [language] "'" value-chars. Only
            // UTF-8 arrives in practice; a mislabelled charset still
            // decodes lossily rather than dropping the name.
            if let Some((_, data)) = v.rsplit_once('\'') {
                ext = Some(percent_decode(data));
            }
        } else if key == "filename" {
            let v = match v.strip_prefix('"') {
                Some(rest) => rest.split('"').next().unwrap_or(""),
                None => v,
            };
            plain = Some(v.to_string());
        }
    }
    // filename* wins per RFC 6266, but only when it actually carried a
    // name: a malformed or empty ext-value must not suppress a perfectly
    // valid plain `filename` beside it.
    let name = ext.filter(|s| !s.trim().is_empty()).or(plain)?;
    let name = name.rsplit(['/', '\\']).next().unwrap_or("").trim();
    // Control characters out: percent-decoding happily produces CR/LF/
    // ESC, and while the filesystem paths re-sanitize downstream, the
    // raw string becomes the job's display name - which reaches logs
    // and would otherwise carry ANSI escapes or forged log lines from
    // whatever answered the fetch.
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    let name = name.trim();
    (!name.is_empty() && name.len() <= 255).then(|| name.to_string())
}

/// Split a Content-Disposition header into its `;`-separated params,
/// honouring quoted-string boundaries: `filename="Show; Part 2.nzb"`
/// is ONE parameter, and splitting it blind named the job `Show` -
/// wrong output folder, wrong duplicate identity. (Backslash escapes
/// inside the quoted string are not interpreted: no client emits them
/// in filenames, and a stray quote merely mis-splits back to the old
/// behaviour, never past the header.)
fn split_disposition_params(hdr: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0usize, false);
    for (i, b) in hdr.bytes().enumerate() {
        match b {
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                parts.push(&hdr[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&hdr[start..]);
    parts
}

/// Percent-decode only - NOT `urldecode`, whose `+` → space rule belongs
/// to form encoding and would corrupt a literal `+` in a filename.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 3 <= b.len()
            && let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The job name for a URL grab that carried no explicit name: the
/// fetched `Content-Disposition` filename when the server sent one
/// (that is the name SABnzbd shows for the same grab), else the URL's
/// last path segment shorn of query and fragment - the old fallback
/// kept the whole `?t=get&id=...` tail on API-style links.
pub(super) fn name_from_fetch(f: &Fetched, url: &str) -> Option<String> {
    if !f.filename.is_empty() {
        return Some(f.filename.clone());
    }
    let path = url.split(['?', '#']).next().unwrap_or("");
    let tail = path.rsplit('/').next().unwrap_or("").trim();
    (!tail.is_empty()).then(|| tail.to_string())
}

/// One `X-DNZB-*` header, trimmed, or empty.
pub(super) fn dnzb(resp: &ureq::Response, name: &str) -> String {
    resp.header(name).unwrap_or_default().trim().to_string()
}

/// The failure-report link out of the two spellings in the wild.
/// `X-DNZB-Failure` is what indexers actually send (it is the header
/// NZBGet's own FailureLink reads, via the `*DNZB:Failure` parameter);
/// `X-DNZB-FailureLink` is what the feature is usually CALLED, and a few
/// indexers send that name instead. The canonical one wins, and a header
/// present but blank counts as absent.
pub(super) fn pick_failure_link(canonical: &str, alias: &str) -> String {
    if canonical.is_empty() {
        alias.to_string()
    } else {
        canonical.to_string()
    }
}

/// The host of an http(s) URL, lowercased, without userinfo and without
/// the port - or empty when there isn't one. Deliberately port-blind: an
/// indexer that serves NZBs on :9117 and reports failures on :9118 is
/// still the same machine, and the check is about WHOSE server we call,
/// not which socket.
///
/// Hand-rolled because the daemon has no URL crate. It parses less than a
/// real one, and everything it cannot parse comes back empty, which fails
/// the origin match - the safe direction.
pub(super) fn url_host(url: &str) -> String {
    let rest = match url.split_once("://") {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") =>
        {
            rest
        }
        _ => return String::new(),
    };
    // Authority ends at the first '/', '?' or '#'.
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    // `user:pass@host` - the LAST '@' separates them, so a password
    // containing '@' cannot smuggle a fake host in front of the real one.
    let hostport = match auth.rsplit_once('@') {
        Some((_, h)) => h,
        None => auth,
    };
    // `[::1]:8080` - the bracketed literal is the host; a bare IPv6 with
    // no brackets is not a legal authority and drops out as empty below.
    let host = if let Some(end) = hostport.find(']') {
        if hostport.starts_with('[') {
            &hostport[..=end]
        } else {
            ""
        }
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

/// May this job's `failure_link` be called? Only when it points back at
/// the host that supplied it. The link arrives in a RESPONSE HEADER from
/// whatever server answered the NZB fetch, and the daemon then calls it
/// from inside the user's network with an SSRF guard that permits
/// loopback and RFC1918 (LAN indexers are the normal case). Binding it to
/// the origin keeps that concession from becoming "any indexer can aim
/// the daemon at any address on your LAN".
///
/// Same host is necessary but not sufficient: an https origin may not be
/// handed an http link. The daemon's own indexer apikey rides in that
/// query string, and "the same indexer, in the clear" is a different
/// party to anything on the path between here and it.
pub(super) fn failure_link_allowed(link: &str, origin_host: &str, origin_https: bool) -> bool {
    // Both sides come out of `url_host`, so this is a comparison of
    // normalized hosts. An empty origin (an NZB the user uploaded, or a
    // record written before this field existed) matches nothing.
    let h = url_host(link);
    if h.is_empty() || h != origin_host {
        return false;
    }
    // Byte compare, not `&link[..8]`: the link comes out of a response
    // header, and slicing a str at a byte index that lands inside a
    // multi-byte character panics.
    !origin_https || link.len() >= 8 && link.as_bytes()[..8].eq_ignore_ascii_case(b"https://")
}

/// Does this response body carry a replacement NZB? Indexers answer 200
/// with a human "nothing found" page at least as often as they answer
/// with XML, so the body decides and the status does not. Same test
/// FailureLink applies.
pub(super) fn is_nzb_body(bytes: &[u8]) -> bool {
    bytes.starts_with(b"<?xml")
}

/// What a re-grabbed replacement inherits from the job it stands in for:
/// `(category, priority, password)`.
///
/// All three used to be dropped on the floor (`cat` fell back to the
/// indexer's own `X-DNZB-Category`, priority was a hardcoded 0, password
/// a hardcoded None), which meant: a Force job's replacement queued at
/// Normal behind work the user had deprioritized; a passworded release's
/// replacement downloaded in full and then failed extraction for a
/// password the daemon was holding (the name-convention fallback cannot
/// recover it - by then `name` is the stem AFTER `smart::name_password`
/// stripped the marker); and the responding server, not the user, chose
/// the output subfolder, the library flag and the move-completed
/// destination.
///
/// Priority is clamped at Normal: a held duplicate carries -3, which is a
/// "parked, do not run" marker, not a speed.
pub(super) fn replacement_inherits(j: &Job) -> (String, i32, Option<String>) {
    (j.category.clone(), j.priority.max(0), j.password.clone())
}

/// May we queue a replacement right now - the mode asks for one, and this
/// chain has not already spent its allowance?
pub(super) fn may_regrab(mode: &str, depth: u8) -> bool {
    mode == "regrab" && depth < FAILURE_REGRAB_MAX
}

/// Ceiling on a fetched NZB. Every caller of [`fetch_url`] - the RSS
/// poller, `/watch`, `addurl`, the failure-link re-grab - takes its URL
/// from somewhere the user does not fully control, and none of them has
/// an opt-in for "this one is allowed to be huge", so the old 256 MB was
/// a quarter of a gigabyte of RAM available to anything that can answer a
/// request.
///
/// 64 MB, not the "a few MB" an NZB usually is: a real 4K remux triple
/// feature off the bench farm measures 23.7 MB of XML, and obfuscated
/// message-ids inflate that further, so the headroom is deliberate. This
/// is a runaway-response guard, not a size policy. An uploaded file goes
/// through addfile, which keeps its own (much larger) body cap.
pub(super) const FETCH_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The bit of [`fetch_url`] both it and [`ping_url`] share: scheme check,
/// SSRF-guarded GET, and the indexer headers off the response.
pub(super) fn fetch_head(url: &str) -> Result<(ureq::Response, String, String)> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        anyhow::bail!("addurl: unsupported url {url}");
    }
    // Release assets redirect to a CDN host; follow the whole chain, but
    // every hop is SSRF-filtered so a public URL can't 302 into 127.0.0.1
    // or 169.254.169.254.
    let resp = ssrf_safe_agent(10, 60).get(url).call()?;
    let failure_link = pick_failure_link(
        &dnzb(&resp, "X-DNZB-Failure"),
        &dnzb(&resp, "X-DNZB-FailureLink"),
    );
    let category = dnzb(&resp, "X-DNZB-Category");
    Ok((resp, failure_link, category))
}

pub(super) fn fetch_url(url: &str) -> Result<Fetched> {
    use std::io::Read;
    let (resp, failure_link, category) = fetch_head(url)?;
    let filename = resp
        .header("Content-Disposition")
        .and_then(content_disposition_filename)
        .unwrap_or_default();
    // Refuse an oversized body BEFORE reading it, when the server was
    // honest enough to declare one; the take() below is the backstop for
    // when it wasn't.
    if let Some(len) = resp
        .header("Content-Length")
        .and_then(|l| l.trim().parse::<u64>().ok())
        && len > FETCH_MAX_BYTES
    {
        anyhow::bail!("{url}: {len} bytes is too large for an NZB");
    }
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(FETCH_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FETCH_MAX_BYTES {
        anyhow::bail!("{url}: response is too large for an NZB");
    }
    // The host we ASKED for, deliberately - not resp.get_url(), which is
    // the last hop of the redirect chain. Otherwise an indexer (or
    // anything that can answer for it) launders an arbitrary origin by
    // bouncing the fetch through one redirect.
    Ok(Fetched {
        bytes,
        failure_link,
        host: url_host(url),
        https: url.starts_with("https://"),
        category,
        filename,
    })
}

/// GET a URL for its SIDE EFFECT only, and never read the body.
///
/// `failure_link` in `report` mode: the report IS the request, nothing
/// inspects what comes back, and a 404 is a normal answer. Returning
/// `Ok(None)` keeps the caller's one error arm (which is where the 404
/// handling lives) doing the work for both modes.
pub(super) fn ping_url(url: &str) -> Result<Option<Fetched>> {
    fetch_head(url)?;
    Ok(None)
}

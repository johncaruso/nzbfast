use std::io::Write as _;

/// Compressed, validated delivery for the embedded pages (TODO §129
/// phase 0c). The dashboard is ~760 KB of HTML fetched on every visit:
/// with no validator and no content encoding it re-crossed the wire in
/// full each time, which a LAN never notices and a phone on a remote
/// link always pays for. The page bodies are substituted per request
/// (theme, locale stamp), so compression happens at respond time and
/// the validator hashes the FINAL bytes: any change that alters the
/// served page changes the ETag, and a 304 can never pin a stale
/// substitution. Cache-Control stays no-cache on purpose - the browser
/// may keep a copy but must revalidate, so a daemon upgrade reaches
/// the UI on the next load as it always has, now as a 304-sized check
/// instead of a full transfer.
///
/// Compression is a per-request gzip rather than a build-time blob for
/// the same substitution reason. A page load is a human-scale event
/// (the 1 Hz polling is JSON, not this path), so milliseconds of
/// deflate per load buys a ~5x smaller transfer with no cache of
/// compressed variants to invalidate.
pub(super) fn respond_page(req: tiny_http::Request, body: String, ctype: &str) {
    // FNV-1a over the final bytes. Not cryptographic and does not need
    // to be: the ETag only has to change when the body changes.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in body.as_bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    let etag = format!("\"{h:016x}\"");

    let mut accepts_gzip = false;
    let mut if_none_match = false;
    for hdr in req.headers() {
        if hdr.field.equiv("Accept-Encoding") {
            accepts_gzip |= gzip_accepted(hdr.value.as_str());
        } else if hdr.field.equiv("If-None-Match") {
            // May carry a list; substring match is exact enough because
            // our tags are fixed-width hex in quotes.
            if_none_match |= hdr.value.as_str().contains(etag.as_str());
        }
    }

    let hdr = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
    if if_none_match {
        let _ = req.respond(
            tiny_http::Response::empty(304)
                .with_header(hdr("ETag", &etag))
                .with_header(hdr("Cache-Control", "no-cache")),
        );
        return;
    }

    // Tiny bodies (404 fallbacks and the like) are not worth a gzip
    // member's overhead.
    let gz = if accepts_gzip && body.len() >= 1024 {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        enc.write_all(body.as_bytes())
            .ok()
            .and_then(|()| enc.finish().ok())
    } else {
        None
    };

    let resp = match gz {
        Some(z) => tiny_http::Response::from_data(z).with_header(hdr("Content-Encoding", "gzip")),
        None => tiny_http::Response::from_data(body.into_bytes()),
    };
    let _ = req.respond(
        resp.with_header(hdr("Content-Type", ctype))
            .with_header(hdr("Cache-Control", "no-cache"))
            .with_header(hdr("Vary", "Accept-Encoding"))
            .with_header(hdr("ETag", &etag)),
    );
}

/// Does this `Accept-Encoding` value permit a gzip body?
///
/// A token scan with the ONE quality value that changes the answer:
/// `q=0` means "not acceptable", so a client that spells out
/// `gzip;q=0` (or `*;q=0` with no gzip token of its own) must get
/// identity. Plain `contains("gzip")` handed it a gzip body it had just
/// said it would not take (L11, 10 Aug sweep). Any other q is a
/// preference between encodings we do not have, and reads as plain
/// acceptance.
fn gzip_accepted(value: &str) -> bool {
    let mut wildcard: Option<bool> = None;
    for tok in value.split(',') {
        let mut parts = tok.split(';').map(str::trim);
        let name = parts.next().unwrap_or("");
        if !name.eq_ignore_ascii_case("gzip") && name != "*" {
            continue;
        }
        let ok = !parts.any(|p| {
            p.strip_prefix("q=")
                .or_else(|| p.strip_prefix("Q="))
                .and_then(|q| q.trim().parse::<f32>().ok())
                .is_some_and(|q| q <= 0.0)
        });
        // A gzip token of its own is the answer; `*` only decides when
        // gzip is not named at all.
        if name == "*" {
            wildcard = Some(ok);
        } else {
            return ok;
        }
    }
    wildcard.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::gzip_accepted;

    /// `q=0` is a refusal, not a preference. The old substring scan
    /// compressed for a client that had explicitly said it could not
    /// take a compressed body (L11, 10 Aug sweep).
    #[test]
    fn a_zero_quality_gzip_is_a_refusal() {
        assert!(gzip_accepted("gzip, deflate, br"));
        assert!(gzip_accepted("gzip;q=1.0, identity;q=0.5"));
        assert!(gzip_accepted("GZIP"));
        assert!(gzip_accepted("*"));
        assert!(!gzip_accepted("gzip;q=0"));
        assert!(!gzip_accepted("deflate, gzip;q=0.0"));
        assert!(!gzip_accepted("identity"));
        assert!(!gzip_accepted(""));
        assert!(!gzip_accepted("*;q=0"));
        // A named gzip decides even when a wildcard disagrees.
        assert!(gzip_accepted("*;q=0, gzip"));
        assert!(!gzip_accepted("*, gzip;q=0"));
    }
}

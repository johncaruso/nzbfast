//! Small shared helpers for the API surface: person-art URLs and
//! thumbnails, the nzo_ids selector, and slot pagination.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// A person's headshot URL, or "" when the cache does not hold one.
///
/// Empty is normal and not an error: the headshot lane fetches lazily,
/// and the cache evicts under its cap, so the UI must always be able to
/// fall back to initials.
#[cfg(feature = "indexer")]
pub(super) fn person_photo_url(art_dir: &std::path::Path, id: i64) -> String {
    let f = crate::wall::person_art_name(id);
    if art_dir.join(&f).is_file() {
        format!("/art/{f}")
    } else {
        Default::default()
    }
}

/// Is `n` a name the unauthenticated /art/ route may join onto the art
/// directory? Only our own `art_name()` output, which is flat ASCII.
///
/// The sanitize round-trip is what keeps a Windows reserved DOS device
/// name out: "CON" is all alphanumerics, so the character class alone
/// lets it through, and `art_root.join("CON")` then opens the console
/// device rather than a file. The read never returns (a hidden console
/// has nobody to type EOF into), so it holds one of the few HTTP worker
/// threads for the life of the process. Real art names carry a "m_"/"t_"
/// key prefix, so none of them can be a device name.
#[cfg(feature = "indexer")]
pub(super) fn art_name_ok(n: &str) -> bool {
    !n.is_empty()
        && !n.contains("..")
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && nzbkit::disk::sanitize_filename_for(n, true) == n
}

/// M28: poster-grid thumbnail - fit inside 342×513 (the TMDB w342
/// aspect), JPEG q80. ~20 KB out of a multi-MB source; None on decode
/// failure (the route then 404s and the client falls back to full art).
#[cfg(feature = "indexer")]
pub(super) fn make_thumb(src: &[u8]) -> Option<Vec<u8>> {
    let img = image::load_from_memory(src).ok()?;
    // Some providers (TVmaze mediums) already serve small posters -
    // never upscale, and never "shrink" into a bigger file.
    if img.width() <= 342 {
        return Some(src.to_vec());
    }
    let img = image::DynamicImage::ImageRgb8(img.thumbnail(342, 513).to_rgb8());
    let mut out = Vec::new();
    img.write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(
        &mut out, 80,
    ))
    .ok()?;
    Some(if out.len() < src.len() {
        out
    } else {
        src.to_vec()
    })
}

/// SAB's `nzo_ids` selector: a client naming specific ids gets exactly
/// those rows, with no start/limit window applied. Sonarr reconciles a
/// download weeks after the grab; an id hidden behind `limit=60` reads
/// as "gone" and wedges its tracking, so direct selection must bypass
/// pagination the way real SABnzbd's does.
pub(super) fn nzo_ids_param(
    params: &std::collections::HashMap<String, String>,
) -> Option<std::collections::HashSet<String>> {
    let raw = params.get("nzo_ids")?;
    let set: std::collections::HashSet<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    (!set.is_empty()).then_some(set)
}

/// start/limit pagination over already-built slots (SAB semantics: both
/// optional; limit 0 = everything).
pub(super) fn paginate(
    slots: Vec<Value>,
    params: &std::collections::HashMap<String, String>,
) -> Vec<Value> {
    let start: usize = params
        .get("start")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let it = slots.into_iter().skip(start);
    if limit == 0 {
        it.collect()
    } else {
        it.take(limit).collect()
    }
}

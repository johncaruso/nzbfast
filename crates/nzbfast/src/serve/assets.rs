use super::*;

/// The dashboard (web/dashboard.html), embedded at compile time so the
/// daemon binary stays a single self-contained file. Edit the html -
/// cargo tracks the include and rebuilds.
pub(super) const DASHBOARD_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/dashboard.html"
));

/// Browser icons and the web manifest the pages link to, embedded like the
/// HTML so an install is still a single binary. Returns the body and its
/// content type, or None if the path is not one of ours.
///
/// The pages used to declare an emoji in a `data:` SVG as their only icon.
/// That draws in the tab strip and nowhere else: with no real bitmap, a
/// browser has nothing to hand the OS when a user pins the dashboard, so
/// Windows drew a generated letter tile instead. These are real PNGs, and
/// 16/32 are drawn from the small master rather than downscaled from the
/// large one (packaging/icon/make-favicons.sh).
pub(super) fn web_icon(path: &str) -> Option<(&'static [u8], &'static str)> {
    Some(match path {
        "/icons/favicon-16.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/favicon-16.png"
            ))[..],
            "image/png",
        ),
        "/icons/favicon-32.png" | "/favicon.ico" => {
            // /favicon.ico is the path a browser probes when a page declares
            // no icon at all - some surfaces (bare API URLs, error pages)
            // still ask for it, so answer with the 32 px art.
            (
                &include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../web/icons/favicon-32.png"
                ))[..],
                "image/png",
            )
        }
        "/icons/apple-touch-icon.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/apple-touch-icon.png"
            ))[..],
            "image/png",
        ),
        "/icons/icon-192.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/icon-192.png"
            ))[..],
            "image/png",
        ),
        "/icons/icon-512.png" => (
            &include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/icons/icon-512.png"
            ))[..],
            "image/png",
        ),
        "/site.webmanifest" => (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../web/site.webmanifest"
            ))
            .as_bytes(),
            "application/manifest+json",
        ),
        _ => return None,
    })
}

/// M13 poster wall (web/wall.html), embedded the same way.
/// §5 i18n phase 1: the supported UI locales and their catalogues,
/// embedded like the HTML so an install is still a single binary.
/// English is the source language and lives inline in the pages -
/// it has no catalogue. Adding a locale = drop web/i18n/<tag>.json,
/// add it here and to UI_LOCALES (and LOCALE_NAMES in dashboard.html -
/// both Interface <select>s are built from that one table at boot):
/// translation-only, no new engineering.
/// Tier 1b (21 Jul) added pt/sv/da/nb/fi/tr/ro - UI only; these have no
/// translated manual or website yet, so /manual/<tag> falls back to
/// English (below) and they're absent from the site pickers.
/// Phase 2a added the Slavic set (ru/pl/cs/uk - CLDR one|few|many plurals,
/// handled by tn()'s Intl.PluralRules) plus Greek (el); likewise UI-only.
/// Phase 2c added Japanese (ja) - first CJK locale; no plural forms
/// (CLDR 'other' → .many), CJK font/wrapping rules live in the pages.
/// Phase 2b added Hebrew (he) - first RTL locale (dual .two plurals) - then
/// Arabic (ar, six CLDR plural categories: .zero/.two/.few added) and
/// Persian (fa, two-form) riding the same dir="rtl" + logical-property
/// layout the pages already had.
/// Phase 2a-ext (Central/SE Europe) added hu/sk/hr/sr (Serbian in Latin
/// script; `sh` aliases to it)/bg/sl - sk/hr/sr carry .few plural keys like
/// cs, Slovenian additionally carries the dual (.two); LTR, likewise UI-only.
pub(super) const UI_LOCALES: [&str; 28] = [
    "en", "fr", "de", "it", "es", "nl", "pt", "sv", "da", "nb", "fi", "tr", "ro", "ru", "pl", "cs",
    "uk", "el", "ja", "he", "ar", "fa", "hu", "sk", "hr", "sr", "bg", "sl",
];
pub(super) fn i18n_catalog(lang: &str) -> Option<&'static str> {
    match lang {
        "fr" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/fr.json"
        ))),
        "de" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/de.json"
        ))),
        "it" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/it.json"
        ))),
        "es" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/es.json"
        ))),
        "nl" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/nl.json"
        ))),
        // Tier 1b - additional Latin-script locales.
        "pt" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/pt.json"
        ))),
        "sv" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/sv.json"
        ))),
        "da" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/da.json"
        ))),
        "nb" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/nb.json"
        ))),
        "fi" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/fi.json"
        ))),
        "tr" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/tr.json"
        ))),
        "ro" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/ro.json"
        ))),
        // Phase 2a - Slavic (ru/pl/cs/uk use CLDR one|few|many plurals) + Greek.
        "ru" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/ru.json"
        ))),
        "pl" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/pl.json"
        ))),
        "cs" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/cs.json"
        ))),
        "uk" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/uk.json"
        ))),
        "el" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/el.json"
        ))),
        // Phase 2c - CJK.
        "ja" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/ja.json"
        ))),
        // Phase 2b - RTL (Hebrew dual; Arabic six-category; Persian two-form).
        "he" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/he.json"
        ))),
        "ar" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/ar.json"
        ))),
        "fa" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/fa.json"
        ))),
        // Phase 2a-ext - hu/bg two-form, sk/hr/sr add .few, sl adds a dual (.two).
        "hu" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/hu.json"
        ))),
        "sk" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/sk.json"
        ))),
        "hr" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/hr.json"
        ))),
        "sr" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/sr.json"
        ))),
        "bg" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/bg.json"
        ))),
        "sl" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/i18n/sl.json"
        ))),
        "en" => Some("{}"), // inline English IS the catalogue
        _ => None,
    }
}
/// Translated manuals (English is MANUAL_HTML itself).
pub(super) fn manual_i18n(lang: &str) -> Option<&'static str> {
    match lang {
        "fr" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.fr.html"
        ))),
        "de" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.de.html"
        ))),
        "it" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.it.html"
        ))),
        "es" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.es.html"
        ))),
        "nl" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.nl.html"
        ))),
        "pt" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.pt.html"
        ))),
        "sv" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.sv.html"
        ))),
        "da" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.da.html"
        ))),
        "nb" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.nb.html"
        ))),
        "fi" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.fi.html"
        ))),
        "tr" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.tr.html"
        ))),
        "ro" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.ro.html"
        ))),
        // Phase 2b RTL - the translated pages carry <html dir="rtl">.
        "he" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.he.html"
        ))),
        "ar" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.ar.html"
        ))),
        "fa" => Some(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/i18n/MANUAL.fa.html"
        ))),
        "en" => Some(MANUAL_HTML),
        _ => None,
    }
}
/// The one design system, shared by the dashboard, the wall and every
/// translation of the manual: the colour tokens plus the pre-paint theme
/// script. Each page carries a `__NZBFAST_UI_TOKENS__` placeholder in its
/// `<head>`; `ui_themed()` substitutes this in.
///
/// Inlined rather than served as `/ui.css` on purpose - an external
/// stylesheet costs a round trip before first paint, which is exactly the
/// flash the pre-paint script exists to avoid.
pub(super) const UI_TOKENS_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/ui-tokens.html"
));

/// Inline the shared design tokens into a page.
pub(super) fn ui_themed(page: &str) -> String {
    page.replace("__NZBFAST_UI_TOKENS__", UI_TOKENS_HTML)
}

/// Stamp the two facts the page shell needs BEFORE its first paint.
///
/// Both pages hide whole regions when the built-in indexer is off, and
/// an answer that arrives with the first API response is too late: the
/// nav, the cards and the wall's poster grid would all render, then
/// disappear. Same mechanism (and the same reason) as the locale token
/// next door.
///
/// `__NZBFAST_INDEX__` is the master switch. `__NZBFAST_INDEXERS__` is
/// how many third-party Newznab accounts are configured and enabled,
/// because with the built-in indexer off that count is what decides
/// whether /wall is still worth a nav pill: it is the pull-search
/// surface too, and hiding it would take the commercial indexers away
/// with it. `__NZBFAST_SPOTS__` is there for the same reason - spots
/// are a third thing /wall can search, switched on independently.
pub(super) fn ui_shell_state(d: &Daemon, page: String) -> String {
    page.replace("__NZBFAST_INDEX__", if d.indexer_off() { "0" } else { "1" })
        .replace(
            "__NZBFAST_SPOTS__",
            if d.spot_enabled.load(Ordering::Relaxed) {
                "1"
            } else {
                "0"
            },
        )
        .replace("__NZBFAST_INDEXERS__", &d.enabled_indexers().to_string())
}

#[cfg(feature = "indexer")]
pub(super) const WALL_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/wall.html"));

pub(super) const MANUAL_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/MANUAL.html"
));

#[cfg(test)]
mod tests {
    use super::DASHBOARD_HTML;

    /// UX §14: a byte formatter may not pair one base with the other's
    /// label.
    ///
    /// `fmtMB` divided by 1024 and printed "GB", so a 100 GiB job read
    /// "100.00 GB" in its own queue row while contributing "107.4 GB" to
    /// the decimal disk-space banner directly above it - the same
    /// download, two numbers, both called GB. The 1024 base is the right
    /// one for release sizes (it is what indexers and SABnzbd quote, and
    /// what the API's `mb` field measures) and stays; the label was the
    /// bug.
    ///
    /// Source-level rather than behavioural because the dashboard has no
    /// runtime under `cargo test` - `web/fmt_test.js` exercises the
    /// arithmetic under node. This one holds the line in CI, where the
    /// page is only ever a string.
    #[test]
    fn byte_formatters_label_the_base_they_divide_by() {
        // Body of `function NAME(` up to its balanced closing brace.
        let body = |name: &str| {
            let at = DASHBOARD_HTML
                .find(&format!("function {name}("))
                .unwrap_or_else(|| panic!("no function {name} in the dashboard"));
            let mut depth = 0usize;
            let bytes = DASHBOARD_HTML.as_bytes();
            let start = at + DASHBOARD_HTML[at..].find('{').expect("no body brace");
            for (i, b) in bytes[start..].iter().enumerate() {
                match b {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return &DASHBOARD_HTML[start..start + i + 1];
                        }
                    }
                    _ => {}
                }
            }
            panic!("unbalanced body for {name}");
        };
        for name in ["fmtMB", "fmtSize"] {
            let b = body(name);
            assert!(
                !b.contains("unit('MB')") && !b.contains("unit('GB')") && !b.contains("unit('TB')"),
                "{name} is 1024-based and must say MiB/GiB/TiB, not MB/GB/TB"
            );
        }
        for name in ["fmtBytes", "fmtGB"] {
            let b = body(name);
            assert!(
                !b.contains("unit('MiB')")
                    && !b.contains("unit('GiB')")
                    && !b.contains("unit('TiB')"),
                "{name} is 1000-based and must say MB/GB/TB, not MiB/GiB/TiB"
            );
        }
        // Every symbol those formatters ask for has to be in the English
        // table, or unit()'s fallback renders "undefined" in every locale
        // that has no override of its own.
        let en = DASHBOARD_HTML
            .split("const UNIT_EN=")
            .nth(1)
            .and_then(|s| s.split('\n').next())
            .expect("UNIT_EN table");
        for k in ["MB:", "GB:", "TB:", "MiB:", "GiB:", "TiB:"] {
            assert!(en.contains(k), "UNIT_EN is missing {k}");
        }
    }
}

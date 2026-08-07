//! serve tests: grabs and the surfaces around them - failure links,
//! regrabs, the settings dashboard, and the update manifest.//!
//! Split out of serve/mod.rs's inline `mod tests` by TODO 106 phase 4;
//! attached to serve as a sibling child module, so `super` still means
//! `serve` exactly as it did inline.

use super::tests_jobs::{job, no_causes};
use super::*;

/// BUG (MEDIUM-HIGH, SSRF): the failure link arrives in a RESPONSE
/// HEADER from whatever server answered the NZB fetch, and the daemon
/// then GETs it with an SSRF guard that deliberately permits loopback
/// and RFC1918 (LAN indexers are the normal case). It may only point
/// back at the host that supplied it.
#[test]
fn a_failure_link_may_only_point_back_at_its_own_indexer() {
    // Same host, different port and path: still the same indexer.
    assert!(failure_link_allowed(
        "http://indexer.example:9118/fail?id=1",
        "indexer.example",
        false
    ));
    assert!(failure_link_allowed(
        "https://Indexer.Example/report",
        "indexer.example",
        false
    ));
    // LAN and loopback indexers keep working.
    assert!(failure_link_allowed(
        "http://127.0.0.1:9117/api?t=failure",
        "127.0.0.1",
        false
    ));
    assert!(failure_link_allowed(
        "http://192.168.1.40:8080/x",
        "192.168.1.40",
        false
    ));
    // Anywhere else is refused - including the classic SSRF targets.
    assert!(!failure_link_allowed(
        "http://127.0.0.1:8989/api/v3/command",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed(
        "http://169.254.169.254/latest/meta-data/",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed(
        "http://evil.example/x",
        "indexer.example",
        false
    ));
    // Userinfo cannot fake the host, and the LAST '@' wins so a
    // password containing '@' cannot smuggle one in either.
    assert!(!failure_link_allowed(
        "http://indexer.example@127.0.0.1/x",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed(
        "http://u:p@a@127.0.0.1/x",
        "indexer.example",
        false
    ));
    // A job with no recorded origin (uploaded NZB, or a record from
    // before the field existed) reports nowhere.
    assert!(!failure_link_allowed(
        "http://indexer.example/fail",
        "",
        false
    ));
    // Non-http schemes and junk are not links at all.
    assert!(!failure_link_allowed(
        "file:///etc/passwd",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed("", "", false));
}

/// BUG (LOW): host equality alone let an indexer reached over TLS hand
/// back an http link for the same host. The report GET carries the
/// user's indexer apikey in its query string, so that is a downgrade
/// of a relationship they had encrypted, chosen by the far end.
#[test]
fn a_failure_link_may_not_downgrade_https_to_http() {
    assert!(!failure_link_allowed(
        "http://indexer.example/fail",
        "indexer.example",
        true
    ));
    assert!(failure_link_allowed(
        "https://indexer.example/fail",
        "indexer.example",
        true
    ));
    // Scheme match is case-insensitive, as schemes are.
    assert!(failure_link_allowed(
        "HTTPS://indexer.example/fail",
        "indexer.example",
        true
    ));
    // Junk with a multi-byte character where the scheme should be:
    // refused, and without panicking on a str slice mid-character.
    assert!(!failure_link_allowed(
        "ht°ps://indexer.example/x",
        "indexer.example",
        true
    ));
    assert!(!failure_link_allowed("é", "indexer.example", true));
    // An http origin is not upgraded-only: it may hand back either.
    assert!(failure_link_allowed(
        "http://indexer.example/fail",
        "indexer.example",
        false
    ));
    assert!(failure_link_allowed(
        "https://indexer.example/fail",
        "indexer.example",
        false
    ));
}

/// BUG (MEDIUM): a transient failure is parked with an M32 automatic
/// retry armed - and was ALSO reported to the indexer as a dead post,
/// re-grabbed, and used to promote the held M14f duplicate. One
/// missing-article gap therefore put three grabs of the same title on
/// the user's block account, and told the indexer a live release was
/// dead over a gap propagation was expected to fill.
///
/// The retry decision has to be answerable BEFORE the hooks run:
/// `park` arms `auto_retry_at` after `run_post_job_hooks` has already
/// spawned, so a guard that reads the field is a race.
#[test]
fn a_failure_awaiting_its_automatic_retry_is_not_reported_dead() {
    let base = json!({
        "nzo_id": "SABnzbd_nzo_nzbfast1",
        "name": "Some.Release.1080p",
        "nzb_path": "/spool/x.nzb",
        "out_dir": "/downloads/Some.Release.1080p",
        "state": "Failed",
        "fail_message": "download incomplete: 12 articles missing",
    });
    let cooldown = 900;

    // First failure: eligible for the automatic retry, so nothing is
    // reported and no replacement is grabbed.
    let first = job(base.clone());
    assert_eq!(first.retries, 0);
    assert!(
        auto_retry_eligible(&first, cooldown),
        "a first transient failure retries"
    );
    assert_eq!(
        post_job_plan(&first, "regrab", cooldown),
        Some(false),
        "hooks still run, but the failure is not final yet"
    );

    // The retry ran, failed again: `retry` bumped `retries` and
    // cleared the stamp, so THIS failure is final and must report.
    let mut second = job(base.clone());
    second.retries = 1;
    assert!(
        !auto_retry_eligible(&second, cooldown),
        "only ONE automatic retry"
    );
    assert_eq!(
        post_job_plan(&second, "regrab", cooldown),
        Some(true),
        "the exhausted retry reports and re-grabs"
    );

    // Auto-retry switched off: the very first failure is final.
    assert!(!auto_retry_eligible(&first, 0));
    assert_eq!(post_job_plan(&first, "regrab", 0), Some(true));

    // A local fault is not transient, so it never held the report
    // back - and it is not reported either (fail_kind, tested above).
    let mut local = job(base.clone());
    local.fail_message = "no space left on device".into();
    assert!(!auto_retry_eligible(&local, cooldown));

    // Deleted mid-download: owes nobody anything, retry or not.
    let mut gone = job(base);
    gone.tombstone = true;
    assert!(!auto_retry_eligible(&gone, cooldown));
    assert_eq!(post_job_plan(&gone, "regrab", cooldown), None);
}

/// BUG (MEDIUM): the config write logged the raw value with a
/// three-name deny-list, so every notification token and every feed
/// url (which carries the indexer apikey) went to stdout - which
/// logtee mirrors into the dashboard log pane users screenshot into
/// support threads, and into journald / `docker logs`.
#[test]
fn the_config_log_never_prints_a_credential() {
    assert_eq!(log_value("apikey", "s3cr3t"), "•••");
    assert_eq!(log_value("nzbkey", "s3cr3t"), "•••");
    assert_eq!(log_value("omdb_key", "s3cr3t"), "•••");

    // Notify targets: counts and kinds, never a url or a token.
    let targets = r#"[{"kind":"kodi","name":"Living room","url":"http://nas:8080/jsonrpc","token":"user:hunter2"},
                      {"kind":"plex","name":"Plex","url":"http://nas:32400","token":"xxPLEXTOKENxx"},
                      {"kind":"webhook","name":"Discord","url":"https://discord.com/api/webhooks/123/AAAsecretBBB","token":""}]"#;
    let shown = log_value("notify_targets", targets);
    assert_eq!(shown, "3 targets (kodi, plex, webhook)");
    for leak in ["hunter2", "PLEXTOKEN", "AAAsecretBBB", "discord.com", "nas"] {
        assert!(!shown.contains(leak), "{leak} reached the log via {shown}");
    }

    // Feeds: the url essentially always embeds `apikey=`.
    let feeds = r#"[{"url":"https://indexer.example/rss?t=tv&apikey=DEADBEEF","interval_secs":900},
                    {"url":"https://other.example/rss?apikey=CAFE","interval_secs":900}]"#;
    let shown = log_value("feeds", feeds);
    assert_eq!(shown, "2 feeds");
    assert!(!shown.contains("DEADBEEF") && !shown.contains("apikey"));

    // M35 indexer entries: the apikey is its own field.
    let idx = r#"[{"name":"geek","url":"https://api.nzbgeek.info","apikey":"SECRETKEY"}]"#;
    let shown = log_value("indexers", idx);
    assert_eq!(shown, "1 indexers");
    assert!(!shown.contains("SECRETKEY"));

    // Malformed JSON must not fall through to the raw value.
    assert!(!log_value("feeds", "{apikey=DEADBEEF").contains("DEADBEEF"));
    assert!(!log_value("indexers", "{apikey=DEADBEEF").contains("DEADBEEF"));
    assert!(!log_value("notify_targets", "hunter2").contains("hunter2"));

    // Switches, numbers and paths still read verbatim - the line is
    // there to be useful.
    assert_eq!(log_value("connections", "40"), "40");
    assert_eq!(
        log_value("out_dir", "/mnt/media/downloads"),
        "/mnt/media/downloads"
    );
    assert_eq!(log_value("auto_rename", "1"), "1");
    assert_eq!(log_value("failure_link", "regrab"), "regrab");

    // DEFAULT DENY: a setting name this function has never heard of -
    // i.e. the next credential-bearing one someone adds - gets a
    // shape summary, not its value.
    assert_eq!(
        log_value("some_future_token", "supersecret"),
        "(11 chars, not logged)"
    );
    assert_eq!(log_value("some_future_token", ""), "(empty)");
}

/// BUG (LOW): the failure-link replacement was enqueued with a
/// hardcoded priority 0 and password None, and took its category from
/// the (untrusted) response header. So a Force job's stand-in queued
/// at Normal, a passworded release's stand-in downloaded in full and
/// then failed extraction for a password the daemon already had, and
/// the indexer chose which of the user's destinations it landed in.
#[test]
fn a_regrabbed_replacement_keeps_the_password_the_priority_and_our_category() {
    let mut j = job(json!({
        "nzo_id": "SABnzbd_nzo_nzbfast1",
        "name": "Some.Release.1080p",
        "nzb_path": "/spool/x.nzb",
        "category": "movies",
        "out_dir": "/downloads/movies/Some.Release.1080p",
        "state": "Failed",
    }));
    j.priority = 2; // Force
    j.password = Some("hunter2".into());
    assert_eq!(
        replacement_inherits(&j),
        ("movies".to_string(), 2, Some("hunter2".to_string()))
    );

    // A held duplicate's -3 is a "parked" marker, not a speed: never
    // propagate it to a download that is meant to run.
    j.priority = -3;
    assert_eq!(replacement_inherits(&j).1, 0);
    // Low is clamped too: the floor is Normal, so a replacement can
    // never come back parked or deprioritized by accident.
    j.priority = -1;
    assert_eq!(replacement_inherits(&j).1, 0, "clamped at Normal");

    // No password, no category: nothing invented.
    let plain = job(json!({
        "nzo_id": "SABnzbd_nzo_nzbfast2",
        "name": "Other.Release",
        "nzb_path": "/spool/y.nzb",
        "out_dir": "/downloads/Other.Release",
        "state": "Failed",
    }));
    assert_eq!(replacement_inherits(&plain), (String::new(), 0, None));
}

/// BUG (MEDIUM): a config save whose value outgrew the 8 KB request
/// line (a watchlist of ~25 shows) got a correct 414 from the server
/// and vanished silently in the browser: `api()` called `r.json()`
/// with no `r.ok` check, the SyntaxError rejected a promise nothing
/// catches, and the one-click "watch this" then no-opped forever.
///
/// Source-level guard: the embedded dashboard is one file with ~60
/// call sites, so what matters is that the two fetch helpers funnel
/// through the checking reader.
#[test]
fn the_dashboard_turns_an_http_error_into_a_visible_one() {
    let src = DASHBOARD_HTML;
    assert!(src.contains("function httpFail(r){ return {status:false, error:'HTTP '+r.status}; }"));
    assert!(src.contains("async function readJson(r){"));
    // Neither helper may parse a response without going through it.
    for helper in [
        "async function api(mode, extra, authKey, post){",
        "async function apiPost(mode, body, authKey){",
    ] {
        let body = &src[src.find(helper).expect("helper present")..];
        let body = &body[..body.find("\n}").expect("helper ends")];
        assert!(
            body.contains("await readJson(r)"),
            "{helper} still parses unchecked"
        );
        assert!(
            !body.contains("await r.json()"),
            "{helper} still parses unchecked"
        );
    }
    // And the JSON-blob settings go up in a POST body, which has no
    // request-line limit to hit in the first place.
    assert!(src.contains("await apiPost('config', {name, value}, auth)"));
}

/// Codex sweep 2, 3 Aug MH1: a query string is not a private
/// channel. It reaches reverse-proxy access logs, the browser's own
/// network panel and history, and any Referer that follows - so a
/// setting whose VALUE is a credential must travel in a request
/// body, whatever its length. `setCfg` sent everything under ~1500
/// chars as `&value=`, and keys are short, so the one class that
/// must never be logged was the class that always was.
///
/// Source-level like its neighbour above, and for the same reason:
/// the property is about which branch a name takes, and the branch
/// is one line.
#[test]
fn a_secret_setting_never_travels_in_the_request_line() {
    let src = DASHBOARD_HTML;
    // The length rule is still there for big JSON blobs, and the
    // secret rule sits beside it as an OR - not an else.
    assert!(
        src.contains("(value.length > 1500 || SECRET_CFG.has(name))"),
        "setCfg no longer forces secrets into the body"
    );
    let set = src
        .split("const SECRET_CFG = new Set(")
        .nth(1)
        .and_then(|s| s.split(");").next())
        .expect("SECRET_CFG present");
    for name in [
        "apikey",
        "nzbkey",
        "omdb_key",
        "notify_targets",
        "arr_instances",
        "indexers",
    ] {
        assert!(set.contains(name), "{name} is not in SECRET_CFG: {set}");
    }
    // notify_test carries a webhook token AND a custom body
    // template. `method:'POST'` does not move query parameters into
    // the body, so it has to be an actual body call.
    assert!(
        src.contains("await apiPost('notify_test', {target: row})"),
        "notify_test still puts the whole target in the request line"
    );
}

/// BUG (MEDIUM): `apply_and_save` answers a write it could not persist
/// with `saved: false` - the value is live, and it reverts at the next
/// restart - and the dashboard threw that flag away. Every path toasted
/// a flat "Saved.", and the API-key ones went further: "New API key
/// created and copied. Paste it into Sonarr, Radarr…" for a key that
/// dies on the next start. The only warning was the eprintln, which is
/// stdout on a NAS, i.e. nobody.
///
/// Source-level guard, like the http-error one above: all three paths
/// that can see the flag must raise the durability bar, and none of
/// them may refuse the key - the daemon is already on it, so a page
/// that kept the old one would lock itself out.
#[test]
fn the_dashboard_says_when_a_change_is_live_but_not_durable() {
    let src = DASHBOARD_HTML;
    assert!(
        src.contains(r#"<div id="durnotice"></div>"#),
        "no durability bar in the page"
    );
    assert!(src.contains("function durNotice("), "no durability notice");
    assert!(
        src.contains("function durNoticeClear("),
        "the bar can never come down again"
    );

    // Function bodies run to the next top-level declaration: openApiFix
    // is a `busy()` wrapper and has no line that is just "}".
    let body_of = |sig: &str| -> &str {
        let s = &src[src.find(sig).unwrap_or_else(|| panic!("{sig} is gone")) + sig.len()..];
        let end = s
            .find("\nasync function ")
            .unwrap_or(s.len())
            .min(s.find("\nfunction ").unwrap_or(s.len()));
        &s[..end]
    };
    for (name, sig) in [
        ("setCfg", "async function setCfg(name, value){"),
        ("newApiKey", "async function newApiKey(){"),
        ("openApiFix", "async function openApiFix(btn){"),
    ] {
        let body = body_of(sig);
        // Strict ===, so an older daemon that omits the field keeps the
        // old behavior rather than warning on every save.
        assert!(
            body.contains("j.saved === false") || body.contains("j.saved===false"),
            "{name} still ignores saved:false"
        );
        assert!(
            body.contains("durNotice("),
            "{name} warns nobody about a lost write"
        );
    }
    // Both key paths still adopt the new key: the daemon is on it.
    for sig in [
        "async function newApiKey(){",
        "async function openApiFix(btn){",
    ] {
        assert!(
            body_of(sig).contains("localStorage.nzbfastKey = j.apikey")
                || body_of(sig).contains("localStorage.nzbfastKey=j.apikey"),
            "a saved:false path stopped adopting the key, which locks the page out"
        );
    }
}

/// One design system, actually reaching every page. Each surface must
/// carry the tokens placeholder, and `ui_themed` must leave none of it
/// behind.
///
/// THE TRAP, hit while writing this: web/ui-tokens.html originally
/// named the placeholder in its own header comment, so substitution
/// re-emitted the literal into every served page. A single `.replace`
/// does not recurse, so nothing broke visibly - it just shipped a
/// stray marker. Hence the "no marker survives" half.
#[cfg(feature = "indexer")]
#[test]
fn every_served_page_gets_the_shared_design_tokens() {
    const MARK: &str = "__NZBFAST_UI_TOKENS__";
    assert!(
        !UI_TOKENS_HTML.contains(MARK),
        "ui-tokens.html names the placeholder, which re-emits it into every page"
    );
    // The tokens themselves, so a gutted file cannot pass.
    for tok in [
        "--surface:",
        "--surface-2:",
        "data-theme=\"contrast\"",
        "nzbfastTheme",
    ] {
        assert!(UI_TOKENS_HTML.contains(tok), "shared tokens lost {tok}");
    }
    // The wall and the manual were the two pages that did NOT read the
    // user's theme; keep them wired.
    let mut pages: Vec<(&str, &str)> = vec![
        ("dashboard", DASHBOARD_HTML),
        ("wall", WALL_HTML),
        ("manual", MANUAL_HTML),
    ];
    for lang in UI_LOCALES {
        if let Some(m) = manual_i18n(lang) {
            pages.push(("manual-i18n", m));
        }
    }
    for (name, page) in pages {
        assert!(page.contains(MARK), "{name} has no tokens placeholder");
        // No page may keep a private palette that would shadow the
        // shared one.
        assert!(
            !page.contains("--bg:#0a0b10") && !page.contains("--bg:#0f1116"),
            "{name} still carries its own background token"
        );
        assert!(
            !ui_themed(page).contains(MARK),
            "{name} kept a stray placeholder"
        );
    }
}

/// BUG (HIGH): a second top-level `function num(v)` - a floor-and-clamp
/// helper for three server-form boxes - was declared in the same single
/// `<script>` block as the locale-aware `function num(v, d)` formatter.
/// Duplicate top-level declarations are legal JS and hoisting makes the
/// LAST one win, so the 1-arg version became the only `num` on the page
/// and every size, speed and percentage lost its decimals: a 1727.39 MB
/// queue item rendered as "1 GB", a 3.4 MB par2 volume as "3 MB", and
/// the Intl decimal-comma path went dead for comma locales.
///
/// `node --check` cannot catch this (the file is valid JS), so the
/// guard is a source-level one: no name may be declared twice at the
/// top level of a served page.
#[cfg(feature = "indexer")]
#[test]
fn no_served_page_declares_the_same_function_twice() {
    for (name, page) in [("dashboard", DASHBOARD_HTML), ("wall", WALL_HTML)] {
        // Column 0 only: that is exactly the top-level scope the whole
        // page shares. Nested declarations are indented and are fine.
        let mut seen: Vec<&str> = Vec::new();
        let mut dupes: Vec<&str> = Vec::new();
        for line in page.lines() {
            let rest = line
                .strip_prefix("function ")
                .or_else(|| line.strip_prefix("async function "));
            let Some(rest) = rest else { continue };
            let ident = rest.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'));
            let Some(ident) = ident.into_iter().next().filter(|s| !s.is_empty()) else {
                continue;
            };
            if seen.contains(&ident) {
                dupes.push(ident);
            } else {
                seen.push(ident);
            }
        }
        assert!(
            dupes.is_empty(),
            "{name}: {dupes:?} declared twice at the top level - the later one silently \
             shadows the earlier for the WHOLE page"
        );
    }

    // And the formatter specifically: it is the one that got shadowed,
    // and it must keep the digit-count argument that ~20 call sites pass.
    assert!(
        DASHBOARD_HTML.contains("function num(v,d){"),
        "the locale-aware number formatter is gone"
    );
    assert!(
        !DASHBOARD_HTML.contains("function num(v){"),
        "a 1-arg num() is back and shadows the formatter"
    );
}

#[test]
fn url_host_parses_the_shapes_that_show_up() {
    assert_eq!(url_host("http://a.example/x"), "a.example");
    assert_eq!(url_host("https://A.Example:443"), "a.example");
    assert_eq!(url_host("http://a.example?q=1"), "a.example");
    assert_eq!(url_host("http://a.example#f"), "a.example");
    assert_eq!(url_host("http://[::1]:8080/x"), "[::1]");
    assert_eq!(url_host("ftp://a.example/x"), "");
    assert_eq!(url_host("/relative"), "");
}

/// THE TRAP in masking the notification token: `saveNotify` rebuilds
/// the whole list from the DOM and the daemon replaces it wholesale,
/// so masking without merging would make the next Apply write
/// `token: ""` and destroy every stored credential.
#[test]
fn a_blank_token_keeps_the_stored_one() {
    use crate::notify::{Kind, Target};
    let t = |name: &str, kind: Kind, url: &str, token: &str| Target {
        name: name.into(),
        kind,
        url: url.into(),
        token: token.into(),
        body: String::new(),
        enabled: true,
        on_failure: false,
        category: String::new(),
    };
    let old = vec![
        t("Plex", Kind::Plex, "http://nas:32400", "PLEXTOKEN"),
        t("Jelly", Kind::Jellyfin, "http://nas:8096", "JELLYKEY"),
    ];
    // Reordered and edited, both tokens blank as the UI sends them.
    let mut incoming = vec![
        t("Jelly", Kind::Jellyfin, "http://nas:8096", ""),
        // Port corrected: no exact match, but only one Plex named Plex.
        t("Plex", Kind::Plex, "http://nas:32401", ""),
        // Brand new row: nothing to carry forward.
        t("Hook", Kind::Webhook, "https://discord/x", ""),
    ];
    super::merge_notify_tokens(&mut incoming, &old);
    assert_eq!(
        incoming[0].token, "JELLYKEY",
        "reordering must not lose a token"
    );
    assert_eq!(
        incoming[1].token, "PLEXTOKEN",
        "editing the URL must not lose a token"
    );
    assert_eq!(incoming[2].token, "");

    // A token the user actually typed always wins.
    let mut typed = vec![t("Plex", Kind::Plex, "http://nas:32400", "NEW")];
    super::merge_notify_tokens(&mut typed, &old);
    assert_eq!(typed[0].token, "NEW");

    // Ambiguous (two same-kind targets with the same name, URL
    // changed): carry nothing rather than hand over the wrong one.
    let twins = vec![
        t("Plex", Kind::Plex, "http://a:32400", "A"),
        t("Plex", Kind::Plex, "http://b:32400", "B"),
    ];
    let mut moved = vec![t("Plex", Kind::Plex, "http://c:32400", "")];
    super::merge_notify_tokens(&mut moved, &twins);
    assert_eq!(moved[0].token, "");
}

/// BUG (LOW, credential leak): the (kind, name) fallback did not check
/// whether the stored target it landed on was ALREADY claimed by an
/// exact (kind, url, name) match on a different incoming row. Adding a
/// second same-kind target that happens to share a name with an
/// existing one therefore copied the first one's token onto it - a
/// credential sent to a server that was never meant to have it.
#[test]
fn a_token_is_never_carried_onto_a_second_target_of_the_same_name() {
    use crate::notify::{Kind, Target};
    let t = |name: &str, kind: Kind, url: &str, token: &str| Target {
        name: name.into(),
        kind,
        url: url.into(),
        token: token.into(),
        body: String::new(),
        enabled: true,
        on_failure: false,
        category: String::new(),
    };
    // One stored Plex server.
    let old = vec![t("Living Room", Kind::Plex, "http://a:32400", "TOKEN-A")];
    // The user keeps it and adds a SECOND Plex server, reusing the
    // name (a rename they have not got round to, or just a habit).
    let mut incoming = vec![
        t("Living Room", Kind::Plex, "http://a:32400", ""),
        t("Living Room", Kind::Plex, "http://b:32400", ""),
    ];
    super::merge_notify_tokens(&mut incoming, &old);
    assert_eq!(
        incoming[0].token, "TOKEN-A",
        "the target it actually belongs to keeps it"
    );
    assert_eq!(
        incoming[1].token, "",
        "a brand new server must not inherit another's token"
    );

    // Same, with the exact-matching row placed second: the fallback
    // must not depend on the order rows arrive in.
    let mut reordered = vec![
        t("Living Room", Kind::Plex, "http://b:32400", ""),
        t("Living Room", Kind::Plex, "http://a:32400", ""),
    ];
    super::merge_notify_tokens(&mut reordered, &old);
    assert_eq!(
        reordered[0].token, "",
        "a brand new server must not inherit another's token"
    );
    assert_eq!(reordered[1].token, "TOKEN-A");

    // A row whose token the user TYPED still claims its stored twin:
    // that credential is being replaced, not made available to a
    // different server that shares the name.
    let mut typed = vec![
        t("Living Room", Kind::Plex, "http://a:32400", "TYPED"),
        t("Living Room", Kind::Plex, "http://b:32400", ""),
    ];
    super::merge_notify_tokens(&mut typed, &old);
    assert_eq!(typed[0].token, "TYPED");
    assert_eq!(
        typed[1].token, "",
        "the replaced credential is not up for grabs either"
    );

    // The legitimate case must still work: the ONLY row of that
    // (kind, name) had its host corrected, so the token follows it.
    let mut corrected = vec![t("Living Room", Kind::Plex, "http://a:32401", "")];
    super::merge_notify_tokens(&mut corrected, &old);
    assert_eq!(
        corrected[0].token, "TOKEN-A",
        "correcting a port must not drop the token"
    );
}

/// The unpack-space forecast has to count the decrypt's temp copy.
///
/// Real case (a tester, 2 Aug): a 13.85 GB RAR5 ENCRYPTED set on a
/// disk with 15.6 GB free. The volumes fit, so the download ran to
/// completion and the unpack then died with the disk full. Counting
/// "volumes + payload" would have told them to free ~12 GB, they
/// would have freed it, and the finish decrypt - which writes the
/// plaintext into a temp beside the ciphertext before renaming -
/// would have failed them a second time.
#[test]
fn an_encrypted_set_is_forecast_a_copy_higher_than_a_plain_one() {
    const GB: u64 = 1_000_000_000;
    // Nothing fetched yet: parts + payload.
    assert_eq!(
        unpack_space_needed(10 * GB, 10 * GB, "rar5 store on-disk"),
        20 * GB
    );
    // Same set, encrypted: the decrypt's temp is a third copy.
    assert_eq!(
        unpack_space_needed(10 * GB, 10 * GB, "rar5 store encrypted on-disk"),
        30 * GB
    );
    // The tester's job, fully downloaded (nothing left to fetch):
    // the honest answer is two more copies, not one.
    assert_eq!(
        unpack_space_needed(0, 13_850 * 1_000_000, "rar5 encrypted unlock-at-end"),
        27_700 * 1_000_000
    );
    // A NESTED set materializes one more layer than it looks: the
    // outer volumes stay on disk, level 0's output IS the inner
    // archive, and level 1's is the payload. So a fully-downloaded
    // 20 GB nested set needs the payload AND the intermediate, where
    // this used to promise only the payload - and the job then hit
    // ENOSPC at the second level with the whole download paid for.
    assert_eq!(
        unpack_space_needed(0, 20 * GB, "rar5 store on-disk inner-rar"),
        40 * GB
    );
    assert_eq!(
        unpack_space_needed(0, 20 * GB, "rar5 store on-disk inner-7z"),
        40 * GB
    );
    // Encrypted AND nested pays for both.
    assert_eq!(
        unpack_space_needed(0, 10 * GB, "rar5 encrypted on-disk inner-rar"),
        30 * GB
    );
    // The plain set beside them is untouched: whole tokens only.
    assert_eq!(
        unpack_space_needed(0, 20 * GB, "rar5 store on-disk"),
        20 * GB
    );
    // Which shapes get a forecast at all: the ones that materialize.
    assert!(shape_unpacks_on_disk("rar5 store encrypted on-disk"));
    assert!(shape_unpacks_on_disk("rar5 store encrypted unlock-at-end"));
    assert!(shape_unpacks_on_disk("rar4 mixed-pass"));
    // A clean one-pass set never holds both at once.
    assert!(!shape_unpacks_on_disk("rar5 store one-pass"));
    assert!(!shape_unpacks_on_disk(""));
    // Saturating, not panicking, on absurd sizes.
    assert_eq!(
        unpack_space_needed(u64::MAX, u64::MAX, "encrypted on-disk"),
        u64::MAX
    );
}

/// BUG (MEDIUM): deleting an active download aborts the pipeline,
/// which surfaces as an Err and files the job Failed - so a
/// cancellation ran the pp-script, sent a "Failed" notification and
/// reported a healthy post to the indexer as dead.
#[test]
fn a_deleted_job_owes_the_outside_world_nothing() {
    assert_eq!(post_job_duties(JobState::Failed, true, "regrab"), None);
    assert_eq!(post_job_duties(JobState::Failed, true, "report"), None);
    // The success race: the fetch returned Ok just before the abort
    // landed. Still deleted, still owes nothing.
    assert_eq!(post_job_duties(JobState::Completed, true, "report"), None);
    // An ordinary failure still reports; an ordinary completion does
    // not, and neither does a failure with the feature off.
    assert_eq!(
        post_job_duties(JobState::Failed, false, "report"),
        Some(true)
    );
    assert_eq!(post_job_duties(JobState::Failed, false, "off"), Some(false));
    assert_eq!(
        post_job_duties(JobState::Completed, false, "regrab"),
        Some(false)
    );
}

/// BUG (MEDIUM): a LOCAL fault reported to the indexer as a dead post.
/// The two policies that read `fail_message` - the auto-retry
/// cooldown and the dead-post report - now share one classifier.
#[test]
fn only_a_dead_post_is_reported_to_the_indexer() {
    // The feature's core cases must still report.
    assert!(
        fail_kind("download incomplete: 3 file(s) with missing segments, 0 decode/write errors")
            .post_unavailable()
    );
    assert!(fail_kind("verification failed and PAR2 repair could not complete").post_unavailable());
    assert!(
        fail_kind("pre-flight: articles missing beyond repair (12 segments)").post_unavailable()
    );
    assert!(fail_kind("content no longer retrievable").post_unavailable());

    // Local faults must not - none of these say anything about the post.
    for local in [
        crate::incomplete_reason(0, 7, &no_causes()),
        "No space left on device (os error 28)".to_string(),
        "Permission denied (os error 13)".to_string(),
        "no usable servers".to_string(),
        "password required to unpack".to_string(),
        "an archive in the output directory could not be unpacked".to_string(),
        "the nested-archive pass failed".to_string(),
    ] {
        assert!(
            !fail_kind(&local).post_unavailable(),
            "must not report: {local}"
        );
    }

    // And the auto-retry policy agrees with itself: waiting can fix a
    // missing article or an unfinished repair, but it cannot empty a
    // full disk - retrying that just runs into the same disk again.
    assert!(
        fail_kind("download incomplete: 1 file(s) with missing segments, 0 decode/write errors")
            .transient()
    );
    assert!(fail_kind("verification failed and PAR2 repair could not complete").transient());
    assert!(!fail_kind(&crate::incomplete_reason(0, 7, &no_causes())).transient());
    // Appended cause clauses (retention / dead server) must not shift
    // the classification: still MissingArticles, still transient.
    let hosts = ["news.x.example".to_string()];
    let with_causes = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 4,
            retention_excluded: 900,
            dead_servers: &hosts,
            ..no_causes()
        },
    );
    assert!(fail_kind(&with_causes).post_unavailable(), "{with_causes}");
    assert!(fail_kind(&with_causes).transient(), "{with_causes}");

    // All-transport losses are the provider's weather, not the
    // post's health: auto-retry yes, indexer dead-post report NO.
    let transport = crate::incomplete_reason(
        3,
        0,
        &crate::LossCauses {
            transport_failed: 12,
            ..no_causes()
        },
    );
    assert!(
        transport.starts_with("download failed on connection errors"),
        "{transport}"
    );
    assert!(!fail_kind(&transport).post_unavailable(), "{transport}");
    assert!(fail_kind(&transport).transient(), "{transport}");

    // A post where every backbone that answered said 430 to every
    // article is DEAD, not damaged. Reported to the indexer like any
    // missing-article failure - but NOT transient: the one automatic
    // retry exists because propagation fills gaps in, and there is no
    // gap here to fill. (Seen in the field, 31 Jul: six minutes and
    // 0 bytes, twice.)
    let gone = crate::incomplete_reason(
        94,
        0,
        &crate::LossCauses {
            missing_430: 12_018,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 0,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(gone.starts_with("post is gone"), "{gone}");
    assert!(fail_kind(&gone).post_unavailable(), "{gone}");
    assert!(!fail_kind(&gone).transient(), "{gone}");
    // The build tag appends to it like anything else, and an *arr
    // still reads it as health so the grab moves to another release.
    assert!(
        !fail_kind(&crate::with_build(gone.clone())).transient(),
        "{gone}"
    );
    assert_eq!(
        super::nzbget_status(&job(json!({
            "nzo_id": "g", "name": "Show.2160p", "nzb_path": "/spool/g.nzb",
            "state": "Failed", "out_dir": "/dl/g", "fail_message": gone,
        }))),
        ("FAILURE/HEALTH", "NONE", "NONE")
    );
    // And the *arr-facing NZBGet mapping calls it health, so a
    // client moves on rather than blaming repair or the machine.
    assert_eq!(
        super::nzbget_status(&job(json!({
            "nzo_id": "t", "name": "Show.1080p", "nzb_path": "/spool/t.nzb",
            "state": "Failed", "out_dir": "/dl/t", "fail_message": transport,
        }))),
        ("FAILURE/HEALTH", "NONE", "NONE")
    );
    // The version tag a job failure now carries must not disturb any
    // of this - it appends after everything.
    let tagged = crate::with_build(transport);
    assert!(!fail_kind(&tagged).post_unavailable(), "{tagged}");
    assert!(!fail_kind("content no longer retrievable").transient());
    // A takedown verdict is a real dead post, but not worth retrying.
    assert!(!fail_kind("pre-flight: articles missing beyond repair").transient());
}

/// The wire tokens the drawer switches on. Pinned because they are an
/// API: renaming one silently drops a remedy button rather than
/// breaking a build.
#[test]
fn fail_kind_tokens_are_stable() {
    for (msg, want) in [
        (
            "download incomplete: 3 file(s) with missing segments, 0 decode/write errors",
            "missing",
        ),
        (
            "download failed on connection errors: pool stalled",
            "transport",
        ),
        (
            "verification failed and PAR2 repair could not complete",
            "unrepairable",
        ),
        (
            "pre-flight: articles missing beyond repair (12 segments)",
            "preflight",
        ),
        ("content no longer retrievable", "gone"),
        ("No space left on device (os error 28)", "local"),
    ] {
        assert_eq!(fail_kind_token(fail_kind(msg)), want, "{msg}");
    }
}

/// The sub-cause inside the message. Each token is keyed on a clause
/// `incomplete_reason` (or the pool) writes verbatim, so the strings
/// here are built by the real producers wherever possible.
#[test]
fn fail_hint_names_the_sub_cause() {
    let retention = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 1,
            retention_excluded: 900,
            ..no_causes()
        },
    );
    assert_eq!(fail_hint(&retention), "retention", "{retention}");
    // A post carrying no parity at all: another release is the only
    // answer, even though the KIND is the retryable missing-articles.
    let nopar2 = crate::incomplete_reason(
        1,
        0,
        &crate::LossCauses {
            missing_430: 3,
            par2_slots: 0,
            ..no_causes()
        },
    );
    assert_eq!(fail_hint(&nopar2), "nopar2", "{nopar2}");
    assert_eq!(fail_kind(&nopar2), FailKind::MissingArticles, "{nopar2}");
    // Both forms of the empty pool, including the build tag that gets
    // appended to every job failure.
    for msg in [
        "no usable servers: none are set up yet - add your provider in Server settings",
        "no usable servers: every one you have set up is out of the pool right now - \
         news.x.example (switched off)",
    ] {
        assert_eq!(fail_hint(msg), "servers", "{msg}");
    }
    // A plain failure has no sub-cause and falls back to its kind.
    assert_eq!(fail_hint("Permission denied (os error 13)"), "");
    let plain = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 4,
            par2_slots: 9,
            ..no_causes()
        },
    );
    assert_eq!(fail_hint(&plain), "", "{plain}");
}

/// ONE action per failure, and never the useless one: the audit found
/// every kind sharing a single Retry, including the two the daemon
/// itself classifies as unfixable by retrying.
#[test]
fn each_failure_gets_the_action_that_can_help() {
    let act = |msg: &str, pw: bool| fail_action(fail_kind(msg), fail_hint(msg), msg, pw);
    // Waiting genuinely helps these two, and only these two.
    assert_eq!(
        act(
            "download incomplete: 1 file(s) with missing segments, 0 decode/write errors",
            false
        ),
        "retry"
    );
    assert_eq!(
        act("download failed on connection errors: pool stalled", false),
        "retry"
    );
    // A dead post, a pre-flight verdict and an unrepairable set are
    // all answered by another release, never by asking again.
    for msg in [
        "content no longer retrievable",
        "pre-flight: articles missing beyond repair (12 segments)",
        "verification failed and PAR2 repair could not complete",
    ] {
        assert_eq!(act(msg, false), "search", "{msg}");
    }
    // Sub-causes outrank the kind.
    let retention = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 1,
            retention_excluded: 900,
            ..no_causes()
        },
    );
    assert_eq!(act(&retention, false), "retention", "{retention}");
    assert_eq!(
        act("no usable servers: none are set up yet", false),
        "servers"
    );
    // ...and the two that outrank everything. Both are `Local`, and
    // "show the folder" answers neither of them.
    assert_eq!(act("No space left on device (os error 28)", false), "space");
    assert_eq!(act("unpack failed", true), "password");
    // A full disk stays a full disk even for a locked archive: the
    // password prompt is the thing that can actually be completed.
    assert_eq!(
        act("No space left on device (os error 28)", true),
        "password"
    );
    // Everything else local: the folder is where the evidence is.
    assert_eq!(act("Permission denied (os error 13)", false), "path");
}

/// Six watch-folder states, four of which are SUCCESSES. The strip
/// showed one sentence for all six and offered a Delete that destroys
/// the only copy in exactly the states where it is not safe.
#[test]
fn watch_folder_states_are_told_apart() {
    use super::tasks::{watch_fail_ingested, watch_fail_kind, watchfail};
    for (msg, kind, ingested) in [
        (watchfail::TRUNCATED.to_string(), "truncated", false),
        (watchfail::ALREADY_QUEUED.to_string(), "queued", true),
        (watchfail::ALREADY_DONE.to_string(), "done", true),
        (watchfail::UNSAVED.to_string(), "unsaved", true),
        (
            format!("{}: Permission denied (os error 13)", watchfail::KEPT),
            "kept",
            true,
        ),
        (
            "not an NZB: no <nzb> element".to_string(),
            "rejected",
            false,
        ),
    ] {
        assert_eq!(watch_fail_kind(&msg), kind, "{msg}");
        assert_eq!(watch_fail_ingested(kind), ingested, "{msg}");
    }
}

#[test]
fn cat_dest_list_parses_and_round_trips() {
    let list = super::parse_cat_dests(" tv = /NAS/TV, movies=/NAS/Movies ; ; ").unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].0, "tv");
    assert_eq!(list[0].1, std::path::PathBuf::from("/NAS/TV"));
    assert_eq!(
        super::fmt_cat_dests(&list),
        "tv=/NAS/TV, movies=/NAS/Movies"
    );
    // Empty clears; malformed and duplicate entries are rejected.
    assert!(super::parse_cat_dests("").unwrap().is_empty());
    assert!(super::parse_cat_dests("no-equals-here").is_err());
    assert!(super::parse_cat_dests("tv=/a, tv=/b").is_err());
    // Category names get the enqueue-path sanitizing (a traversal
    // token can't map to a folder no job ever used).
    let odd = super::parse_cat_dests("t/v=/NAS/X").unwrap();
    assert_eq!(odd[0].0, nzbkit::disk::sanitize_filename("t/v"));
}

/// The two spellings of the failure header in the wild, and the
/// blank-header case (an indexer that sets it unconditionally).
#[test]
fn failure_link_header_aliases() {
    assert_eq!(
        super::pick_failure_link("http://a/fail", ""),
        "http://a/fail"
    );
    assert_eq!(
        super::pick_failure_link("", "http://b/fail"),
        "http://b/fail"
    );
    // Canonical wins when an indexer sends both.
    assert_eq!(
        super::pick_failure_link("http://a/fail", "http://b/fail"),
        "http://a/fail"
    );
    assert_eq!(super::pick_failure_link("", ""), "");
}

/// The body decides whether a replacement came back, not the status:
/// indexers answer 200 with a "nothing found" page all the time, and
/// queueing that as an NZB would fail a second job for no reason.
#[test]
fn only_an_xml_body_counts_as_a_replacement() {
    assert!(super::is_nzb_body(br#"<?xml version="1.0"?><nzb></nzb>"#));
    assert!(!super::is_nzb_body(
        b"<html><body>No results found</body></html>"
    ));
    assert!(!super::is_nzb_body(b""));
    // A bare <nzb> with no declaration is rejected too - same rule
    // FailureLink applies, and being stricter than the thing we are
    // matching would queue junk the reference implementation skips.
    assert!(!super::is_nzb_body(b"<nzb></nzb>"));
}

/// A replacement that also fails asks for another. The chain has to
/// stop on its own, unattended, before it walks an indexer's whole
/// run of dead posts through someone's block account.
#[test]
fn the_regrab_chain_stops_at_the_cap() {
    assert!(super::may_regrab("regrab", 0));
    assert!(super::may_regrab("regrab", super::FAILURE_REGRAB_MAX - 1));
    assert!(!super::may_regrab("regrab", super::FAILURE_REGRAB_MAX));
    assert!(!super::may_regrab("regrab", super::FAILURE_REGRAB_MAX + 9));
    // "report" reaches the indexer but never queues anything, and
    // "off" was already filtered out upstream - neither re-grabs.
    assert!(!super::may_regrab("report", 0));
    assert!(!super::may_regrab("off", 0));
}

/// End to end over a real socket: an indexer's X-DNZB headers have to
/// survive the fetch, or the failure link is never recorded and the
/// whole feature is silently dead. Loopback is deliberately reachable
/// through the SSRF guard (see the test below), so this exercises the
/// real `fetch_url`, agent and all.
#[test]
fn fetch_url_keeps_the_indexer_headers() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/getnzb/abc", listener.local_addr().unwrap());
    let t = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let body = r#"<?xml version="1.0"?><nzb></nzb>"#;
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                 X-DNZB-Failure: http://indexer/fail?id=abc\r\n\
                 X-DNZB-Category: tv\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });
    let f = super::fetch_url(&url).expect("loopback fetch");
    t.join().unwrap();
    assert_eq!(f.failure_link, "http://indexer/fail?id=abc");
    assert_eq!(f.category, "tv");
    assert!(super::is_nzb_body(&f.bytes));
}

/// Issue #26 end to end at the fetch layer: a Prowlarr redirect grab is
/// `addurl` with an id-hash URL and no `nzbname`; the release name only
/// exists in the response's Content-Disposition. It has to survive the
/// fetch, or the job is titled after the hash.
#[test]
fn fetch_url_keeps_the_content_disposition_name() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/getnzb/chsfsd12das32da90aa3181?i=1&r=key",
        listener.local_addr().unwrap()
    );
    let t = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let body = r#"<?xml version="1.0"?><nzb></nzb>"#;
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                 Content-Disposition: attachment; filename=\"Some.Release.2026.1080p-GRP.nzb\"\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });
    let f = super::fetch_url(&url).expect("loopback fetch");
    t.join().unwrap();
    assert_eq!(f.filename, "Some.Release.2026.1080p-GRP.nzb");
    assert_eq!(
        super::name_from_fetch(&f, &url).as_deref(),
        Some("Some.Release.2026.1080p-GRP.nzb")
    );
}

/// The three Content-Disposition shapes in the wild, plus the refusals:
/// path components are shorn (the header is attacker-influenced) and
/// RFC 5987 `filename*` wins over `filename` when both appear.
#[test]
fn content_disposition_filename_shapes() {
    let cd = super::content_disposition_filename;
    assert_eq!(
        cd("attachment; filename=\"A.Release.nzb\"").as_deref(),
        Some("A.Release.nzb")
    );
    assert_eq!(
        cd("attachment; filename=bare.nzb").as_deref(),
        Some("bare.nzb")
    );
    assert_eq!(
        cd("attachment; filename*=UTF-8''Sp%C3%A9cial%20Name.nzb").as_deref(),
        Some("Spécial Name.nzb")
    );
    // filename* wins regardless of parameter order, and `+` stays literal.
    assert_eq!(
        cd("attachment; filename=\"fallback.nzb\"; filename*=utf-8''Real+One.nzb").as_deref(),
        Some("Real+One.nzb")
    );
    // Path components shorn - a header must not steer names around.
    assert_eq!(
        cd("attachment; filename=\"../../etc/evil.nzb\"").as_deref(),
        Some("evil.nzb")
    );
    assert_eq!(
        cd("attachment; filename=\"C:\\\\spool\\\\evil.nzb\"").as_deref(),
        Some("evil.nzb")
    );
    // Nothing usable: absent, empty, or absurd.
    assert_eq!(cd("inline"), None);
    assert_eq!(cd("attachment; filename=\"\""), None);
    assert_eq!(
        cd(&format!("attachment; filename=\"{}\"", "x".repeat(300))),
        None
    );
    // Codex 7 Aug L3: a semicolon INSIDE the quoted value is part of
    // the name, not a parameter boundary - the blind split named the
    // job "Show" and skewed folder + duplicate identity off it.
    assert_eq!(
        cd("attachment; filename=\"Show; Part 2.nzb\"").as_deref(),
        Some("Show; Part 2.nzb")
    );
    // ...and an empty/malformed filename* must not suppress the valid
    // plain filename beside it.
    assert_eq!(
        cd("attachment; filename=\"Good.nzb\"; filename*=UTF-8''").as_deref(),
        Some("Good.nzb")
    );
    // Sweep 7 Aug: control characters out - a percent-encoded CR/LF or
    // ESC in the header must not reach logs through the job name.
    assert_eq!(
        cd("attachment; filename*=UTF-8''evil%0d%0afake%20log%20line.nzb").as_deref(),
        Some("evilfake log line.nzb")
    );
}

/// Without a Content-Disposition the fallback is the URL's last path
/// segment WITHOUT the query string - the old code kept `?t=get&id=...`
/// glued onto API-style links.
#[test]
fn name_from_fetch_strips_the_query() {
    let f = super::Fetched {
        bytes: Vec::new(),
        failure_link: String::new(),
        host: String::new(),
        https: false,
        category: String::new(),
        filename: String::new(),
    };
    assert_eq!(
        super::name_from_fetch(&f, "https://x/api?t=get&id=abc").as_deref(),
        Some("api")
    );
    assert_eq!(
        super::name_from_fetch(&f, "https://x/getnzb/abc123.nzb?r=key#frag").as_deref(),
        Some("abc123.nzb")
    );
    assert_eq!(super::name_from_fetch(&f, "https://x/dir/"), None);
}

/// SSRF guard: cloud-metadata / link-local is refused; loopback, LAN
/// and CGNAT stay reachable (self-hosted indexers + Tailscale live
/// there), as do public hosts.
#[test]
fn ssrf_guard_blocks_metadata_but_allows_local() {
    use std::net::IpAddr;
    let blocked = [
        "169.254.169.254",        // cloud metadata (link-local)
        "169.254.1.1",            // link-local
        "0.0.0.0",                // unspecified
        "255.255.255.255",        // broadcast
        "fe80::1",                // v6 link-local
        "::ffff:169.254.169.254", // v4-mapped metadata
        "100.100.100.200",        // Alibaba metadata (inside CGNAT)
        "fd00:ec2::254",          // AWS IPv6 IMDS (inside ULA)
    ];
    for s in blocked {
        let ip: IpAddr = s.parse().unwrap();
        assert!(super::is_forbidden_fetch_ip(ip), "should block {s}");
    }
    // Legitimate for a self-hosted downloader - must stay reachable.
    let allowed = [
        "127.0.0.1",    // local indexer on loopback
        "10.0.0.5",     // LAN
        "192.168.1.10", // LAN
        "172.16.9.9",   // LAN
        "100.64.0.1",   // Tailscale CGNAT
        "::1",          // v6 loopback
        "fc00::1",      // v6 ULA (LAN)
        "8.8.8.8",      // public
        "2606:4700:4700::1111",
    ];
    for s in allowed {
        let ip: IpAddr = s.parse().unwrap();
        assert!(!super::is_forbidden_fetch_ip(ip), "should allow {s}");
    }
}

// A deterministic ephemeral keypair (fixed seed) drives the crypto-path
// tests, so they never depend on the production key and there is nothing
// to regenerate when the embedded key rotates.
fn test_vector() -> (String, Vec<u8>, String) {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pub_hex = hex::encode(sk.verifying_key().to_bytes());
    let manifest = br#"{"version":"9.9.9"}"#.to_vec();
    let sig_hex = hex::encode(sk.sign(&manifest).to_bytes());
    (pub_hex, manifest, sig_hex)
}

#[test]
fn manifest_signature_accepts_valid() {
    let (pk, manifest, sig) = test_vector();
    assert!(super::verify_with_key(&pk, &manifest, sig.as_bytes()).is_ok());
}

#[test]
fn manifest_signature_rejects_tampered_body() {
    let (pk, manifest, sig) = test_vector();
    let mut bad = manifest.clone();
    let n = bad.len() - 3;
    bad[n] ^= 0x01;
    assert!(super::verify_with_key(&pk, &bad, sig.as_bytes()).is_err());
}

#[test]
fn manifest_signature_rejects_tampered_sig() {
    let (pk, manifest, mut sig) = test_vector();
    let first = if sig.starts_with('f') { 'e' } else { 'f' };
    sig.replace_range(0..1, &first.to_string());
    assert!(super::verify_with_key(&pk, &manifest, sig.as_bytes()).is_err());
}

#[test]
fn manifest_signature_rejects_wrong_key() {
    // A valid signature under one key must NOT verify under a different
    // key - this is the property that stops a foreign manifest.
    let (_pk, manifest, sig) = test_vector();
    assert!(super::verify_manifest_sig(&manifest, sig.as_bytes()).is_err());
}

#[test]
fn manifest_signature_rejects_malformed_sig() {
    let (pk, manifest, _sig) = test_vector();
    assert!(super::verify_with_key(&pk, &manifest, b"not-hex").is_err());
    assert!(super::verify_with_key(&pk, &manifest, b"abcd").is_err());
    assert!(super::verify_with_key(&pk, &manifest, b"").is_err());
}

// ---- anti-rollback ratchet (READ-ONLY phase) ----------------------
//
// These pin the properties the LATER enforcing build will rely on. The
// one thing they must also prove is that this build does not enforce:
// a regression is recorded and warned about, never refused.

#[test]
fn manifest_serial_ratchet_advances_and_never_lowers() {
    use super::SerialStep::*;
    let m = |s: u64| serde_json::json!({ "version": "1.0.0", "serial": s });

    // A fresh install (seen = 0) takes whatever it is first told.
    assert_eq!(super::serial_ratchet(0, &m(100)), Advance(100));
    assert_eq!(super::serial_ratchet(100, &m(140)), Advance(140));

    // THE replay: an old, genuinely-signed manifest served again. The
    // signature is valid - only the serial catches this.
    assert_eq!(
        super::serial_ratchet(140, &m(100)),
        Regressed {
            got: 100,
            seen: 140
        }
    );

    // Re-serving the same manifest is the steady state, not a write.
    assert_eq!(super::serial_ratchet(140, &m(140)), Hold);
}

#[test]
fn manifest_serial_junk_and_absence_hold_the_ratchet() {
    use super::SerialStep::*;
    // Absent: normal during the rollout. Must HOLD, not clear - if it
    // cleared, replaying a pre-serial manifest would disarm the defence.
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "version": "1.0.0" })),
        Hold
    );
    // Junk must not coerce into a huge serial, which would pin the
    // install above every real release it will ever be offered.
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": "999999" })),
        Hold
    );
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": -5 })),
        Hold
    );
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": 1.5 })),
        Hold
    );
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": null })),
        Hold
    );
}

#[test]
fn manifest_serial_is_not_enforced_in_this_build() {
    // The read-only guarantee, stated as a test so that flipping to
    // enforcement has to come here and change it deliberately rather
    // than inherit it. `serial_ratchet` reports a regression and that
    // is ALL it can do - there is no variant that refuses, so no
    // caller can act on one by accident.
    use super::SerialStep::*;
    let stale = serde_json::json!({ "version": "99.0.0", "serial": 1 });
    assert_eq!(
        super::serial_ratchet(500, &stale),
        Regressed { got: 1, seen: 500 }
    );
    assert!(
        super::version_newer("99.0.0", env!("CARGO_PKG_VERSION")),
        "the version comparison, which is what actually decides today, is untouched"
    );
}

#[test]
fn embedded_update_key_is_well_formed() {
    // The shipped key must be a valid 32-byte ed25519 public key, or every
    // update check dies at "update key is malformed".
    let raw = hex::decode(super::UPDATE_PUBKEY_HEX).expect("pubkey hex");
    assert_eq!(raw.len(), 32, "UPDATE_PUBKEY_HEX must be 32 bytes");
    let arr: [u8; 32] = raw.try_into().unwrap();
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&arr).is_ok());
}

#[test]
fn parse_sizes() {
    assert_eq!(super::parse_size("500M"), Some(500_000_000));
    assert_eq!(super::parse_size("10G"), Some(10_000_000_000));
    assert_eq!(super::parse_size("1.5T"), Some(1_500_000_000_000));
    assert_eq!(super::parse_size("12345"), Some(12345));
    assert_eq!(super::parse_size("nope"), None);
}

// -- M34 index size cap ------------------------------------------------

/// The order setting is a closed set. Anything else is rejected at
/// the settings boundary, which is what lets `evict_policy` treat the
/// stored string as always-valid.
#[cfg(feature = "indexer")]
#[test]
fn evict_order_setting_accepts_exactly_the_five_orders() {
    use nzbkit::index::EvictOrder as O;
    assert!(matches!(
        super::parse_evict_order("ladder"),
        Some(O::Ladder)
    ));
    assert!(matches!(
        super::parse_evict_order("oldest"),
        Some(O::Oldest)
    ));
    assert!(matches!(
        super::parse_evict_order("newest"),
        Some(O::Newest)
    ));
    assert!(matches!(
        super::parse_evict_order("largest"),
        Some(O::Largest)
    ));
    assert!(matches!(
        super::parse_evict_order("smallest"),
        Some(O::Smallest)
    ));
    // Case and whitespace are the user's, not ours.
    assert!(matches!(
        super::parse_evict_order("  LaDdEr "),
        Some(O::Ladder)
    ));
    // Everything else, including the empty string, is refused rather
    // than silently defaulted - a typo must not quietly change which
    // rows get deleted.
    for bad in ["", "random", "ladder,oldest", "biggest", "asc"] {
        assert!(
            super::parse_evict_order(bad).is_none(),
            "{bad:?} must not parse"
        );
    }
    // The advertised list and the parser agree.
    for o in super::EVICT_ORDERS {
        assert!(
            super::parse_evict_order(o).is_some(),
            "{o} advertised but unparseable"
        );
    }
}

/// The kinds list is validated for a reason worth spelling out: it is
/// a RESTRICTION ("evict only these"), so a typo does not evict the
/// wrong thing - it evicts nothing, and the user is left staring at a
/// cap that never frees a byte with no error anywhere.
#[cfg(feature = "indexer")]
#[test]
fn evict_kinds_setting_validates_and_normalizes() {
    assert_eq!(super::parse_evict_kinds("").unwrap(), Vec::<String>::new());
    assert_eq!(
        super::parse_evict_kinds("   ").unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        super::parse_evict_kinds(" Movie , TV ").unwrap(),
        vec!["movie".to_string(), "tv".to_string()]
    );
    // Duplicates collapse; trailing separators are ignored.
    assert_eq!(
        super::parse_evict_kinds("tv,tv,,other,").unwrap(),
        vec!["tv".to_string(), "other".to_string()]
    );
    let e = super::parse_evict_kinds("movie,film").unwrap_err();
    assert!(e.contains("film"), "the error must name the offender: {e}");
}

/// The wizard's answer must not read as an established install: the
/// setup command runs as its own process, so its answer reaches
/// settings.json before the daemon has ever started, and the
/// first-run API key test keys off exactly that file.
#[test]
fn a_settings_file_of_wizard_answers_is_still_a_first_run() {
    let dir = std::env::temp_dir().join(format!("nzbfast-setupans-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("settings.json");
    let beyond = |text: &str| {
        std::fs::write(&p, text).unwrap();
        super::settings_beyond_setup_answers(&p)
    };
    assert!(
        !beyond(r#"{"index_interests":"linux,sports"}"#),
        "the wizard answer alone"
    );
    assert!(
        !beyond(r#"{"index_interests":""}"#),
        "answering \"nothing\" is an answer"
    );
    // Anything the daemon itself wrote means it has run.
    assert!(beyond(r#"{"index_interests":"linux","auto_speed":false}"#));
    assert!(beyond(r#"{"apikey":"k"}"#));
    // An empty object carries no wizard answer to explain itself, so
    // the old rule stands: the file exists, the install has run.
    assert!(beyond("{}"));
    // Unreadable or not-an-object: never mint over state we cannot
    // parse.
    assert!(beyond("[1,2,3]"));
    assert!(beyond("this is not json"));
    // A missing file is the caller's case, and answers false here.
    std::fs::remove_file(&p).unwrap();
    assert!(!super::settings_beyond_setup_answers(&p));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rename_punctuation_defaults_preserve_upgrades_only() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rename-upgrade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("nzbfast.toml");
    let out = dir.join("downloads");
    let settings = dir.join("settings.json");

    assert!(
        !super::legacy_rename_punctuation(&config, &out, &settings),
        "a genuinely fresh install gets the new unpunctuated default"
    );
    std::fs::write(&settings, r#"{"index_interests":"tv"}"#).unwrap();
    assert!(
        !super::legacy_rename_punctuation(&config, &out, &settings),
        "the setup wizard runs before the daemon but is still a fresh install"
    );
    std::fs::write(&settings, "{}").unwrap();
    assert!(
        super::legacy_rename_punctuation(&config, &out, &settings),
        "an established settings file preserves the historical punctuation"
    );

    std::fs::remove_file(&settings).unwrap();
    std::fs::create_dir_all(config.with_file_name(".spool")).unwrap();
    assert!(
        super::legacy_rename_punctuation(&config, &out, &settings),
        "pre-settings installs are also identified by their existing spool"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

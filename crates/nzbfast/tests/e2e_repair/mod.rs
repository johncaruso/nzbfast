//! Repair-ladder e2e surfaces, a child module so e2e.rs stays inside
//! its size-gate baseline (the e2e_chip6 pattern: `mod` children in a
//! sibling dir, harness reached through `super::*`).

use super::*;

/// Codex sweep 10 Aug M3: par2cmdline is an OPTIONAL escape hatch, so a
/// machine without one must still reach the escalation that fetches
/// every remaining recovery volume and retries natively. The old control
/// flow returned the moment the external binary would not spawn, which
/// put its own native escalation out of reach - a repairable set could
/// fail purely because an unrelated tool was not installed.
///
/// Both hatches are shut here: `PATH` is emptied so nothing resolves
/// `par2`, and the native kill switch makes every native attempt
/// decline. That pins the CONTROL FLOW - the escalation is entered and
/// the remaining volumes are fetched - not the repair verdict, which
/// cannot succeed with native repair switched off.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_external_par2_still_reaches_the_native_escalation() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, _inner, _vol_names) = rar_release("no-external-par2", true);
    let victim = |file: &str, suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains(file) && k.ends_with(suffix))
            .unwrap()
            .clone()
    };
    let chaos = Chaos {
        missing: [
            victim("r_part2_rar", "-3@mock>"),
            victim("r_part2_rar", "-5@mock>"),
        ]
        .into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        // An empty PATH is the whole point: `tools::resolve("par2")`
        // falls back to the bare name, and with nothing to search the
        // spawn fails exactly as it does on a native-only install.
        run_get(
            &cfg,
            &nzb,
            &out,
            &[("PATH", ""), ("NZBFAST_NO_NATIVE_REPAIR", "1")],
        )
    })
    .await
    .unwrap();
    assert!(
        log.contains("no external par2 was runnable"),
        "the external hatch was not the one that closed:\n{log}"
    );
    assert!(
        log.contains("repair short - fetching all"),
        "a missing external par2 skipped the native escalation:\n{log}"
    );
    assert!(
        !ok,
        "with native repair switched off there is nothing left to repair with:\n{log}"
    );
}

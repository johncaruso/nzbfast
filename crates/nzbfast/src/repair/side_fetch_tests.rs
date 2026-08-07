//! Side-fetch cancellation tests (Codex 5 Aug M3). A child module of
//! `repair` so repair.rs keeps its size-gate baseline - same pattern
//! as pool/unit_tests.rs.

use super::*;

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-sidefetch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Codex 5 Aug M3: a side-fetch against a blackholed provider used to
/// run its whole multi-session retry ladder with no way to stop it,
/// holding drain_network's await - and with it Cancel/Pause - for
/// minutes. With a QueueControl attached, an abort must bring
/// `fetch_volume_articles` home promptly.
#[tokio::test]
async fn an_aborted_side_fetch_returns_promptly() {
    use nzbkit::mock::{Chaos, MockServer};
    use nzbkit::pool::{ArticleReq, QueueControl};
    // A provider that accepts the TCP connect and never greets - the
    // blackhole shape that held the ladder hostage.
    let chaos = Chaos {
        mute_greeting: true,
        ..Default::default()
    };
    let srv = MockServer::start(std::collections::HashMap::new(), chaos).await;
    let servers = side_pool_servers(&[(srv.server_config(), nzbkit::pool::PoolConfig::default())]);
    let dir = tdir("m3-abort");
    let ctl = Arc::new(QueueControl::default());
    // Abort shortly after the fetch starts, and keep aborting: the
    // handle attaches inside the call, so a single early abort could
    // land before there is a pool to abort.
    let aborter = {
        let ctl = ctl.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            loop {
                ctl.abort();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
    };
    let mut idm = std::collections::HashMap::new();
    idm.insert("<vol@x>".to_string(), 0usize);
    let ids = vec![ArticleReq {
        id: "<vol@x>".to_string(),
        age_days: 0,
        part: 1,
    }];
    let t0 = std::time::Instant::now();
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        fetch_volume_articles(
            &servers,
            ids,
            idm,
            &dir,
            &nzbkit::pool::BufPool::new(4),
            u64::MAX,
            Some(&ctl),
        ),
    )
    .await
    .expect("an aborted side-fetch must not run the full retry ladder")
    .expect("harvest still succeeds after an abort");
    aborter.abort();
    // Well under the ladder's multi-session budget (each connect
    // alone is allowed 20 s); generous against a loaded CI box.
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(15),
        "abort took {:?}",
        t0.elapsed()
    );
    // Nothing landed, and the harvest says so honestly.
    assert!(res.1.is_empty(), "no volume paths from a mute provider");
    let _ = std::fs::remove_dir_all(&dir);
}

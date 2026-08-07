//! §123 chip-6 e2e surfaces, a child module so e2e.rs stays inside
//! its size-gate baseline (the daemon.rs pattern: `mod` children in a
//! sibling dir, harness reached through `super::*`).

use super::*;
/// §123 chip 6, NZB bytes-skew: the per-segment `bytes` attribute is
/// the poster's own claim, and indexers routinely get it wrong (raw
/// vs encoded size, off-by-headers, stale repost geometry). Every
/// consumer - plan offsets, progress totals, the §118 volume-size
/// declaration that can demote one-pass - must treat it as advisory:
/// a skewed declaration may cost the one-pass fast path, but it must
/// never corrupt output or fail a job whose actual articles are all
/// present and healthy. Declarations here run 0.5x, 1.7x and honest
/// in rotation, so both understatement (the §118 trip direction) and
/// overstatement are on the wire in one run.
#[tokio::test(flavor = "multi_thread")]
async fn skewed_declared_bytes_still_complete_byte_perfect() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (mut fx, inner, _vols) = rar_release("skew", true);
    let mut i = 0usize;
    for (_, segs) in fx.nzb_files.iter_mut() {
        for (_, bytes, _) in segs.iter_mut() {
            *bytes = match i % 3 {
                0 => (*bytes / 2).max(1),
                1 => *bytes + *bytes * 7 / 10,
                _ => *bytes,
            };
            i += 1;
        }
    }
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed on skewed declarations:\n{log}");
    let extracted = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(
        extracted, inner,
        "declared-bytes skew must never change the output bytes"
    );
}

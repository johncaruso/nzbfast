//! System benchmark (design: M15): measure the three download bottlenecks
//! - network, compute, disk - and report the fastest download speed the
//! machine could sustain, plus which stage limits it and what to change.
//!
//! Also: per-server benchmarks and an infrastructure-overlap detector.
//! Two Usenet servers on the SAME backbone share takedowns and missing
//! articles, so they add capacity but NOT recovery diversity. We STAT a
//! shared article sample on every server and cluster servers whose
//! missing-article vectors agree - telling the user which providers are
//! redundant and which genuinely widen coverage.

use std::sync::Arc;

/// Whether this CPU has hardware AES, which decides which AEAD the TLS
/// connection pins (see `nntp::tls_provider`). Duplicated as a `pub`
/// here so the CPU bench can measure the suite the download path will
/// actually negotiate rather than a guess.
pub fn hw_aes() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Name of the AEAD a TLS connection will use on this CPU.
pub fn tls_aead_name() -> &'static str {
    if hw_aes() { "tls aead AES-128-GCM" } else { "tls aead ChaCha20" }
}

/// Run the negotiated TLS AEAD over `p` in 16 KB TLS records, using
/// rustls' own provider (aws-lc-rs) so the number matches the download
/// path. Every downloaded byte is decrypted, so this belongs in the
/// per-byte budget alongside md5 and yEnc decode - and on a weak core it
/// is a large share of it.
///
/// Seals rather than opens: `open_in_place` consumes its ciphertext, so
/// a throughput loop would have to re-seal anyway, and for GCM and
/// ChaCha20-Poly1305 the two directions are the same work.
pub fn tls_aead_seal(p: &[u8]) {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
    let alg = if hw_aes() {
        &aws_lc_rs::aead::AES_128_GCM
    } else {
        &aws_lc_rs::aead::CHACHA20_POLY1305
    };
    let key = LessSafeKey::new(UnboundKey::new(alg, &[0x5au8; 32][..alg.key_len()]).unwrap());
    const REC: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(REC + 32);
    for c in p.chunks(REC) {
        buf.clear();
        buf.extend_from_slice(c);
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::empty(),
            &mut buf,
        )
        .expect("seal");
        std::hint::black_box(&buf);
    }
}
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use md5::{Digest, Md5};

use crate::config::ServerConfig;
use crate::nntp::Connection;

/// OVER returns message-ids already angle-bracketed; NZB segments do not.
/// Normalize to exactly one bracket pair for STAT/BODY.
pub fn bracket_id(id: &str) -> String {
    let t = id.trim().trim_start_matches('<').trim_end_matches('>');
    format!("<{t}>")
}

/// GB/s of a compute stage, single-core and all-core.
#[derive(Clone, Copy, serde::Serialize)]
pub struct StageRate {
    pub one_core: f64,
    pub all_core: f64,
}

#[derive(Clone, serde::Serialize)]
pub struct ComputeReport {
    pub cores: usize,
    pub decode_simd: StageRate,
    pub crc32: StageRate,
    pub md5: StageRate,
    /// The binding stage of the pipeline (decode once + verify once).
    pub verify: StageRate,
    /// All-core verify Gbps - the compute ceiling.
    pub ceiling_gbps: f64,
}

/// Run the per-stage compute benchmark. `mb` = payload per stage.
pub fn compute(mb: usize) -> ComputeReport {
    let cores = std::thread::available_parallelism().map_or(8, |n| n.get());
    let bytes = mb * 1024 * 1024;
    let payload: Vec<u8> = (0..bytes)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 11) as u8))
        .collect();
    let part = &payload[..(700 * 1024).min(payload.len())];
    let article = crate::yenc::encode("b.bin", part.len() as u64, Some((1, 2)), 1, part);

    let run = |f: &(dyn Fn(&[u8]) + Sync)| -> StageRate {
        let t0 = Instant::now();
        f(&payload);
        let one = bytes as f64 / t0.elapsed().as_secs_f64() / 1e9;
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..cores {
                s.spawn(|| f(&payload));
            }
        });
        let all = (bytes * cores) as f64 / t0.elapsed().as_secs_f64() / 1e9;
        StageRate { one_core: one, all_core: all }
    };

    let art = article.clone();
    let decode_simd = run(&move |p: &[u8]| {
        for _ in 0..(p.len() / (700 * 1024)).max(1) {
            std::hint::black_box(crate::yenc_simd::decode(&art).ok());
        }
    });
    let crc32 = run(&|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            std::hint::black_box(crc32fast::hash(c));
        }
    });
    let md5 = run(&|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box(d);
        }
    });
    let verify = run(&|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box((d, crc32fast::hash(c)));
        }
    });

    ComputeReport {
        cores,
        decode_simd,
        crc32,
        md5,
        verify,
        ceiling_gbps: verify.all_core * 8.0,
    }
}

/// Sequential write throughput of `dir`'s filesystem, GB/s. Writes+fsyncs
/// `mb` of data to a temp file, then removes it.
pub fn disk_write(dir: &std::path::Path, mb: usize) -> std::io::Result<f64> {
    use std::io::Write;
    let path = dir.join(format!(".nzbfast-diskbench-{}", std::process::id()));
    let block = vec![0xA5u8; 8 << 20];
    let t0 = Instant::now();
    {
        let mut f = std::fs::File::create(&path)?;
        let mut written = 0usize;
        while written < mb << 20 {
            f.write_all(&block)?;
            written += block.len();
        }
        f.sync_all()?;
    }
    let secs = t0.elapsed().as_secs_f64();
    let _ = std::fs::remove_file(&path);
    Ok((mb << 20) as f64 / secs / 1e9)
}

/// Live download-rate probe: fetch `articles` real bodies from one server
/// over `connections` pipelined connections for up to `secs`, return Gbps.
/// Uses the pool so it reflects our actual fetch path.
/// Discover up to `want` fetch-worthy article ids (300 KB–1.2 MB) from
/// the newest headers of `group`. Kept cheap: a few OVER chunks, never a
/// deep scan - a probe must start in seconds even on a slow link.
pub async fn discover_ids(
    server: &ServerConfig,
    group: &str,
    want: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let (mut conn, _) = Connection::connect(server).await?;
    let g = conn.group(group).await?;
    let mut ids = Vec::new();
    let mut high = g.high;
    let mut chunks = 0;
    // Small wants stay cheap (6 chunks); the multi-gig probes ask for
    // thousands of ids and may scan deeper - the loop still exits the
    // moment `want` is reached, so dense groups pay almost nothing extra.
    let max_chunks = (want / 600).clamp(6, 20);
    while ids.len() < want && high > g.low && chunks < max_chunks {
        let from = high.saturating_sub(4_000).max(g.low);
        for e in conn.over(from, high).await? {
            if (300_000..=1_200_000).contains(&e.bytes) && !e.message_id.is_empty() {
                ids.push(bracket_id(&e.message_id));
            }
        }
        chunks += 1;
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    conn.quit().await;
    if ids.is_empty() {
        return Err(format!("no suitably-sized articles found in {group}").into());
    }
    Ok(ids)
}

/// Fetch `ids` from one server with `connections` sockets for `secs`,
/// returning the achieved rate in Gbps.
/// Returns (Gbps over the window, total raw bytes actually transferred -
/// callers bill the latter to the data-usage ledger).
pub async fn timed_fetch(
    server: &ServerConfig,
    ids: Vec<String>,
    connections: usize,
    secs: u64,
) -> (f64, u64) {
    use crate::pool::PoolConfig;
    let cfg = PoolConfig {
        connections,
        window: 4,
        ..PoolConfig::default()
    };
    let (gbps, per, _, _) =
        timed_fetch_multi(vec![(server.clone(), cfg)], ids, usize::MAX, secs).await;
    (gbps, per.first().copied().unwrap_or(0))
}

/// Timed fetch across a whole SERVER SET sharing one work queue - the
/// pool-aggregate measurement ("do my providers together saturate the
/// line?"). Returns (aggregate Gbps, per-server raw bytes, per-server
/// connections still granted at the measure point, supply-exhausted
/// flag), all vecs in input order.
///
/// The rate is bytes over the time the transfer ACTUALLY took, not the
/// nominal window: a fast line drains a fixed id supply in a fraction of
/// the window, and dividing by the full window capped the measured rate
/// at supply/window (East Coast bench box, 5 Gbps: "0.24 Gbps - network is your
/// limit" on a path that does 3+ Gbps in real downloads). When the
/// exhausted flag is true the rate is real but slightly LOW - the
/// connect/TLS ramp is inside the measured span - so callers wanting
/// precision should hand in a supply sized to outlast the window.
pub async fn timed_fetch_multi(
    mut servers: Vec<(ServerConfig, crate::pool::PoolConfig)>,
    mut ids: Vec<String>,
    max_ids: usize,
    secs: u64,
) -> (f64, Vec<u64>, Vec<usize>, bool) {
    use crate::pool::{FetchOutcome, LiveStats, QueueControl, fetch_all_multi_ctl};
    // Live gauges so the caller can see how many sockets the provider
    // actually accepted (asked ≠ granted near account limits).
    let live = LiveStats::for_servers(&servers);
    for (_, cfg) in servers.iter_mut() {
        cfg.live = Some(live.clone());
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FetchOutcome>(256);
    let bytes = Arc::new(AtomicU64::new(0));
    let bytes2 = bytes.clone();
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(secs);
    // Nanos-since-t0 of the last in-window completion: the denominator
    // when the queue runs dry early (excludes the QUIT/teardown tail).
    let last_done_ns = Arc::new(AtomicU64::new(0));
    let last_done_ns2 = last_done_ns.clone();
    let consumer = tokio::spawn(async move {
        while let Some(o) = rx.recv().await {
            if let FetchOutcome::Done { raw, .. } = o {
                let now = Instant::now();
                if now < deadline {
                    bytes2.fetch_add(raw.len() as u64, Ordering::Relaxed);
                    last_done_ns2.store((now - t0).as_nanos() as u64, Ordering::Relaxed);
                }
            }
        }
    });
    // Cap the id list so fetch_all returns near the window.
    ids.truncate(max_ids.max(64));
    let n_servers = servers.len();
    let reqs: Vec<crate::pool::ArticleReq> =
        ids.into_iter().map(crate::pool::ArticleReq::fresh).collect();
    // Stop via QueueControl at the deadline: aborting the outer future
    // instead LEAKED the spawned workers, which kept downloading and
    // strangled every later ladder step's measurement.
    let ctl = Arc::new(QueueControl::default());
    let ctl2 = ctl.clone();
    let mut handle =
        tokio::spawn(async move { fetch_all_multi_ctl(&servers, reqs, tx, Some(&ctl2)).await });
    // Track peak granted sockets while the fetch runs: when the queue
    // drains early the workers are already gone by the measure point, and
    // a point sample would read 0.
    let peaks: Vec<Arc<std::sync::atomic::AtomicUsize>> =
        live.servers.iter().map(|_| Arc::new(std::sync::atomic::AtomicUsize::new(0))).collect();
    let live2 = live.clone();
    let peaks2 = peaks.clone();
    let sampler = tokio::spawn(async move {
        loop {
            for (s, p) in live2.servers.iter().zip(&peaks2) {
                p.fetch_max(s.connected.load(Ordering::Relaxed), Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    // Wait for the window - or for the queue to drain first, which stops
    // the clock at the real end of the transfer.
    let mut early = None;
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
        r = &mut handle => { early = Some(r.unwrap_or_default()); }
    }
    sampler.abort();
    let exhausted = early.is_some();
    // Granted = sockets live at the measure point (asked ≠ granted near
    // account limits); on early drain, the peak seen during the run.
    let granted: Vec<usize> = if exhausted {
        peaks.iter().map(|p| p.load(Ordering::Relaxed)).collect()
    } else {
        live.servers.iter().map(|s| s.connected.load(Ordering::Relaxed)).collect()
    };
    let stats = match early {
        Some(s) => s,
        None => {
            let _ = tokio::task::spawn_blocking(move || ctl.abort()).await;
            tokio::time::timeout(Duration::from_secs(10), handle)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default()
        }
    };
    let _ = consumer.await;
    let secs_f = if exhausted {
        (last_done_ns.load(Ordering::Relaxed) as f64 / 1e9).max(0.1)
    } else {
        (secs as f64).max(0.1)
    };
    let per: Vec<u64> = if stats.len() == n_servers {
        stats.iter().map(|s| s.bytes).collect()
    } else {
        vec![0; n_servers]
    };
    (bytes.load(Ordering::Relaxed) as f64 * 8.0 / 1e9 / secs_f, per, granted, exhausted)
}

/// Returns (Gbps, raw bytes transferred) - bill the bytes.
pub async fn network_probe(
    server: &ServerConfig,
    group: &str,
    connections: usize,
    secs: u64,
) -> Result<(f64, u64), Box<dyn std::error::Error + Send + Sync>> {
    // Enough ids to keep a ~6 Gbps line busy for the whole window
    // (~600 KB low-end article estimate). Sparse groups return fewer;
    // the early-drain timing in timed_fetch_multi keeps that honest.
    let want = (connections * 60).max(secs as usize * 1250);
    let ids = discover_ids(server, group, want).await?;
    Ok(timed_fetch(server, ids, connections, secs).await)
}

/// One step of a connection ladder: sockets asked for, sockets the
/// provider actually granted (still connected at the measure point), and
/// the achieved rate.
#[derive(Clone, serde::Serialize)]
pub struct LadderStep {
    pub connections: usize,
    pub granted: usize,
    pub gbps: f64,
    /// Raw bytes this step transferred (for the data-usage ledger).
    pub bytes: u64,
    /// The step drained its whole article supply before the window
    /// closed. The rate is still measured over the actual transfer time
    /// (so it's real), but reads slightly low - the connect ramp is
    /// inside the span.
    pub saturated: bool,
}

/// M18: per-server connection tuning - ADAPTIVE: keep doubling the
/// socket count (2, 4, 8, … up to `max_conns`) while the previous step
/// still gained ≥12%, so the knee is found wherever it is - including
/// ABOVE the configured account limit (over-asking is harmless: the
/// provider refuses the extras, workers bow out, and `granted` exposes
/// the real ceiling). Distinct article slices per step so provider-side
/// caching can't flatter the later steps.
pub async fn conn_ladder(
    server: &ServerConfig,
    group: &str,
    max_conns: usize,
    secs_per_step: u64,
) -> Result<Vec<LadderStep>, Box<dyn std::error::Error + Send + Sync>> {
    use crate::pool::PoolConfig;
    let mut ids = discover_ids(server, group, 8_000).await?;
    let mut out: Vec<LadderStep> = Vec::new();
    let mut c = 2usize;
    let mut stopped_flat = false;
    // Articles a step needs to outlast its window, sized from the fastest
    // rate seen so far (×2.5: a doubling step may better-than-double).
    // A fixed connections×40 supply drains in a fraction of the window on
    // a multi-gig line, capping every step at supply/window and reading
    // as a flat ladder (East Coast bench box: identical per-conn rates at 2 and 4).
    let supply_for = |peak_gbps: f64, conns: usize| -> usize {
        let by_rate =
            (peak_gbps.max(0.05) * 2.5 * secs_per_step as f64 * 1e9 / 8.0 / 600_000.0) as usize;
        (conns * 40).max(by_rate).max(64)
    };
    loop {
        let c_now = c.min(max_conns.max(2));
        let peak = out.iter().map(|s| s.gbps).fold(0.0, f64::max);
        let want = supply_for(peak, c_now);
        let per_step = want.min(ids.len());
        let slice: Vec<String> = ids[..per_step].to_vec();
        // Rotate so the next step reads different articles.
        let rot = per_step.min(ids.len().saturating_sub(1));
        ids.rotate_left(rot);
        let cfg = PoolConfig { connections: c_now, window: 4, ..PoolConfig::default() };
        let (gbps, per, granted, saturated) =
            timed_fetch_multi(vec![(server.clone(), cfg)], slice, per_step, secs_per_step).await;
        out.push(LadderStep {
            connections: c_now,
            granted: granted.first().copied().unwrap_or(0),
            gbps,
            bytes: per.first().copied().unwrap_or(0),
            saturated,
        });
        // The group didn't yield the supply this step wanted AND the step
        // drained it early: the rate is ramp-biased low, so don't let it
        // masquerade as "the doubling stopped paying".
        let last_starved = saturated && per_step < want;
        if c_now >= max_conns {
            break;
        }
        let n = out.len();
        // Stop once a doubling stopped paying (we've tested one step past
        // the knee), or the provider granted well under what we asked.
        if n >= 2 && !last_starved && out[n - 1].gbps <= out[n - 2].gbps * 1.12 {
            stopped_flat = true;
            break;
        }
        if out[n - 1].granted + 2 < c_now {
            break;
        }
        c = c_now * 2;
    }
    // Binary refinement: a doubling bracket overshoots the knee by up to
    // 2× (flat at 16 says the knee is anywhere in 8..16). Bisect between
    // the last gaining step and the flat one - up to two 5 s probes -
    // so the recommendation lands near the true knee.
    if stopped_flat && out.len() >= 2 {
        let peak = out.iter().map(|s| s.gbps).fold(0.0, f64::max);
        let (mut lo, mut hi) =
            (out[out.len() - 2].connections, out[out.len() - 1].connections);
        for _ in 0..2 {
            if hi.saturating_sub(lo) <= (lo / 4).max(2) {
                break;
            }
            let mid = (lo + hi) / 2;
            let per_step = supply_for(peak, mid).min(ids.len());
            let slice: Vec<String> = ids[..per_step].to_vec();
            let rot = per_step.min(ids.len().saturating_sub(1));
            ids.rotate_left(rot);
            let cfg = PoolConfig { connections: mid, window: 4, ..PoolConfig::default() };
            let (gbps, per, granted, saturated) =
                timed_fetch_multi(vec![(server.clone(), cfg)], slice, per_step, secs_per_step)
                    .await;
            out.push(LadderStep {
                connections: mid,
                granted: granted.first().copied().unwrap_or(0),
                gbps,
                bytes: per.first().copied().unwrap_or(0),
                saturated,
            });
            if gbps >= peak * 0.9 {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        out.sort_by_key(|s| s.connections);
    }
    Ok(out)
}

/// The whole-system verdict.
#[derive(serde::Serialize)]
pub struct SystemReport {
    pub network_gbps: f64,
    pub compute_gbps: f64,
    pub disk_gbps: f64,
    pub bottleneck: String,
    /// Expected sustained download speed = min of the three.
    pub expected_gbps: f64,
    pub advice: String,
}

pub fn verdict(network_gbps: f64, compute: &ComputeReport, disk_gbps: f64) -> SystemReport {
    let n = network_gbps;
    let c = compute.ceiling_gbps;
    let d = disk_gbps * 8.0;
    let expected = n.min(c).min(d);
    let (bottleneck, advice) = if expected == n {
        (
            "network",
            "The network is your limit. Add Usenet connections/providers, \
             move to a faster link (2.5/10 GbE), or check for an upstream \
             switch/uplink cap. Compute and disk have headroom."
                .to_string(),
        )
    } else if expected == c {
        (
            "compute",
            format!(
                "CPU verification is your limit ({:.0} Gbps). Rare - only \
                 on very fast links. A faster CPU, or a CRC32-only \
                 fast-verify mode, would raise it.",
                c
            ),
        )
    } else {
        (
            "disk",
            format!(
                "Disk write is your limit ({:.1} GB/s). Use an NVMe/SSD \
                 target, or a faster volume; network and CPU have headroom.",
                disk_gbps
            ),
        )
    };
    SystemReport {
        network_gbps: n,
        compute_gbps: c,
        disk_gbps: d,
        bottleneck: bottleneck.to_string(),
        expected_gbps: expected,
        advice,
    }
}

// ---------------------------------------------------------------------------
// Server diversity / overlap detector
// ---------------------------------------------------------------------------

/// Per-server result of the overlap sweep.
#[derive(Clone, serde::Serialize)]
pub struct ServerProbe {
    pub host: String,
    pub connect_ok: bool,
    pub rtt_ms: f64,
    /// Fraction of the shared sample this server HAD (0..1).
    pub availability: f64,
    /// Solo download rate, Gbps (short probe).
    pub speed_gbps: f64,
    /// Raw bytes the speed probe transferred (for the usage ledger).
    pub bytes: u64,
}

/// One pair's infra-overlap score.
#[derive(Clone, serde::Serialize)]
pub struct OverlapPair {
    pub a: String,
    pub b: String,
    /// Jaccard similarity of the two servers' MISSING-article sets over
    /// the shared sample (1.0 = identical gaps = same backbone).
    pub missing_jaccard: f64,
    /// Correlation verdict for the UI.
    pub verdict: String,
}

#[derive(serde::Serialize)]
pub struct DiversityReport {
    pub servers: Vec<ServerProbe>,
    pub pairs: Vec<OverlapPair>,
    pub recommendation: String,
}

/// STAT a shared article sample on every server; per-server availability
/// vectors reveal which providers share infrastructure (identical gaps).
///
/// `sample_ids` should span a range of ages (recent + old) so takedowns
/// and retention differences actually show up. Returns a per-server
/// present/absent bit vector alongside the probes.
pub async fn diversity(
    servers: &[ServerConfig],
    sample_ids: &[String],
    group: &str,
) -> DiversityReport {
    let _ = group; // speed probes reuse the shared sample now
    // Phase 1: STAT sweeps run CONCURRENTLY - they're latency-bound and
    // independent, so wall time is the slowest server, not the sum (the
    // sequential version blew the API's 60 s cap on slow links).
    let t_sweeps = Instant::now();
    // collect() eagerly: a lazy map would spawn each sweep only when the
    // join loop reaches it - sequential again.
    let sweeps: Vec<_> = servers.iter().map(|s| {
        let s = s.clone();
        let ids: Vec<String> = sample_ids.to_vec();
        tokio::spawn(async move {
            let n = ids.len();
            // Whole-sweep hard cap: send/flush have no per-op timeouts, so
            // one black-holed connection would otherwise hang its task (and
            // the whole report) forever.
            let swept = tokio::time::timeout(Duration::from_secs(45), async move {
                let t0 = Instant::now();
                let mut vec = vec![false; ids.len()];
                let mut connect_ok = false;
                let mut rtt = 0.0;
                let mut had = 0usize;
                if let Ok(Ok((mut conn, _))) =
                    tokio::time::timeout(Duration::from_secs(12), Connection::connect(&s)).await
                {
                    connect_ok = true;
                    rtt = t0.elapsed().as_secs_f64() * 1000.0;
                    // Pipelined STAT sweep.
                    let window = 40usize;
                    let mut sent = 0;
                    let mut recv = 0;
                    'sweep: while recv < ids.len() {
                        while sent < ids.len() && sent - recv < window {
                            if conn.send_stat(&ids[sent]).await.is_err() {
                                break 'sweep;
                            }
                            sent += 1;
                        }
                        if conn.flush().await.is_err() {
                            break;
                        }
                        match tokio::time::timeout(Duration::from_secs(20), conn.read_stat()).await
                        {
                            Ok(Ok(has)) => {
                                vec[recv] = has;
                                if has {
                                    had += 1;
                                }
                                recv += 1;
                            }
                            _ => break,
                        }
                    }
                    conn.quit().await;
                }
                (connect_ok, rtt, had, vec)
            })
            .await;
            swept.unwrap_or((false, 0.0, 0, vec![false; n]))
        })
    }).collect();
    let mut sweep_results = Vec::new();
    for h in sweeps {
        sweep_results.push(h.await.unwrap_or((false, 0.0, 0, vec![false; sample_ids.len()])));
    }
    println!(
        "[diversity] STAT sweeps done in {:.1}s ({} servers × {} ids)",
        t_sweeps.elapsed().as_secs_f64(),
        servers.len(),
        sample_ids.len()
    );

    // Phase 2: short solo speed probes, SEQUENTIAL so they don't contend
    // for the line, fetching from the shared sample this server was just
    // seen to HAVE (no per-server OVER discovery - that alone used to
    // cost more than the probe).
    let t_probes = Instant::now();
    let mut probes = Vec::new();
    let mut present: Vec<Vec<bool>> = Vec::new(); // [server][article] = had it
    for (s, (connect_ok, rtt, had, vec)) in servers.iter().zip(sweep_results) {
        let (speed, probe_bytes) = if connect_ok {
            let have: Vec<String> = sample_ids
                .iter()
                .zip(&vec)
                .filter(|&(_, &h)| h)
                .map(|(id, _)| id.clone())
                .collect();
            if have.is_empty() { (0.0, 0) } else { timed_fetch(s, have, 8, 4).await }
        } else {
            (0.0, 0)
        };
        probes.push(ServerProbe {
            host: s.host.clone(),
            connect_ok,
            rtt_ms: rtt,
            availability: had as f64 / sample_ids.len().max(1) as f64,
            speed_gbps: speed,
            bytes: probe_bytes,
        });
        present.push(vec);
    }
    println!("[diversity] speed probes done in {:.1}s", t_probes.elapsed().as_secs_f64());

    // Pairwise MISSING-set Jaccard: over the shared sample, articles this
    // server lacked. High overlap of gaps ⇒ same infra.
    let mut pairs = Vec::new();
    for i in 0..servers.len() {
        for j in (i + 1)..servers.len() {
            if !probes[i].connect_ok || !probes[j].connect_ok {
                continue;
            }
            let (mut inter, mut union) = (0usize, 0usize);
            for k in 0..sample_ids.len() {
                let mi = !present[i][k];
                let mj = !present[j][k];
                if mi || mj {
                    union += 1;
                }
                if mi && mj {
                    inter += 1;
                }
            }
            let jac = if union == 0 { 0.0 } else { inter as f64 / union as f64 };
            let verdict = if jac >= 0.8 {
                "SAME infra - redundant for recovery (share takedowns/gaps)"
            } else if jac >= 0.4 {
                "partial overlap - some shared backbone"
            } else {
                "diverse - independent gaps, good recovery pairing"
            };
            pairs.push(OverlapPair {
                a: servers[i].host.clone(),
                b: servers[j].host.clone(),
                missing_jaccard: jac,
                verdict: verdict.to_string(),
            });
        }
    }

    // Recommendation: flag redundant clusters, praise diversity.
    let redundant: Vec<String> = pairs
        .iter()
        .filter(|p| p.missing_jaccard >= 0.8)
        .map(|p| format!("{} ≈ {}", p.a, p.b))
        .collect();
    let recommendation = if redundant.is_empty() {
        "Your providers have diverse infrastructure - good article recovery \
         coverage. Keep them all."
            .to_string()
    } else {
        format!(
            "Redundant (same backbone, won't help recover each other's \
             missing articles): {}. For maximum recovery, keep one of each \
             cluster and add a provider on a different backbone.",
            redundant.join(", ")
        )
    };

    DiversityReport {
        servers: probes,
        pairs,
        recommendation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_report_is_sane() {
        let r = compute(16);
        assert!(r.cores >= 1);
        // SIMD decode must beat MD5 (it does in reality by ~5×).
        assert!(r.decode_simd.all_core > r.md5.all_core);
        assert!(r.ceiling_gbps > 0.0);
    }

    #[test]
    fn disk_write_measures() {
        let d = std::env::temp_dir();
        let gbps = disk_write(&d, 64).unwrap();
        assert!(gbps > 0.0 && gbps < 1000.0);
    }

    /// `verdict` is arithmetic - it picks the min of three numbers - so the
    /// compute figure is STATED here, not measured.
    ///
    /// It used to call `compute(16)`, which benchmarks this machine for real,
    /// and the test then assumed the answer would land above the 1.0 Gbps
    /// network figure it was comparing against. On a debug build that is not
    /// a safe assumption: the compute kernels are unoptimized, and on Windows
    /// x64 the measured ceiling came in UNDER 1.0, so `verdict` correctly
    /// answered "compute" and the test called it a failure. It was asserting
    /// the host was fast, not that the min-picking works. A stated ceiling
    /// tests the logic on every machine and takes ~16 MB of benchmarking per
    /// run out of the suite.
    #[test]
    fn verdict_picks_min() {
        let flat = StageRate { one_core: 1.0, all_core: 8.0 };
        let c = ComputeReport {
            cores: 8,
            decode_simd: flat,
            crc32: flat,
            md5: flat,
            verify: flat,
            ceiling_gbps: 40.0,
        };
        // Network tiny → network is the bottleneck.
        let v = verdict(1.0, &c, 5.0);
        assert_eq!(v.bottleneck, "network");
        assert!((v.expected_gbps - 1.0).abs() < 1e-9);
        // Disk tiny (0.05 GB/s = 0.4 Gbps) → disk bottleneck.
        let v = verdict(50.0, &c, 0.05);
        assert_eq!(v.bottleneck, "disk");
        // ...and compute when it is genuinely the floor, which the measured
        // version could never pin because it did not know its own value.
        let v = verdict(50.0, &c, 100.0);
        assert_eq!(v.bottleneck, "compute");
        assert!((v.expected_gbps - 40.0).abs() < 1e-9);
    }

    /// Regression (East Coast bench box, 5 Gbps): a fixed article supply drained in
    /// well under the timing window and the rate was still divided by the
    /// FULL window - sysbench reported "0.24 Gbps, network is your limit"
    /// on a path that does 3+ Gbps, and every connladder step read the
    /// same per-conn rate. When the queue runs dry early, the clock must
    /// stop at the last completion and the step must be flagged.
    #[tokio::test(flavor = "multi_thread")]
    async fn exhausted_supply_measures_actual_transfer_time() {
        let mut articles = std::collections::HashMap::new();
        let data: Vec<u8> = (0..400_000u32).map(|i| i as u8).collect();
        let segs =
            crate::mock::make_file_articles("t.bin", &data, 20_000, "sb", &mut articles);
        let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
        let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        let cfg = crate::pool::PoolConfig {
            connections: 2,
            window: 4,
            ramp_delay: Duration::from_millis(0),
            ..Default::default()
        };
        const WINDOW: u64 = 30; // loopback drains the supply in ms
        let t0 = Instant::now();
        let (gbps, per, _granted, exhausted) =
            timed_fetch_multi(vec![(srv.server_config(), cfg)], ids, usize::MAX, WINDOW).await;
        let took = t0.elapsed();
        assert!(exhausted, "tiny supply must be flagged exhausted");
        assert!(
            took < Duration::from_secs(WINDOW / 2),
            "must return when the queue drains, not sleep out the window (took {took:?})"
        );
        // The old bug: bytes / full-window. The fix must beat that cap by
        // a wide margin because the drain took milliseconds, not 30 s.
        let capped = per[0] as f64 * 8.0 / 1e9 / WINDOW as f64;
        assert!(
            gbps > capped * 10.0,
            "rate must reflect actual drain time, not the window ({gbps} vs capped {capped})"
        );
    }

    #[test]
    fn diversity_math_on_synthetic_vectors() {
        // Not a network test - verify the Jaccard/verdict logic directly.
        // 3 "servers": A,B identical gaps; C independent.
        let present = [
            vec![true, false, true, false, true, false],  // A: missing idx 1,3,5
            vec![true, false, true, false, true, false],  // B: same
            vec![false, true, true, true, false, true],   // C: missing 0,4
        ];
        let jac = |x: &[bool], y: &[bool]| {
            let (mut i, mut u) = (0, 0);
            for k in 0..x.len() {
                let (mx, my) = (!x[k], !y[k]);
                if mx || my {
                    u += 1;
                }
                if mx && my {
                    i += 1;
                }
            }
            i as f64 / u as f64
        };
        assert!((jac(&present[0], &present[1]) - 1.0).abs() < 1e-9); // identical
        assert!(jac(&present[0], &present[2]) < 0.4); // diverse
    }
}

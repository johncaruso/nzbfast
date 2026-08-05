//! Standalone chaos NNTP server for the TODO 111 fault matrix: wraps
//! `nzbkit::mock` (the in-process chaos mock the payout rigs run
//! against) in a runnable server so EXTERNAL clients - nzbfast's own
//! CLI, NZBGet, SABnzbd, rustnzb, Weaver - can be raced against the
//! same fault shapes on loopback. Generates a deterministic corpus of
//! a few hundred MB, writes the matching .nzb, and serves it with a
//! fault profile chosen by flag. Two-server profiles (one faulty + one
//! clean twin, the shape the pool.rs payout rigs use) bind a second
//! port, so in-process numbers and standalone numbers stay comparable.
//!
//! Fault onset is logged with wall-clock timestamps, and a progress
//! line (bodies served / bytes moved per tick) is printed per server,
//! so recovery time (onset -> throughput restored) is measurable from
//! this log alone, whatever the client under test exposes.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, anyhow, bail};
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};

/// One corpus file's NZB ingredients.
struct CorpusFile {
    name: String,
    /// (message-id sans brackets, encoded size, part number)
    segs: Vec<(String, u64, u32)>,
}

pub struct Opts {
    pub profile: String,
    pub bind: String,
    pub port: u16,
    /// Clean-twin port for the two-server profiles.
    pub port2: u16,
    /// Total corpus payload bytes.
    pub size: u64,
    pub files: u32,
    pub article_size: usize,
    pub nzb: PathBuf,
    /// Shifts the deterministic fault positions (same seed = same
    /// faulted ids, the fairness requirement across clients).
    pub seed: u64,
    /// Per-connection cap on the healthy path, bytes/sec.
    pub per_conn_bps: u64,
    /// Whole-server line cap, bytes/sec (0 = per-connection only).
    pub line_bps: u64,
    /// External `par2 create -r<pct>` over the corpus (needs a par2
    /// binary; the recovery volumes join the corpus and the NZB).
    pub par2_redundancy: Option<u32>,
    /// Override the profile's faulted-article count (deadair/corrupt).
    pub fault_count: Option<usize>,
    /// Real files to article-ize into the corpus alongside the
    /// generated ones (a playable video makes the rig a playback
    /// end-to-end fixture; --files 0 serves only these).
    pub media: Vec<PathBuf>,
}

/// What one profile does to each server. `label` feeds the log lines.
struct Plan {
    chaos: Chaos,
    /// Second server (clean twin) - None for single-server profiles.
    twin: Option<Chaos>,
    /// Human line printed at startup describing the fault and when it
    /// engages, so the run log is self-describing.
    onset_note: String,
    /// Body count at which a threshold fault engages (brownout); the
    /// monitor logs the exact onset timestamp when served crosses it.
    onset_after_bodies: Option<u64>,
}

pub const PROFILES: &[&str] = &[
    "clean",
    "flap",
    "deadair",
    "deadair-dial",
    "brownout",
    "jitter",
    "jitter-dial",
    "corrupt",
    "corruptstorm",
    "splitbrain",
    "slowconn",
];

/// The `-dial` profile variants' per-connection greeting delay (TODO
/// 115): every fresh connection pays this before the server says 200,
/// approximating a real TCP+TLS+AUTH dial on loopback - so a strategy
/// that recovers by reconnecting pays its real-world cost on the rig
/// instead of redialing for free (NZBGet's flap "win" is 217 free
/// loopback dials; a provider would refuse that hammering).
const DIAL_COST_MS: u64 = 250;

/// Deterministic corpus bytes: same generator family as mockserv, mixed
/// with the seed so distinct seeds give distinct (but reproducible) data.
fn corpus_data(len: usize, seed: u64) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            (i.wrapping_add(seed.wrapping_mul(0x9E3779B97F4A7C15))
                .wrapping_mul(2654435761)
                >> 16) as u8
        })
        .collect()
}

/// Evenly spread `count` positions across the middle of `n` articles
/// (30%..90% of the queue), so faults bite mid-run with healthy history
/// behind them - the placement the payout rigs use. Seed shifts phase.
fn spread_positions(n: usize, count: usize, seed: u64) -> Vec<usize> {
    if n == 0 || count == 0 {
        return Vec::new();
    }
    let lo = n * 3 / 10;
    let hi = n * 9 / 10;
    let span = (hi - lo).max(1);
    let count = count.min(span);
    let step = (span / count).max(1);
    let phase = (seed as usize) % step;
    (0..count)
        .map(|k| lo + (k * step + phase) % span)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

fn ts() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

fn say(msg: &str) {
    println!("CHAOS {} {msg}", ts());
    let _ = std::io::stdout().flush();
}

/// Write the multi-file NZB for the corpus.
fn write_nzb(path: &Path, files: &[CorpusFile]) -> Result<()> {
    let mut nzb = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for f in files {
        nzb.push_str(&format!(
            "<file poster=\"chaos@bench.local\" date=\"1750000000\" \
             subject=\"&quot;{}&quot; yEnc (1/{})\">\n\
             <groups><group>alt.binaries.bench</group></groups>\n<segments>\n",
            f.name,
            f.segs.len()
        ));
        for (id, bytes, number) in &f.segs {
            nzb.push_str(&format!(
                "<segment bytes=\"{bytes}\" number=\"{number}\">{id}</segment>\n"
            ));
        }
        nzb.push_str("</segments>\n</file>\n");
    }
    nzb.push_str("</nzb>\n");
    std::fs::write(path, nzb).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Run external `par2 create` over the corpus files and article-ize the
/// resulting volumes into the same corpus.
fn add_par2(
    redundancy: u32,
    payloads: &[(String, Vec<u8>)],
    article_size: usize,
    articles: &mut HashMap<String, Vec<u8>>,
    corpus: &mut Vec<CorpusFile>,
) -> Result<()> {
    let bin = std::env::var("PAR2_BIN").unwrap_or_else(|_| "par2".into());
    let dir = std::env::temp_dir().join(format!("chaosserv-par2-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    for (name, data) in payloads {
        std::fs::write(dir.join(name), data)?;
    }
    let mut cmd = std::process::Command::new(&bin);
    cmd.current_dir(&dir)
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg("-qq")
        .arg("chaos.par2");
    for (name, _) in payloads {
        cmd.arg(name);
    }
    let st = cmd
        .status()
        .with_context(|| format!("run {bin} create (set PAR2_BIN to the binary)"))?;
    if !st.success() {
        bail!("{bin} create failed with {st}");
    }
    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "par2"))
        .collect();
    vols.sort();
    for (i, vol) in vols.iter().enumerate() {
        let name = vol
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("non-utf8 par2 name"))?
            .to_string();
        let data = std::fs::read(vol)?;
        let segs = make_file_articles(&name, &data, article_size, &format!("chp{i}"), articles);
        corpus.push(CorpusFile { name, segs });
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The profile table. Shapes and ratios mirror the pool.rs payout rigs
/// (flap = payout_flap_breaker_collapses_ip_cap_churn, brownout =
/// payout_brownout_recovery_across_config_tiers, deadair =
/// payout_adaptive_timeout_cuts_dead_air_stalls, jitter =
/// safety_adaptive_timeout_kills_nothing_on_a_jittery_link, slowconn =
/// payout_slope_recycle_frees_a_degraded_session), scaled from the
/// rigs' tens-of-KB/s throttles to MB/s so a few-hundred-MB corpus
/// finishes in minutes.
fn plan(
    profile: &str,
    all_ids: &[String],
    per_conn_bps: u64,
    line_bps: u64,
    seed: u64,
    fault_count: Option<usize>,
) -> Result<Plan> {
    let healthy = Throttle {
        per_conn_bps,
        line_bps,
        ..Default::default()
    };
    let n = all_ids.len();
    let base = Chaos {
        throttle: healthy.clone(),
        ..Default::default()
    };
    // The clean twin: healthy throttle, no faults.
    let clean_twin = Chaos {
        throttle: healthy.clone(),
        ..Default::default()
    };
    Ok(match profile {
        "clean" => Plan {
            chaos: base,
            twin: None,
            onset_note: "clean baseline - no fault".into(),
            onset_after_bodies: None,
        },
        // The eweka shape: 2 sessions win, the rest bounce off a 502
        // cap refusal, and each winner dies after one body at a crawl.
        // Rig ratio 60k:150k burned:steady = 0.4x healthy rate.
        "flap" => Plan {
            chaos: Chaos {
                accept_cap: Some(2),
                drop_after: 1,
                throttle: Throttle {
                    per_conn_bps: (per_conn_bps * 2) / 5,
                    line_bps,
                    ..Default::default()
                },
                ..Default::default()
            },
            twin: Some(clean_twin),
            onset_note: "flap: accept_cap=2 + drop_after=1 on the faulty server, \
                         structural from t0; clean twin on port2"
                .into(),
            onset_after_bodies: None,
        },
        "deadair" | "deadair-dial" => {
            let dial = profile.ends_with("-dial");
            let count = fault_count.unwrap_or(12);
            let stall_pre: HashSet<String> = spread_positions(n, count, seed)
                .into_iter()
                .map(|i| all_ids[i].clone())
                .collect();
            let note = format!(
                "deadair{}: {} articles hang before the status line on their \
                 first request (retries succeed); spread mid-queue{}",
                if dial { "-dial" } else { "" },
                stall_pre.len(),
                if dial {
                    format!("; every new connection pays a {DIAL_COST_MS} ms greeting delay")
                } else {
                    String::new()
                }
            );
            Plan {
                chaos: Chaos {
                    stall_pre,
                    greet_delay_ms: if dial { DIAL_COST_MS } else { 0 },
                    ..base
                },
                twin: None,
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // Frontend goes mute after 40% of the corpus and never comes
        // back; the clean twin carries the group (rig shape).
        "brownout" => {
            let after = (n as u64 * 2) / 5;
            Plan {
                chaos: Chaos {
                    brownout_after: after,
                    ..base
                },
                twin: Some(clean_twin),
                onset_note: format!(
                    "brownout: faulty server goes mute (dead air, no recovery) \
                     after {after} bodies; clean twin on port2"
                ),
                onset_after_bodies: Some(after),
            }
        }
        // Every 5th body 1.8 s late on a healthy link - the satellite
        // shape. The right client behaviour is to kill nothing.
        "jitter" | "jitter-dial" => {
            let dial = profile.ends_with("-dial");
            Plan {
                chaos: Chaos {
                    jitter: Some((5, 1_800)),
                    greet_delay_ms: if dial { DIAL_COST_MS } else { 0 },
                    ..base
                },
                twin: None,
                onset_note: format!(
                    "jitter{}: every 5th body +1800 ms, structural from t0; \
                     a healthy link - killing sessions here is the failure{}",
                    if dial { "-dial" } else { "" },
                    if dial {
                        format!("; every new connection pays a {DIAL_COST_MS} ms greeting delay")
                    } else {
                        String::new()
                    }
                ),
                onset_after_bodies: None,
            }
        }
        // Bit-rot storm: a spread of articles serve wrong bytes (yEnc
        // CRC fails); a clean twin holds good copies, so re-fetching
        // elsewhere can save the job without repair.
        "corrupt" => {
            let count = fault_count.unwrap_or(n / 10);
            let corrupt: HashSet<String> = spread_positions(n, count, seed)
                .into_iter()
                .map(|i| all_ids[i].clone())
                .collect();
            let note = format!(
                "corrupt: {} articles serve flipped bytes (CRC fails) on the \
                 faulty server, structural from t0; clean twin on port2 holds \
                 good copies",
                corrupt.len()
            );
            Plan {
                chaos: Chaos { corrupt, ..base },
                twin: Some(clean_twin),
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // Server-wide corrupt storm: a broken cache node. Every Nth
        // BODY the faulty server sends (arrival order, retries
        // included) has a flipped byte, so the damage cannot be pinned
        // to specific ids - a retry of the SAME article to the SAME
        // server may come back good or bad. Clean twin holds good
        // copies. Distinct from `corrupt` (fixed per-id set = a damaged
        // POST); this prices whether a retry policy converges under
        // damage it cannot attribute.
        "corruptstorm" => {
            let every = fault_count.map(|c| c as u64).unwrap_or(10).max(2);
            Plan {
                chaos: Chaos {
                    corrupt_every: every,
                    ..base
                },
                twin: Some(clean_twin),
                onset_note: format!(
                    "corruptstorm: every {every}th body served by the faulty \
                     server has a flipped byte (CRC fails), retries included, \
                     structural from t0; clean twin on port2 holds good copies"
                ),
                onset_after_bodies: None,
            }
        }
        // Split-brain: the faulty server's storage backend is
        // mismatched - a request for one id is answered with ANOTHER
        // article's fully valid bytes, in bidirectional pairs. The yEnc
        // CRC PASSES; only the article's declared identity (part
        // number) betrays it. The live "downloads complete but never
        // verify" class. Clean twin holds true copies. A size gate
        // cannot see this; the hash gate is mandatory.
        "splitbrain" => {
            let count = fault_count.unwrap_or(n / 10);
            let mut picks = spread_positions(n, count, seed);
            picks.sort_unstable();
            let mut swap = HashMap::new();
            for pair in picks.chunks(2) {
                if let [a, b] = pair {
                    swap.insert(all_ids[*a].clone(), all_ids[*b].clone());
                    swap.insert(all_ids[*b].clone(), all_ids[*a].clone());
                }
            }
            let note = format!(
                "splitbrain: {} articles served as {} swapped pairs (right id, \
                 wrong article's bytes, yEnc CRC passes) on the faulty server, \
                 structural from t0; clean twin on port2 holds true copies",
                swap.len(),
                swap.len() / 2
            );
            Plan {
                chaos: Chaos { swap, ..base },
                twin: Some(clean_twin),
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // One degraded TCP session on an otherwise healthy server: the
        // 3rd accepted connection crawls at 1/40th of the healthy rate;
        // a reconnect gets a fresh, healthy session (rig shape).
        "slowconn" => Plan {
            chaos: Chaos {
                slow_conn: Some((3, (per_conn_bps / 40).max(10_000))),
                ..base
            },
            twin: None,
            onset_note: format!(
                "slowconn: the 3rd accepted connection is capped to {} B/s; \
                 every other (re)connect is healthy",
                (per_conn_bps / 40).max(10_000)
            ),
            onset_after_bodies: None,
        },
        other => bail!("unknown profile {other:?}; one of {}", PROFILES.join("|")),
    })
}

pub async fn run(opts: Opts) -> Result<()> {
    // ---- corpus ----
    let per_file = (opts.size / opts.files.max(1) as u64) as usize;
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let mut corpus: Vec<CorpusFile> = Vec::new();
    let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
    say(&format!(
        "generating corpus: {} files x {:.1} MB, {} B articles, seed {}",
        opts.files,
        per_file as f64 / 1e6,
        opts.article_size,
        opts.seed
    ));
    for i in 0..opts.files {
        let name = format!("chaos-{:02}.bin", i + 1);
        let data = corpus_data(per_file, opts.seed.wrapping_add(i as u64));
        let segs = make_file_articles(
            &name,
            &data,
            opts.article_size,
            &format!("chs{}s{i}", opts.seed),
            &mut articles,
        );
        corpus.push(CorpusFile {
            name: name.clone(),
            segs,
        });
        payloads.push((name, data));
    }
    for (i, path) in opts.media.iter().enumerate() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("--media path has no file name: {}", path.display()))?;
        let data =
            std::fs::read(path).with_context(|| format!("read --media {}", path.display()))?;
        say(&format!(
            "media file: {} ({:.1} MB) joins the corpus",
            name,
            data.len() as f64 / 1e6
        ));
        let segs = make_file_articles(
            &name,
            &data,
            opts.article_size,
            &format!("chm{}m{i}", opts.seed),
            &mut articles,
        );
        corpus.push(CorpusFile {
            name: name.clone(),
            segs,
        });
        payloads.push((name, data));
    }
    if let Some(r) = opts.par2_redundancy {
        say(&format!(
            "par2: creating recovery volumes at {r}% redundancy"
        ));
        add_par2(r, &payloads, opts.article_size, &mut articles, &mut corpus)?;
    }
    drop(payloads);
    // Fault selection walks the NZB's own article order.
    let all_ids: Vec<String> = corpus
        .iter()
        .flat_map(|f| f.segs.iter().map(|(id, _, _)| format!("<{id}>")))
        .collect();
    write_nzb(&opts.nzb, &corpus)?;
    say(&format!(
        "corpus: {} articles, {:.1} MB payload; nzb at {}",
        all_ids.len(),
        opts.size as f64 / 1e6,
        opts.nzb.display()
    ));

    // ---- servers ----
    let plan = plan(
        &opts.profile,
        &all_ids,
        opts.per_conn_bps,
        opts.line_bps,
        opts.seed,
        opts.fault_count,
    )?;
    let twin_articles = plan.twin.is_some().then(|| articles.clone());
    let faulty = MockServer::start_bound(
        &format!("{}:{}", opts.bind, opts.port),
        articles,
        HashMap::new(),
        Vec::new(),
        plan.chaos,
    )
    .await;
    say(&format!(
        "profile {} serving on {} [{}]",
        opts.profile,
        faulty.addr,
        if plan.twin.is_some() {
            "faulty"
        } else {
            "single"
        }
    ));
    let twin = match plan.twin {
        Some(chaos) => {
            let t = MockServer::start_bound(
                &format!("{}:{}", opts.bind, opts.port2),
                twin_articles.unwrap_or_default(),
                HashMap::new(),
                Vec::new(),
                chaos,
            )
            .await;
            say(&format!("clean twin serving on {} [clean]", t.addr));
            Some(t)
        }
        None => None,
    };
    say(&format!("ONSET-PLAN {}", plan.onset_note));

    // ---- monitor: onset + throughput timeline ----
    let mut onset_logged = plan.onset_after_bodies.is_none();
    let mut last = (0u64, 0u64, 0u64); // served faulty, served twin, accepted faulty
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let sf = faulty.served.load(Ordering::Relaxed);
        let af = faulty.accepted.load(Ordering::Relaxed);
        let st = twin
            .as_ref()
            .map_or(0, |t| t.served.load(Ordering::Relaxed));
        if !onset_logged
            && let Some(th) = plan.onset_after_bodies
            && sf >= th
        {
            say(&format!("ONSET fault engaged after {sf} bodies"));
            onset_logged = true;
        }
        if (sf, st, af) != (last.0, last.1, last.2) {
            say(&format!(
                "tick faulty: served={sf} (+{}) accepted={af} · twin: served={st} (+{})",
                sf - last.0,
                st - last.1
            ));
            last = (sf, st, af);
        }
    }
}

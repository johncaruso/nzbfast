//! The pre-flight check command: probes every server for segment availability and renders the Verdict the get command's --preflight consumes.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use std::path::Path;

// ---------------------------------------------------------------------------
// check - pre-flight availability (M2): STAT sweep + verdict
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Complete,
    Repairable { est_missing: usize, recovery: usize },
    Impossible { est_missing: usize, recovery: usize },
}

pub(crate) async fn check(
    config: &Path,
    nzb_path: &Path,
    sample_pct: u8,
    connections: usize,
    window: usize,
) -> Result<Verdict> {
    use nzbkit::preflight::{stat_sweep, stratified_sample};

    let cfg_all = Config::load(config)?;
    let xml = std::fs::read(nzb_path).with_context(|| format!("reading {}", nzb_path.display()))?;
    let nzb = Nzb::parse(&xml).context("parsing NZB")?;

    // Sampled ids from DATA + par2-main files (recovery volumes count via
    // the recovery budget, not the deficit) + per-id weight = how many
    // segments each sampled id represents in its file.
    let mut ids: Vec<String> = Vec::new();
    let mut weights: Vec<f64> = Vec::new();
    let mut file_of: Vec<usize> = Vec::new();
    for (fi, f) in nzb.files.iter().enumerate() {
        if f.kind() == FileKind::Par2Volume {
            continue;
        }
        let n = f.segments.len();
        let take = if sample_pct >= 100 {
            n
        } else {
            ((n * sample_pct as usize).div_ceil(100)).max(2.min(n))
        };
        for si in stratified_sample(n, take) {
            ids.push(format!("<{}>", f.segments[si].message_id));
            weights.push(n as f64 / take as f64);
            file_of.push(fi);
        }
    }
    let recovery: usize = nzb
        .files
        .iter()
        .filter_map(|f| vol_count_from_name(f.filename_hint().unwrap_or(&f.subject)))
        .sum();
    println!(
        "pre-flight: STAT {} article(s) ({}% sample) × {} server(s), {} conns × window {}",
        ids.len(),
        sample_pct.min(100),
        cfg_all.servers.len(),
        connections,
        window
    );

    let sweep = stat_sweep(&cfg_all.servers, &ids, connections, window).await;
    for (si, s) in cfg_all.servers.iter().enumerate() {
        let (have, missing, unknown) = sweep.server_counts(si);
        println!(
            "  {:<28} {:>5.1}% available ({have} have, {missing} missing{})",
            s.host,
            have as f64 * 100.0 / ids.len().max(1) as f64,
            if unknown > 0 {
                format!(", {unknown} unknown")
            } else {
                String::new()
            }
        );
    }

    let missing = sweep.union_missing();
    let est_missing: f64 = missing.iter().map(|&i| weights[i]).sum();
    let est_missing = est_missing.round() as usize;
    let mut missing_files: std::collections::BTreeMap<usize, usize> = Default::default();
    for &i in &missing {
        *missing_files.entry(file_of[i]).or_default() += 1;
    }
    for (fi, count) in &missing_files {
        let f = &nzb.files[*fi];
        println!(
            "  ✘ {}: {count} of {} sampled segment(s) missing on every server",
            f.filename_hint().unwrap_or(&f.subject),
            f.segments.len().min(
                (f.segments.len() * sample_pct.min(100) as usize)
                    .div_ceil(100)
                    .max(2)
            ),
        );
    }

    // Verdict in article units (block ≈ article for typical posts; the
    // live ledger is exact once the par2 main packet is in hand).
    let verdict = if est_missing == 0 {
        Verdict::Complete
    } else if est_missing <= recovery {
        Verdict::Repairable {
            est_missing,
            recovery,
        }
    } else {
        Verdict::Impossible {
            est_missing,
            recovery,
        }
    };
    match &verdict {
        Verdict::Complete => println!(
            "verdict: COMPLETE - every sampled article present on at least one server ({:.2?})",
            sweep.elapsed
        ),
        Verdict::Repairable {
            est_missing,
            recovery,
        } => println!(
            "verdict: REPAIRABLE - ≈{est_missing} article(s) missing everywhere ≤ {recovery} recovery block(s) ({:.2?})",
            sweep.elapsed
        ),
        Verdict::Impossible {
            est_missing,
            recovery,
        } => println!(
            "verdict: IMPOSSIBLE - ≈{est_missing} article(s) missing everywhere > {recovery} recovery block(s) ({:.2?})",
            sweep.elapsed
        ),
    }
    Ok(verdict)
}

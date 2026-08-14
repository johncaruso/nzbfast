//! The pre-flight check command: probes every server for segment availability and renders the Verdict the get command's --preflight consumes.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use std::path::Path;

// ---------------------------------------------------------------------------
// check - pre-flight availability (M2): STAT sweep + verdict
// ---------------------------------------------------------------------------

/// What pre-flight expects the download to do.
///
/// `dropped` names the files whose loss does NOT decide the verdict:
/// Usenet furniture (`.nfo`, `.sfv`, `.txt`, …) that no server has in
/// full. It rides on every variant because a job can lose furniture in
/// any state of repair, and because the count is a separate claim from
/// the payload one - see [`is_droppable_metadata`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Complete {
        dropped: Vec<String>,
    },
    Repairable {
        est_missing: usize,
        recovery: usize,
        /// At least one recovery volume declares an ordinal but no slice
        /// count (`.vol-NN.par2`), so `recovery` is a FLOOR, not the
        /// budget. Renders as an approximate answer rather than a
        /// comparison the numbers do not support.
        recovery_unknown: bool,
        dropped: Vec<String>,
    },
    Impossible {
        est_missing: usize,
        recovery: usize,
        dropped: Vec<String>,
    },
}

/// Is this NZB file Usenet furniture whose loss should not decide the
/// verdict?
///
/// Issue #23. The old verdict weighed TOTAL missing articles against
/// TOTAL recovery blocks and never asked which file the articles came
/// from, so one absent article in a single-segment `.nfo` beside 51
/// spare blocks printed `REPAIRABLE` - a repair that could never happen,
/// because a `.nfo` is not in the recovery set. The reporter's downloads
/// then failed on every release, over a file their own cleanup settings
/// would have deleted seconds later.
///
/// This is the same predicate the post-drain census now uses to spare
/// such a slot (`smart::is_junk_ext`, via `get::census`), which is the
/// point: pre-flight should predict what the downloader will actually
/// do. Its exclusions are what make it safe - archives and executables
/// are deliberately NOT furniture, so a missing `.rar` or `.mkv` still
/// decides the verdict.
///
/// Two narrowings on top of the shared list:
///
/// - No extension, no spare. An obfuscated post ships hashes for names,
///   and we cannot tell furniture from payload by guessing.
/// - `.par2` is on the junk list (cleanup deletes it) but is not
///   furniture HERE: the main packet is how repair happens at all. The
///   census reaches the same place by skipping recovery slots outright.
pub(crate) fn is_droppable_metadata(name: &str) -> bool {
    let ext = std::path::Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    !ext.is_empty() && ext != "par2" && crate::smart::is_junk_ext(&ext)
}

/// The verdict, given a PAYLOAD deficit - furniture already set aside.
///
/// Splitting the deficit is what makes the answer honest in both
/// directions. Furniture the set does not cover can never be repaired,
/// so counting it towards `recovery` promised a repair that will not
/// happen (#23); but its articles do not SPEND recovery blocks either,
/// so counting it could equally flip a payload that repairs fine to
/// IMPOSSIBLE. Neither number is the payload's, and only the payload's
/// decides whether the job completes.
///
/// Pre-flight is STAT-only: it never downloads the PAR2 packets, so it
/// cannot read the set's real file list and cannot KNOW that a given
/// `.nfo` is uncovered - it infers it from the name, exactly as the
/// downloader now does. That inference only affects the fate of the
/// file, never the fate of the job: if the set does not cover it the
/// download completes and drops it, and if the set does cover it repair
/// rebuilds it. The copy says both rather than picking one.
///
/// `recovery_unknown` says the budget above is a FLOOR: some recovery
/// volume names an ordinal without a slice count, the `.vol-NN.par2`
/// shape playWEB/NORViNE/GRACE post. Those volumes carry real blocks we
/// cannot count from the name, and pre-flight never downloads the PAR2
/// packets that would say. Summing them as ZERO is what made this
/// report IMPOSSIBLE - aborting the CLI, failing daemon and library
/// jobs - on sets the downloader repairs, because the real repair path
/// estimates the same volumes from their SIZE instead
/// (`repair::recovery_candidates`). Pre-flight cannot borrow that
/// estimate: it needs the set's block size, which only the PAR2 main
/// packet carries. So it declines to claim impossibility it cannot
/// support - the asymmetry is the point, since IMPOSSIBLE stops a
/// download that would have worked while REPAIRABLE only lets the real
/// verify decide (14 Aug sweep).
pub(crate) fn verdict_of(
    est_missing: usize,
    recovery: usize,
    recovery_unknown: bool,
    dropped: Vec<String>,
) -> Verdict {
    if est_missing == 0 {
        Verdict::Complete { dropped }
    } else if est_missing <= recovery || recovery_unknown {
        Verdict::Repairable {
            est_missing,
            recovery,
            recovery_unknown,
            dropped,
        }
    } else {
        Verdict::Impossible {
            est_missing,
            recovery,
            dropped,
        }
    }
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
    // Known counts sum; an ordinal-only volume (`.vol-NN.par2`) has real
    // blocks this name cannot size, so it is recorded as UNKNOWN rather
    // than silently added as zero - see `verdict_of`.
    let mut recovery: usize = 0;
    let mut recovery_unknown = false;
    for f in nzb
        .files
        .iter()
        .filter(|f| f.kind() == FileKind::Par2Volume)
    {
        match vol_count_from_name(f.filename_hint().unwrap_or(&f.subject)) {
            Some(n) => recovery += n,
            None => recovery_unknown = true,
        }
    }
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
    // Which NZB files are furniture rather than payload. Only DATA files
    // qualify: `Par2Volume` never reaches the sample, and `Par2Main` is
    // the packet repair is made of, not something to shrug off.
    let furniture: Vec<bool> = nzb
        .files
        .iter()
        .map(|f| {
            f.kind() == FileKind::Data
                && is_droppable_metadata(f.filename_hint().unwrap_or(&f.subject))
        })
        .collect();
    let est_missing: f64 = missing
        .iter()
        .filter(|&&i| !furniture[file_of[i]])
        .map(|&i| weights[i])
        .sum();
    let est_missing = est_missing.round() as usize;
    let mut missing_files: std::collections::BTreeMap<usize, usize> = Default::default();
    for &i in &missing {
        *missing_files.entry(file_of[i]).or_default() += 1;
    }
    let mut dropped: Vec<String> = Vec::new();
    for (fi, count) in &missing_files {
        let f = &nzb.files[*fi];
        let name = f.filename_hint().unwrap_or(&f.subject);
        println!(
            "  ✘ {name}: {count} of {} sampled segment(s) missing on every server{}",
            f.segments.len().min(
                (f.segments.len() * sample_pct.min(100) as usize)
                    .div_ceil(100)
                    .max(2)
            ),
            if furniture[*fi] {
                " - metadata, not payload"
            } else {
                ""
            },
        );
        if furniture[*fi] {
            dropped.push(name.to_string());
        }
    }
    if !dropped.is_empty() {
        println!(
            "  note: metadata files are Usenet furniture the recovery set usually does \
             not cover, and pre-flight is STAT-only so it cannot read the set's file \
             list to be sure. Uncovered, the download completes and the file is \
             dropped; covered, repair rebuilds it from the same block budget."
        );
    }

    // Verdict in article units (block ≈ article for typical posts; the
    // live ledger is exact once the par2 main packet is in hand), and in
    // PAYLOAD articles only - see verdict_of.
    let verdict = verdict_of(est_missing, recovery, recovery_unknown, dropped);
    let dropped_tail = |dropped: &[String]| {
        if dropped.is_empty() {
            String::new()
        } else {
            format!(
                "; {} metadata file(s) no server has in full: {}",
                dropped.len(),
                dropped.join(", ")
            )
        }
    };
    match &verdict {
        Verdict::Complete { dropped } if dropped.is_empty() => println!(
            "verdict: COMPLETE - every sampled article present on at least one server ({:.2?})",
            sweep.elapsed
        ),
        Verdict::Complete { dropped } => println!(
            "verdict: COMPLETE - the payload is whole{} ({:.2?})",
            dropped_tail(dropped),
            sweep.elapsed
        ),
        Verdict::Repairable {
            est_missing,
            recovery,
            recovery_unknown: false,
            dropped,
        } => println!(
            "verdict: REPAIRABLE - ≈{est_missing} payload article(s) missing everywhere ≤ {recovery} recovery block(s){} ({:.2?})",
            dropped_tail(dropped),
            sweep.elapsed
        ),
        Verdict::Repairable {
            est_missing,
            recovery,
            recovery_unknown: true,
            dropped,
        } => println!(
            "verdict: PROBABLY REPAIRABLE - ≈{est_missing} payload article(s) missing everywhere, against {recovery} counted recovery block(s) plus volumes whose names do not say how many they hold - the real block count is read during repair{} ({:.2?})",
            dropped_tail(dropped),
            sweep.elapsed
        ),
        Verdict::Impossible {
            est_missing,
            recovery,
            dropped,
        } => println!(
            "verdict: IMPOSSIBLE - ≈{est_missing} payload article(s) missing everywhere > {recovery} recovery block(s){} ({:.2?})",
            dropped_tail(dropped),
            sweep.elapsed
        ),
    }
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Issue #23 in one assertion: the reporter's post, one absent
    /// article in a single-segment `.nfo`, 51 spare recovery blocks.
    ///
    /// The old verdict weighed 1 against 51 and said REPAIRABLE. It is
    /// not repairable at any block count - a `.nfo` the recovery set
    /// does not cover has no parity behind it - and the downloader now
    /// completes the job and drops the file. Pre-flight has to predict
    /// THAT, so the only wrong answer here is any verdict carrying a
    /// repair promise.
    #[test]
    fn a_missing_nfo_is_not_a_repair_promise() {
        let v = verdict_of(0, 51, false, names(&["release.nfo"]));
        assert_eq!(
            v,
            Verdict::Complete {
                dropped: names(&["release.nfo"])
            }
        );
        // And the reverse framing: nothing missing anywhere is still the
        // plain COMPLETE, with nothing to say about metadata.
        assert_eq!(
            verdict_of(0, 51, false, vec![]),
            Verdict::Complete { dropped: vec![] }
        );
    }

    /// Furniture set aside must not spend the block budget either. A
    /// payload deficit that fits is REPAIRABLE even when the same post
    /// also lost a `.sfv`, and the dropped file rides along rather than
    /// being folded into the count.
    #[test]
    fn furniture_does_not_spend_the_recovery_budget() {
        assert_eq!(
            verdict_of(4, 51, false, names(&["release.sfv"])),
            Verdict::Repairable {
                est_missing: 4,
                recovery: 51,
                recovery_unknown: false,
                dropped: names(&["release.sfv"]),
            }
        );
        assert_eq!(
            verdict_of(52, 51, false, names(&["release.sfv"])),
            Verdict::Impossible {
                est_missing: 52,
                recovery: 51,
                dropped: names(&["release.sfv"]),
            }
        );
        // The boundary the old code drew, undisturbed: exactly enough
        // blocks still repairs.
        assert_eq!(
            verdict_of(51, 51, false, vec![]),
            Verdict::Repairable {
                est_missing: 51,
                recovery: 51,
                recovery_unknown: false,
                dropped: vec![],
            }
        );
    }

    /// 14 Aug sweep: recovery volumes whose names carry an ordinal but
    /// no slice count (`.vol-01.par2` … `.vol-09.par2`, the playWEB
    /// shape) summed to a ZERO budget, so one missing payload article
    /// beside nine real recovery volumes reported IMPOSSIBLE and aborted
    /// a job the downloader repairs. Unknown must not be spent as zero.
    #[test]
    fn unknown_recovery_counts_never_reach_impossible() {
        // The old arithmetic: 5 missing against a budget counted as 0.
        assert_eq!(
            verdict_of(5, 0, true, vec![]),
            Verdict::Repairable {
                est_missing: 5,
                recovery: 0,
                recovery_unknown: true,
                dropped: vec![],
            },
            "an uncountable recovery set cannot prove a job impossible"
        );
        // A PARTLY known budget is still a floor, not a ceiling: the
        // known 2 blocks do not bound what the ordinal volumes hold.
        assert_eq!(
            verdict_of(40, 2, true, vec![]),
            Verdict::Repairable {
                est_missing: 40,
                recovery: 2,
                recovery_unknown: true,
                dropped: vec![],
            }
        );
        // And the flag changes nothing when the budget IS fully known -
        // a genuinely short set still reports impossible.
        assert_eq!(
            verdict_of(52, 51, false, vec![]),
            Verdict::Impossible {
                est_missing: 52,
                recovery: 51,
                dropped: vec![],
            }
        );
        // Nothing missing stays COMPLETE either way.
        assert_eq!(
            verdict_of(0, 0, true, vec![]),
            Verdict::Complete { dropped: vec![] }
        );
    }

    /// The rule is only correct while it is NARROW - a version that
    /// spared everything would pass the tests above just as well. Both
    /// halves in one function so neither can be deleted alone.
    #[test]
    fn only_usenet_furniture_is_droppable() {
        for n in [
            "release.nfo",
            "release.NFO",
            "release.sfv",
            "release.txt",
            "release.srr",
            "Some.Release-GRP.md5",
        ] {
            assert!(is_droppable_metadata(n), "{n} should be furniture");
        }
        for n in [
            // Payload, in every shape: the whole point of the check.
            "release.mkv",
            "release.rar",
            "release.r00",
            "release.part01.rar",
            "release.7z",
            "setup.exe",
            "release.zip",
            // The main packet is how repair happens at all, so it is not
            // furniture here even though cleanup deletes it.
            "release.par2",
            "release.vol000+51.par2",
            // Obfuscated: a hash with no extension could be anything,
            // and guessing wrong drops a video.
            "8upt36kdv2iwfhb1ev81aj",
            "",
        ] {
            assert!(!is_droppable_metadata(n), "{n} should NOT be furniture");
        }
    }
}

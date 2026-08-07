//! The disk-unpack tail (TODO 106 phase 2.1, cut 6): the volume-eating
//! decision and its arm, the resumed-run re-extract, the §94A restored-
//! source cleanup, the unrar ladder over demoted volume groups, and the
//! nested-archive second pass. Body is a verbatim move from the
//! orchestrator.

use crate::*;
use std::path::Path;
use tracing::{info, warn};

/// How the unpack tail left the job. The orchestrator destructures the
/// fields back onto the inline names.
pub(super) struct UnpackVerdict {
    pub(super) all_good: bool,
    pub(super) reextract_failed: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn unpack_tail(
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    restored: &nzbkit::journal::Restored,
    ex_report: &nzbkit::extract::ExtractReport,
    final_shape: &Option<nzbkit::extract::ArchiveShape>,
    outer_vol_stems: &std::collections::HashSet<String>,
    out_dir: &Path,
    password: Option<&str>,
    resuming: bool,
    no_extract: bool,
    resume_map: bool,
    eat_consent: bool,
    note_activity: &(dyn Fn(&'static str) + Sync),
    mut all_good: bool,
    mut reextract_failed: Option<String>,
) -> Result<UnpackVerdict> {
    note_activity("extracting");
    // TODO 101: should this job's disk unpack eat its own volumes as it
    // consumes them? Decided ONCE, here, where every input is known and
    // measured - the set is fully on disk by now, so the forecast is
    // arithmetic rather than a projection - and armed for the length of
    // the disk ladder below. `all_good` IS the verified gate: it is false
    // for any set PAR2 could not vouch for, and an unverified set is
    // never eaten whatever the mode says.
    //
    // Deliberately NOT extended over the nested pass further down: those
    // are intermediates the extraction produced, owned by
    // `sweep_spent_entry`, not the downloaded volume set this mode is
    // about.
    let eat_arm = {
        // `tag()`, not `display()`. Every other consumer of this shape
        // reads the raw tokens; `display()` runs each one through
        // `shape_word` and joins with " · " for humans, so the token
        // test worked only by the accident that "encrypted" is spelled
        // the same either way. One rewording or one localization of that
        // single word and the encrypted third copy would silently drop
        // out of the forecast, leaving a `low_disk` job that must eat
        // its volumes reading as "fits" and dying at the decrypt.
        let shape = final_shape.as_ref().map(|s| s.tag()).unwrap_or_default();
        let encrypted = shape.split_whitespace().any(|t| t == "encrypted");
        let mut on_disk = collect_rar_volumes(out_dir).unwrap_or_default();
        on_disk.extend(collect_obfuscated_rar_volumes(out_dir).unwrap_or_default());
        let forecast =
            crate::eatvol::forecast(out_dir, crate::eatvol::volume_bytes(&on_disk), encrypted);
        let verdict = crate::eatvol::decide(crate::eatvol::mode(), all_good, eat_consent, forecast);
        if verdict.eats() {
            info!(
                target: "extract",
                "volume-eating unpack armed ({}): {} volume(s) on disk, {:.1} GB free, \
                 the unpack needs {:.1} GB",
                crate::eatvol::mode().as_str(),
                on_disk.len(),
                forecast.free as f64 / 1e9,
                forecast.needed() as f64 / 1e9
            );
        }
        crate::eatvol::EatArm::new(verdict.eats())
    };
    // Resumed runs skipped in-stream extraction - extract from the (now
    // verified) volume files on disk. Not under §94 A replay: there the
    // extractor mapped in-stream like a fresh run, and whatever demoted
    // takes the same disk ladder a fresh run's demotes take, below.
    if resuming && !no_extract && !resume_map && all_good {
        all_good = reextract_dir(out_dir, password)?;
        if !all_good {
            reextract_failed =
                Some("resumed job: the verified volumes on disk could not be extracted".into());
        }
    }
    // §94 A: a replayed volume whose slot MAPPED (or chased) leaves its
    // restored source file behind - the output came through the map, so
    // the source is now redundant. Removed only on a fully-good finish
    // (the crash journal's records keep pointing at these files until
    // then, so a kill mid-run still resumes from them), and only when
    // the slot did not adopt that exact file as its plain writer.
    if resume_map && all_good {
        for seed in &restored.seeds {
            // Recovery volumes were never replayed; their files belong to
            // the ordinary end-of-job PAR2 cleanup, not to this pass.
            if seed.slot >= slots.len() || slots[seed.slot].is_par2() {
                continue;
            }
            // Never delete a path an extraction PRODUCED. The preclaim
            // at replay time already stops an inner member taking a
            // restored source's name, so this is the second lock on the
            // same door (Codex sweep 3 Aug H3): identity by path string
            // alone once deleted the only output of the job while
            // reporting it green.
            if ex_report.extracted.iter().any(|(n, _)| n == &seed.name) {
                continue;
            }
            let p = out_dir.join(&seed.name);
            if extractor.slot_path(seed.slot).as_deref() != Some(p.as_path()) && p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    // The unrar ladder below reasons about RAR VOLUMES, so a top-level 7z
    // chase that demoted is filtered out of it entirely: that demote
    // leaves a materialized .7z, which the post-extraction pass further
    // down owns. Left in, its reason text steers all three arms wrongly -
    // "held-bytes cap" reads as an unowned set and "encrypted" as a
    // locked RAR - and each one ends at try_unrar over a directory with
    // no RAR in it, which answers false and fails a job that is fine.
    let vol_fallbacks: Vec<&(String, String)> = ex_report
        .fallbacks
        .iter()
        .filter(|(_, w)| !sevenz_disk_fallback(w))
        .collect();
    // Compressed (non-encrypted) archives can't stream-extract, but a
    // Set when the set is locked and no password was found: the verified
    // volumes ARE the deliverable until one arrives, so the nested pass must
    // not then try (and fail) to unpack them. A NAMED encrypted set was
    // already safe by accident - its stems are in `outer_vol_stems`, so the
    // pass skipped it - but an obfuscated one has no stem to match (hash
    // names carry no extension), so the pass ran, `extract_obfuscated_rar`
    // failed for want of the password, and the job came out FAILED with no
    // password prompt, where the identical named set finishes Completed and
    // offers the unlock.
    let mut locked_no_password = false;
    // bundled unrar unpacks the verified volumes. Encrypted sets join in
    // when a password is known; without one they stay on disk.
    let enc_fallback = vol_fallbacks
        .iter()
        .any(|(_, w)| w.contains("encrypted") || w.contains("password"));
    // Every OTHER demote leaves its volumes unowned - see
    // [`fallback_needs_disk_unpack`].
    let unowned_fallback = vol_fallbacks
        .iter()
        .any(|(_, w)| fallback_needs_disk_unpack(w));
    if all_good
        && (vol_fallbacks.iter().any(|(_, w)| w.contains("compressed"))
            || (enc_fallback && password.is_some()))
    {
        // The unrar outcome IS the job outcome here: a corrupt compressed
        // set (or a wrong password) must not exit 0 with loose volumes.
        // On success the volumes are spent (Part B of the 2026-07-29
        // one-pass spec): a demoted 57.8 GB job used to finish holding
        // both the movie AND its full volume set.
        match try_unrar_spent(out_dir, password) {
            Some(spent) => remove_spent_volumes(&spent),
            None => {
                all_good = false;
                reextract_failed = Some(
                    "the verified volumes could not be unpacked \
                     (compressed set, or the password is wrong)"
                        .into(),
                );
            }
        }
    } else if all_good && unowned_fallback && !enc_fallback {
        match try_unrar_spent(out_dir, password) {
            Some(spent) => remove_spent_volumes(&spent),
            None => {
                all_good = false;
                reextract_failed =
                    Some("the verified volumes could not be unpacked after a fallback".into());
            }
        }
    } else if all_good && enc_fallback {
        locked_no_password = true;
        println!(
            "🔒 archive is password-protected and no password was found - \
             verified volumes kept in the output directory. Supply one with \
             --password, a <meta type=\"password\"> in the NZB, or a \
             {{{{password}}}} suffix on the NZB filename, then retry."
        );
    }
    // The downloaded volume set is done with. Everything below works on
    // what extraction PRODUCED, which this mode has no business eating.
    drop(eat_arm);
    // Post-extraction pass: nested archives (a RAR whose payload is one
    // more RAR), 7z sets, and SFX payloads unpack here - the inner layer
    // only exists once the outer extraction produced it, so this is
    // inherently a second pass over the output dir. Volumes of the
    // DOWNLOADED set deliberately remain in some flows (encrypted-no-
    // password, unrar-fallback leftovers) and must never be re-processed:
    // when nothing else needs the pass they simply skip it, and when the
    // fallback unpack itself produced a nested archive beside them
    // (compressed outer wrapping a RAR/7z) they are parked in a scratch
    // hold for the pass's duration instead, so the payload still denests.
    let outer_vols_on_disk = || -> bool {
        use nzbkit::extract::release_stem;
        match std::fs::read_dir(out_dir) {
            Ok(it) => it.flatten().any(|e| {
                let p = e.path();
                looks_like_named_rar(&p)
                    && p.file_name().is_some_and(|n| {
                        outer_vol_stems.contains(&release_stem(&n.to_string_lossy()))
                    })
            }),
            Err(_) => true, // unreadable output dir: keep the conservative skip
        }
    };
    let nested_hold: Option<Option<OuterHold>> = if !(all_good && !no_extract) {
        None
    } else if locked_no_password {
        // The volumes are the deliverable; nothing here can unpack them.
        None
    } else if !outer_vols_on_disk() {
        Some(None) // run the pass, nothing to park
    } else if nested_archive_beside_leftovers(out_dir, outer_vol_stems) {
        match OuterHold::park(out_dir, outer_vol_stems) {
            Ok(h) => Some(Some(h)),
            Err(e) => {
                // Park failure degrades to the historical skip - never
                // risk the pass seeing the outer set.
                println!("⚠ could not isolate leftover volumes for the nested pass: {e}");
                None
            }
        }
    } else {
        None
    };
    if let Some(hold) = nested_hold {
        let nested_res = extract_nested(out_dir, password, 1);
        // Restore parked volumes before judging the result - they must be
        // back in place on every path, including the failure ones.
        drop(hold);
        match nested_res {
            Ok(NestOutcome::Produced) => {}
            Ok(outcome) => {
                // A zip we cannot unpack FAILS the job when it is the
                // payload, and is forgiven when it is a sidecar.
                //
                // This used to warn either way, reasoning that failing
                // would loop *arr retries on a download that arrived
                // fine. But it did not arrive fine: if the payload is a
                // zip we cannot open, the release delivered nothing an
                // *arr can import, and Completed is a conclusion it acts
                // on - it stops looking, and the series sits stuck
                // forever. Failed is the honest answer, and it is the one
                // that makes Sonarr blocklist this release and grab a
                // usable one. The archive itself stays on disk either way.
                //
                // (There is no third status worth having. Sonarr's
                // Warning state is reachable only by claiming a disk-full
                // failure verbatim - SAB fail_message
                // "Unpacking failed, write error or disk is full?", or
                // nzbget UnpackStatus=SPACE - which would put a lie in
                // front of the user to buy a softer badge.)
                //
                // Forgiveness keys off what the PASS stopped at, never off
                // "is there a zip somewhere in the tree": a RAR/7z we could
                // not unpack is a payload we did not deliver even when an
                // unrelated `Subs/subs.zip` sits beside it.
                let zip_gap = outcome == NestOutcome::ZipGap;
                match unsupported_archive_present(out_dir) {
                    Some(u) if zip_gap && !u.blocking => println!("{}", u.message()),
                    Some(u) if zip_gap => {
                        println!("{}", u.message());
                        all_good = false;
                        reextract_failed = Some(format!(
                            "the payload {} could not be unpacked \
                             (damaged, encrypted, or an unsupported compression method)",
                            u.display
                        ));
                    }
                    // Either a non-zip gap over a named archive, or a pass
                    // that stopped without leaving one we can point at.
                    other => {
                        all_good = false;
                        reextract_failed = Some(match other {
                            Some(u) => format!(
                                "{} in the output directory could not be unpacked",
                                u.display
                            ),
                            None => {
                                "an archive in the output directory could not be unpacked".into()
                            }
                        });
                    }
                }
            }
            Err(e) => {
                println!("⚠ nested-archive pass failed: {e}");
                all_good = false;
                reextract_failed = Some("the nested-archive pass failed".into());
            }
        }
    }
    Ok(UnpackVerdict {
        all_good,
        reextract_failed,
    })
}

/// The end-of-extraction report: finish() the extractor, apply the
/// deferred deobfuscation renames, collect the outer volume stems the
/// nested pass must park, and print what came out in-stream.
pub(super) fn report_extraction(
    extractor: &Arc<nzbkit::extract::Extractor>,
    deferred_renames: &[(usize, String)],
    out_dir: &Path,
) -> Result<(
    nzbkit::extract::ExtractReport,
    std::collections::HashSet<String>,
    Option<nzbkit::extract::ArchiveShape>,
)> {
    let ex_report = extractor.finish()?;
    // Now that no writer holds the partial file, a chased slot that
    // demoted can take the deobfuscated name after all. A slot whose
    // chase SUCCEEDED has no file left to rename (sevenz_finish deletes
    // the partial - the payload came out the other way), so slot_path is
    // None and this skips it.
    for (sidx, pname) in deferred_renames {
        if let Some(path) = extractor.slot_path(*sidx)
            && path.exists()
        {
            publish_verified_name(&path, pname, out_dir);
        }
    }
    // Named-RAR volume files of the DOWNLOADED set sitting in the output
    // dir at end-of-download (fallback groups' materialized volumes,
    // resumed runs' on-disk sets). Direct-extraction payload is subtracted
    // by name: a payload that is itself a named RAR set (RAR-in-RAR
    // release) is not an outer volume, and the nested pass below must
    // denest it rather than skip on its presence.
    let outer_vol_stems: std::collections::HashSet<String> = {
        use nzbkit::extract::release_stem;
        let payload: std::collections::HashSet<&str> = ex_report
            .extracted
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        std::fs::read_dir(out_dir)
            .map(|it| {
                it.flatten()
                    .map(|e| e.path())
                    .filter(|p| looks_like_named_rar(p))
                    .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .filter(|n| !payload.contains(n.as_str()))
                    .map(|n| release_stem(&n))
                    .collect()
            })
            .unwrap_or_default()
    };
    let final_shape = extractor.archive_shape();
    if !ex_report.extracted.is_empty() {
        // Sum the per-file sizes printed right below rather than the
        // extractor's `extracted_bytes` counter: that counter is only
        // incremented on the RAR store mapping path, so every CHASE
        // (7z and zip) reported "(0.0 MB)" under a list of files whose
        // own sizes were right. Found on a live 160 MB zip, 31 Jul.
        let extracted_mb: u64 = ex_report.extracted.iter().map(|(_, s)| *s).sum();
        println!(
            "extracted {} file(s) in-stream ({:.1} MB) - volumes never touched disk{}:",
            ex_report.extracted.len(),
            extracted_mb as f64 / 1e6,
            final_shape
                .as_ref()
                .map(|sh| format!(" [{}]", sh.display()))
                .unwrap_or_default()
        );
        for (name, size) in &ex_report.extracted {
            let lock = if ex_report.decrypted.contains(name) {
                " 🔓 decrypted"
            } else {
                ""
            };
            println!("  ▶ {name} ({:.1} MB){lock}", *size as f64 / 1e6);
        }
    } else if let Some(sh) = final_shape.as_ref() {
        // Nothing came out in-stream, so the shape has not been printed
        // anywhere yet - and it is exactly what explains why.
        println!("archive: {}", sh.display());
    }
    // Coalesce fallback reports by reason (an encrypted 180-volume set
    // would otherwise print 180 identical lines).
    let mut by_reason: std::collections::BTreeMap<&str, usize> = Default::default();
    for (_, why) in &ex_report.fallbacks {
        *by_reason.entry(why.as_str()).or_default() += 1;
    }
    for (why, n) in by_reason {
        println!(
            "  ⚠ direct extraction fell back for {n} volume group(s): {why} - volumes on disk"
        );
    }
    Ok((ex_report, outer_vol_stems, final_shape))
}

// Issue #14 tail: a sniffed post's recovery files sit on disk under
// hash names - the bootstrap volume, deferred slots' head-article
// partials, restored resume volumes, and anything a repair fetched.
// No extension rule can ever match them, so sweep by packet magic
// under the same `par_cleanup` setting that governs named `.par2`.
// ONLY on a good job (a failed one keeps its recovery data for the
// retry), and only HERE - after extractor.finish() - so no writer
// still holds a handle on the files (Windows would refuse the
// remove), and nothing that runs later reads them. Payload that is
// ITSELF par2 is spared by FileDesc name: the activated set's if one
// exists, the on-disk packets' otherwise.
pub(super) fn sweep_sniffed_leftovers(
    all_good: bool,
    par_cleanup: bool,
    sniff: &Arc<SniffCtl>,
    sniff_covered: Option<std::collections::HashSet<String>>,
    out_dir: &Path,
) {
    if all_good && par_cleanup && sniff.any_sniffed() {
        let covered: std::collections::HashSet<String> = sniff_covered.unwrap_or_else(|| {
            nzbkit::par2repair::covered_names(out_dir)
                .unwrap_or_default()
                .iter()
                .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
                .collect()
        });
        let mut freed: u64 = 0;
        let mut gone: usize = 0;
        // Same reasoning as the adoption-source sweep above: sniffed
        // recovery files ride the setting that governs named `.par2`,
        // and since §64 that is a recoverable, parked delete. Flag read
        // once at the sweep's entry.
        let recoverable = crate::smart::cleanup_recoverable();
        let staging = crate::smart::trash_staging_dir(out_dir);
        for p in nzbkit::par2repair::sniffed_packet_files(out_dir).unwrap_or_default() {
            let is_payload = p
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .is_some_and(|n| covered.contains(&n));
            if is_payload {
                continue;
            }
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            match crate::smart::remove_swept_file(&p, recoverable, staging.as_deref()) {
                Ok(_) => {
                    freed += len;
                    gone += 1;
                }
                Err(e) => warn!(
                    target: "cleanup",
                    "could not remove {} - {e}",
                    p.display()
                ),
            }
        }
        if gone > 0 {
            // "freed" only when the bytes actually left the disk - see
            // the adoption-source sweep above.
            println!(
                "  cleaned up {gone} obfuscated leftover(s), {:.1} MB {}",
                freed as f64 / 1e6,
                if recoverable { "to the Trash" } else { "freed" }
            );
        }
    }
}

/// The job's last word: on a good finish drop the spared metadata,
/// retire the journal and return Ok; otherwise print the diagnostics
/// block the dashboard log ring mirrors and fail with the closest
/// cause. Body is a verbatim move from the orchestrator's tail.
#[allow(clippy::too_many_arguments)]
pub(super) fn finish_job(
    all_good: bool,
    out_dir: &Path,
    incomplete_spared: &[String],
    journal: Arc<nzbkit::journal::Journal>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    stats: &[nzbkit::pool::PoolStats],
    reextract_failed: Option<String>,
    incomplete: usize,
    derrs: u64,
    missing_430: &Arc<AtomicU64>,
    retention_skipped: u64,
    transport_failed: &Arc<AtomicU64>,
    transport_sample: &Arc<std::sync::Mutex<Option<String>>>,
    decode_error_sample: &Arc<std::sync::Mutex<Option<String>>>,
    dead_servers: &[String],
    slots: &[Arc<FileSlot>],
    stalled: &Arc<std::sync::atomic::AtomicBool>,
    missing_segments: u64,
    total_segments: u64,
    total: u64,
    backbones: &[String],
    post_age_days: u32,
    repair_shortfall: Option<(usize, usize)>,
) -> Result<()> {
    // Download complete and verified (or repaired): the journal's job is
    // done. Anything less is a FAILED job - the daemon parks it in history
    // (an *arr must see Failed, never import an incomplete dir) and the
    // journal stays on disk so a retry fetches only what's still missing.
    if all_good {
        // Issue #23: a job that completed WITH something missing has to
        // say so at the end, not only in a per-file line a thousand
        // progress updates ago. These are metadata files no repair could
        // have healed, so the download really is done - but "done" and
        // "everything arrived" are different claims and only one of them
        // is true.
        let kept = drop_spared_metadata(out_dir, incomplete_spared);
        if !kept.is_empty() {
            // The delete IS the safety of the spare (see the fn doc):
            // a holed .nfo looks exactly like a real .nfo, and going
            // green while it sits in the directory hands an *arr the
            // false file the sparing rule exists to withhold. Fail
            // instead, and keep the journal so a retry can finish the
            // cleanup.
            anyhow::bail!(with_build(format!(
                "download complete, but {} partial metadata file(s) could not be \
                 removed: {} - refusing to report success while a holed file that \
                 looks real remains in the output directory (fix permissions and retry)",
                kept.len(),
                kept.join(", ")
            )))
        }
        if let Ok(j) = Arc::try_unwrap(journal) {
            j.remove();
        }
        return Ok(());
    }
    // Failing: print the block a bug report can carry whole. The daemon
    // mirrors stdout into the dashboard log ring, so this is what a user
    // pastes when they say "every file failed".
    print_failure_diagnostics(servers, stats);
    if let Some(why) = reextract_failed {
        anyhow::bail!(with_build(format!(
            "{why} - the verified files are still in the output directory"
        )))
    } else if incomplete > 0 || derrs > 0 {
        let causes = LossCauses {
            missing_430: missing_430.load(Ordering::Relaxed),
            retention_excluded: retention_skipped,
            transport_failed: transport_failed.load(Ordering::Relaxed),
            transport_sample: transport_sample.lock_ok().clone(),
            decode_sample: decode_error_sample.lock_ok().clone(),
            dead_servers,
            // Sniffed slots count: "this post carries no PAR2 recovery
            // data" must not be claimed about a post whose recovery set
            // was identified in-stream (issue #14).
            par2_slots: slots.iter().filter(|s| s.is_par2()).count(),
            stalled: stalled.load(Ordering::Relaxed),
            missing_segments,
            total_segments,
            bytes_arrived: total,
            backbones,
            post_age_days,
        };
        anyhow::bail!(with_build(incomplete_reason(incomplete, derrs, &causes)))
    } else if let Some((needed, have)) = repair_shortfall {
        anyhow::bail!(with_build(format!(
            "verification failed and PAR2 repair could not complete: {needed} recovery \
             block(s) needed but the NZB only carries {have}"
        )))
    } else {
        anyhow::bail!(with_build(
            "verification failed and PAR2 repair could not complete".into()
        ))
    }
}

/// Issue #23: finish the job WITHOUT the metadata files no server had.
///
/// Removed rather than left behind, and that is what makes sparing the
/// job safe. A slot short an article still has a file on disk with a
/// zero-filled hole where the bytes should be, and
/// `a_disk_repair_does_not_certify_files_outside_its_recovery_set` is
/// right that handing an *arr one of those is worse than failing - a
/// holed .nfo looks exactly like a real .nfo. Deleting it is the answer
/// neither the old behaviour nor a bare spare reached: the job
/// completes, and nothing false is left in the directory.
///
/// Safe to delete precisely because of the rule that selected these:
/// the recovery set does not cover them, so nothing can rebuild them,
/// and they are furniture rather than payload.
/// Returns the names it could NOT remove - the caller must refuse to
/// complete while any remain (a holed file that survived is exactly the
/// false artifact the delete exists to prevent).
fn drop_spared_metadata(out_dir: &Path, spared: &[String]) -> Vec<String> {
    if spared.is_empty() {
        return Vec::new();
    }
    let mut gone = Vec::new();
    let mut kept = Vec::new();
    for name in spared {
        let p = out_dir.join(nzbkit::disk::sanitize_filename(name));
        match std::fs::remove_file(&p) {
            // Never written at all is the same outcome we want.
            Ok(()) => gone.push(name.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => gone.push(name.clone()),
            Err(e) => {
                println!("  could not remove the partial {}: {e}", p.display());
                kept.push(name.clone());
            }
        }
    }
    if kept.is_empty() {
        println!(
            "complete, without {} metadata file(s) no server had: {} \
             (the partial copy was removed - nothing can rebuild it)",
            gone.len(),
            gone.join(", ")
        );
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tdir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-get-tail-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_empty_spared_list_is_a_no_op() {
        // Never-created directory: an empty list must return before any IO.
        drop_spared_metadata(Path::new("/nonexistent/nzbfast-test"), &[]);
    }

    /// The spared partial is removed; a spared name that was never
    /// written at all (NotFound) is the same wanted outcome.
    #[test]
    fn spared_partials_are_removed_and_notfound_is_success() {
        let d = tdir("spared");
        std::fs::write(d.join("a.nfo"), b"partial").unwrap();
        let kept =
            drop_spared_metadata(&d, &["a.nfo".to_string(), "never-written.nfo".to_string()]);
        assert!(
            !d.join("a.nfo").exists(),
            "the holed partial must be deleted"
        );
        assert!(kept.is_empty(), "both outcomes are success: {kept:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A spared partial that CANNOT be removed must come back in the
    /// kept list - the caller refuses to complete on a non-empty one,
    /// because the surviving file is a zero-holed fake that looks like
    /// a real .nfo to an *arr (the exact artifact the delete exists to
    /// prevent). Going green regardless was the 5 Aug sweep's H3.
    #[test]
    #[cfg(unix)]
    fn an_unremovable_spared_partial_is_reported_not_swallowed() {
        use std::os::unix::fs::PermissionsExt;
        let d = tdir("spared-ro");
        std::fs::write(d.join("a.nfo"), b"partial").unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let kept = drop_spared_metadata(&d, &["a.nfo".to_string()]);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(kept, vec!["a.nfo".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A traversal name is neutered by sanitize_filename: the file the
    /// raw join would have hit, OUTSIDE the output dir, survives.
    #[test]
    fn a_traversal_name_cannot_reach_outside_the_dir() {
        let parent = tdir("traverse");
        let out = parent.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(parent.join("evil.nfo"), b"keep me").unwrap();
        drop_spared_metadata(&out, &["../evil.nfo".to_string()]);
        assert!(
            parent.join("evil.nfo").exists(),
            "sanitize_filename must keep the delete inside the output dir"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// Drive finish_job with everything healthy except the overrides.
    fn run_finish(
        dir: &Path,
        all_good: bool,
        reextract_failed: Option<String>,
        incomplete: usize,
        derrs: u64,
        repair_shortfall: Option<(usize, usize)>,
    ) -> Result<()> {
        let (j, _) = nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap();
        finish_job(
            all_good,
            dir,
            &[],
            Arc::new(j),
            &[],
            &[],
            reextract_failed,
            incomplete,
            derrs,
            &Arc::new(AtomicU64::new(0)),
            0,
            &Arc::new(AtomicU64::new(0)),
            &Arc::new(std::sync::Mutex::new(None)),
            &Arc::new(std::sync::Mutex::new(None)),
            &[],
            &[],
            &Arc::new(std::sync::atomic::AtomicBool::new(false)),
            0,
            0,
            0,
            &[],
            0,
            repair_shortfall,
        )
    }

    /// A good finish retires the journal and returns Ok.
    #[test]
    fn a_good_finish_retires_the_journal() {
        let d = tdir("good");
        assert!(run_finish(&d, true, None, 0, 0, None).is_ok());
        assert!(
            !d.join(".nzbfast.journal").exists(),
            "the journal's job is done on a verified finish"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The four failure arms are ranked: reextract beats incomplete and
    /// derrs, which beat repair_shortfall, which beats the bare verdict.
    #[test]
    fn failure_arms_are_ranked() {
        let d = tdir("ranked");
        let msg = |r: Result<()>| r.unwrap_err().to_string();
        // reextract_failed wins over everything behind it.
        let m = msg(run_finish(
            &d,
            false,
            Some("boom".into()),
            3,
            2,
            Some((9, 1)),
        ));
        assert!(m.contains("boom"), "{m}");
        assert!(m.contains("still in the output directory"), "{m}");
        // incomplete files beat the repair-shortfall arm.
        let m = msg(run_finish(&d, false, None, 1, 0, Some((9, 1))));
        assert!(m.contains("download incomplete"), "{m}");
        assert!(!m.contains("recovery block"), "{m}");
        // derrs alone also beat the shortfall arm.
        let m = msg(run_finish(&d, false, None, 0, 2, Some((9, 1))));
        assert!(m.contains("could not write the download"), "{m}");
        // The shortfall arm names its arithmetic.
        let m = msg(run_finish(&d, false, None, 0, 0, Some((9, 1))));
        assert!(m.contains("9 recovery"), "{m}");
        assert!(m.contains("carries 1"), "{m}");
        // Nothing else to say: the bare verdict.
        let m = msg(run_finish(&d, false, None, 0, 0, None));
        assert!(
            m.contains("verification failed and PAR2 repair could not complete"),
            "{m}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

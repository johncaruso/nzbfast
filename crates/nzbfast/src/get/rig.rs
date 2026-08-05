//! Rig-phase helpers for get_with_progress (TODO 106 phase 2.1, cut 3):
//! the in-stream password probe hook and the crash-resume replay/adopt
//! pass. Bodies are verbatim moves from the orchestrator.

use crate::*;
use std::path::Path;

// Increment A (one-pass encrypted plan, 2026-07-31): candidate probe
// over the job's OWN files. Password sidecars ride the same NZB and
// land within the head round (M3 scheduling fetches every file's
// first segment up front, and a password note is one segment), so
// when an encrypted set blocks, the extractor parks it and asks this
// hook instead of demoting. Candidates are the 2nd-pass harvest
// (small .txt/.nfo/.diz lines, "password:" tails, file stems) plus
// the job directory's name - the release stem an obfuscated post
// carries nowhere else - plus, on daemon runs, a password the user
// typed mid-download (mode=set_password → the hub's owner-tagged
// cell; C2 step 1). Only a check-VERIFIED candidate is returned;
// the tried-set is keyed by (salt, value) so a value that failed one
// set's check is still tested against a second set's - which is also
// what lets a corrected password typed after a wrong one get its
// turn. Check-less sets never park (try_pw_await gates on a
// well-formed check), so an unverifiable typed password can never
// key a mapper here - those sets take the finish-adjudication route.
pub(super) fn install_password_probe(
    extractor: &Arc<nzbkit::extract::Extractor>,
    hub: &Option<Arc<StreamHub>>,
    out_dir: &Path,
    stream_owner: &str,
) {
    let dir = out_dir.to_path_buf();
    let tried: std::sync::Mutex<std::collections::HashSet<([u8; 16], String)>> = Default::default();
    let hub_pw = hub.clone();
    let owner = stream_owner.to_string();
    extractor.set_password_probe(std::sync::Arc::new(move |probe| {
        let t0 = std::time::Instant::now();
        let mut cands = harvest_password_candidates(&dir, None);
        if let Some(n) = dir.file_name().map(|n| n.to_string_lossy().to_string()) {
            let stem = nzbkit::extract::release_stem(&n);
            if stem != n {
                cands.push(PwCandidate {
                    value: stem,
                    source: "job name stem".into(),
                    structured: false,
                });
            }
            cands.push(PwCandidate {
                value: n,
                source: "job name".into(),
                structured: false,
            });
        }
        // The operator's passwords file outranks the harvested
        // guesses (curated beats scraped), re-read per invocation -
        // the operator may add the password WHILE the download
        // runs, and this probe is exactly the moment it pays off:
        // the set re-keys in place and streams one-pass instead of
        // parking for a post-completion unlock. Structured, like
        // the typed password, so the KDF-depth gate never blocks
        // an operator-supplied value.
        if let Some(path) = hub_pw
            .as_ref()
            .and_then(|h| h.unpack_password_file.lock_ok().clone())
        {
            for (i, pw) in crate::smart::read_password_file(&path)
                .into_iter()
                .enumerate()
            {
                cands.insert(
                    i,
                    PwCandidate {
                        value: pw,
                        source: "passwords file".into(),
                        structured: true,
                    },
                );
            }
        }
        // The late-typed password outranks every harvested guess:
        // first in line, and structured (operator-supplied) so the
        // KDF-depth gate never blocks it. Re-read per invocation -
        // the cell can change between probes. CLI runs have no hub.
        if let Some(pw) = hub_pw.as_ref().and_then(|h| h.late_password_for(&owner)) {
            cands.insert(
                0,
                PwCandidate {
                    value: pw,
                    source: "set_password (typed mid-download)".into(),
                    structured: true,
                },
            );
        }
        let mut tried = tried.lock_ok();
        for c in cands {
            if !tried.insert((probe.salt, c.value.clone())) {
                continue;
            }
            // Same KDF-depth gate as the 2nd-pass harvest: only the
            // operator's own password may pay for a hostile-depth
            // KDF, and no candidate sweep may exceed the wall-clock
            // budget - a crafted post can stuff sidecars with
            // thousands of lines.
            if !kdf_candidate_allowed(probe.lg2_count, c.structured) {
                continue;
            }
            if t0.elapsed() > PW_PROBE_BUDGET {
                break;
            }
            if probe.verify(&c.value) == nzbkit::rar::PwVerdict::Verified {
                println!(
                    "🔑 archive password found in {} (in-stream probe)",
                    c.source
                );
                // A verified key means nobody needs to be asked -
                // and the winner is parked for finalize to record
                // onto the Job (the volumes decrypt one-pass, so
                // the completion path never meets them).
                if let Some(h) = hub_pw.as_ref() {
                    *h.password_wanted.lock_ok() = None;
                    *h.password_found.lock_ok() = Some((owner.clone(), c.value.clone()));
                }
                return Some(c.value);
            }
        }
        // The probe only fires when an encrypted set is BLOCKED on a
        // password, so a fruitless sweep IS the live "this download
        // wants a password" moment. Owner-tagged; the dashboard's
        // "ask at once" mode prompts off the queue slot this raises.
        if let Some(h) = hub_pw.as_ref() {
            *h.password_wanted.lock_ok() = Some(owner.clone());
        }
        None
    }));
}

// Crash resume (placement journal). Two modes:
//
// Replay (§94 A, NZBFAST_RESUME_MAP): restored spans flow through
// `Extractor::write` in offset order BEFORE the network opens,
// exactly as if the articles had just arrived - the offset-0 sniff
// fires, the mappers walk replayed headers, and the run continues
// one-pass. Deliberately NOT re-journaled: the spans are already
// durable, and the old records keep describing where the bytes are
// if this run is killed too (restored source files are only removed
// after a fully-good finish, below). The verifier sees each span as
// an unverified arrival - full MD5 under delegation - because no
// decoder vouched for these bytes THIS run.
//
// Adopt (default): restored files become plain slot writers and
// their spans are registered as pre-spans - the M15b backfill hashes
// every restored byte against the PAR2 block map once the set
// activates, so nothing is trusted unverified.
pub(super) fn replay_or_adopt_restored(
    restored: &nzbkit::journal::Restored,
    slots: &[Arc<FileSlot>],
    resume_map: bool,
    extractor: &Arc<nzbkit::extract::Extractor>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    out_dir: &Path,
) {
    let mut replayed_files = 0usize;
    let mut replayed_bytes = 0u64;
    for seed in &restored.seeds {
        // is_par2(): a resume-recognised recovery volume is not adopted as
        // a payload writer and its bytes stay out of the verifier - like a
        // par2-main slot, its file simply waits on disk for a repair.
        if seed.slot >= slots.len() || slots[seed.slot].is_par2() {
            continue;
        }
        if resume_map {
            // The restored file is a live SOURCE for this whole run.
            // Claim its name before any replay so an inner member with
            // the same sanitized name cannot open the same inode as an
            // output writer (Codex sweep 3 Aug H3) - a fresh extractor
            // starts with an empty name set, and `hash.bin` containing a
            // member named `hash.bin` is exactly the shape the disk
            // extractor stages into an isolated directory to avoid.
            extractor.preclaim_name(&seed.name);
            let path = out_dir.join(&seed.name);
            let mut f = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("resume: replaying {} failed to open: {e}", seed.name);
                    continue;
                }
            };
            // The journal name (the real on-disk name) beats the subject
            // hint for PAR2 file matching, same as the adopt path.
            verifier.set_name_hint(seed.slot, &seed.name);
            let mut spans = seed.spans.clone();
            spans.sort_unstable();
            let mut buf = vec![0u8; 4 << 20];
            let mut file_ok = true;
            'spans: for &(off, len) in &spans {
                let mut done = 0u64;
                while done < len {
                    use std::io::{Read, Seek, SeekFrom};
                    let chunk = ((len - done).min(4 << 20)) as usize;
                    if f.seek(SeekFrom::Start(off + done)).is_err()
                        || f.read_exact(&mut buf[..chunk]).is_err()
                    {
                        eprintln!("resume: replaying {} failed mid-span", seed.name);
                        file_ok = false;
                        break 'spans;
                    }
                    if let Err(e) =
                        extractor.write(seed.slot, &seed.name, seed.size, off + done, &buf[..chunk])
                    {
                        eprintln!("resume: replay write {}: {e}", seed.name);
                        file_ok = false;
                        break 'spans;
                    }
                    verifier.on_data_unverified(
                        seed.slot,
                        &seed.name,
                        seed.size,
                        off + done,
                        &buf[..chunk],
                    );
                    done += chunk as u64;
                }
            }
            if file_ok {
                replayed_files += 1;
                replayed_bytes += spans.iter().map(|s| s.1).sum::<u64>();
            }
        } else {
            if let Err(e) = extractor.seed_slot(seed.slot, &seed.name, seed.size, &seed.spans) {
                eprintln!("resume: adopting {} failed: {e}", seed.name);
                continue;
            }
            verifier.seed_pre_spans(seed.slot, &seed.spans);
            // The journal name (the real on-disk name) beats the subject hint
            // for PAR2 file matching.
            verifier.set_name_hint(seed.slot, &seed.name);
        }
    }
    if replayed_files > 0 {
        println!(
            "resume: replayed {replayed_files} restored file(s) ({:.1} MB) through the one-pass path",
            replayed_bytes as f64 / 1e6
        );
    }
}

//! Failure diagnostics: loss classification, the failure snapshot, unsupported-archive detection and the disk-unpack fallback tests.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;

/// Lines of console output a failed job keeps for its history entry, and
/// the byte ceiling that keeps history.json from growing without bound.
///
/// A job that lost every file prints one `⚠` line per file, so the line
/// budget has to clear a full set (the 31 Jul report was 94) and still
/// leave room for the per-server table and the diagnostics footer under
/// it. The LAST lines are the ones kept: a failure block ends with its
/// verdict.
pub(crate) const FAIL_DETAIL_LINES: usize = 160;
pub(crate) const FAIL_DETAIL_BYTES: usize = 24 * 1024;

/// This job's console output since `mark`, as the block a failed history
/// entry carries.
///
/// The one-line `fail_message` is a verdict; this is the evidence for it,
/// and until now it existed only in a memory-only 2000-line ring that a
/// restart wipes - which is exactly what happened to the 31 Jul job whose
/// diagnosis had to be reconstructed by re-probing the servers by hand.
pub(crate) fn fail_detail_snapshot(mark: u64) -> String {
    let lines = nzbkit::logtee::since(mark, FAIL_DETAIL_LINES);
    if lines.is_empty() {
        return String::new();
    }
    let mut out = lines.join("\n");
    if out.len() > FAIL_DETAIL_BYTES {
        // Truncate from the FRONT on a line boundary, keeping the tail:
        // the verdict and the server table are the last things printed.
        // Walk forward to a char boundary FIRST. `out.len() -
        // FAIL_DETAIL_BYTES` is a byte offset, and these lines are dense
        // with multi-byte characters - the census prints `⚠` per short
        // file, `print_failure_diagnostics` prints `·` separators, and
        // logtee substitutes U+FFFD for any non-UTF-8 byte a child
        // process emitted. Slicing `out[cut..]` on a continuation byte
        // panics, and the lane supervisor turns that panic into
        // "post-processing crashed (internal error)", which REPLACES the
        // real verdict, drops the evidence this function exists to keep,
        // and - because `fail_kind` classifies on the message opening -
        // relabels a MissingArticles/Transport failure as Local, so the
        // automatic retry never arms.
        let mut cut = out.len() - FAIL_DETAIL_BYTES;
        while cut < out.len() && !out.is_char_boundary(cut) {
            cut += 1;
        }
        let cut = out[cut..].find('\n').map_or(out.len(), |i| cut + i + 1);
        out = format!("[…earlier lines dropped…]\n{}", &out[cut..]);
    }
    out
}

/// Tag a job-failure message with the build that produced it. Failure
/// messages travel: history screenshots, Reddit posts, *arr logs - and
/// they arrive with no other version context. Appended, never prefixed:
/// the daemon's `fail_kind` classifies on the message OPENING.
pub(crate) fn with_build(msg: String) -> String {
    format!("{msg} [nzbfast {}]", env!("CARGO_PKG_VERSION"))
}

/// The block a bug report should contain, printed once when a job fails:
/// build, platform, and a per-server table that is deliberately
/// ANONYMOUS - level/connections/TLS/retention/outcome, never hostnames
/// or accounts, because these logs get pasted on public forums.
pub(crate) fn print_failure_diagnostics(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    stats: &[nzbkit::pool::PoolStats],
) {
    println!(
        "diagnostics (safe to include in a bug report): nzbfast {} · {} {} · {} cores · {} GB RAM",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        nzbkit::mem::physical_ram().map_or(0, |b| b / 1_000_000_000),
    );
    for (i, ((s, cfg), st)) in servers.iter().zip(stats).enumerate() {
        let retention = if s.retention_days == 0 {
            "unlimited".to_string()
        } else {
            format!("{}d", s.retention_days)
        };
        let outcome = if st.ever_connected {
            format!(
                "served {:.1} MB ({} connects, {} reconnects)",
                st.bytes as f64 / 1e6,
                st.connects,
                st.reconnects
            )
        } else {
            "NO USABLE CONNECTION for the entire run".to_string()
        };
        println!(
            "  server {}: level {} · {} conns · tls={} · retention {} · {}",
            i + 1,
            s.level,
            cfg.connections,
            s.tls,
            retention,
            outcome
        );
    }
}

/// Why a download did not come out whole - as a sentence whose OPENING
/// says which of the two it was, because the daemon's policies read it.
///
/// A missing segment is the post's problem: it earns an auto-retry (
/// propagation often fills the gap) and, with failure-link reporting on,
/// it is what the indexer wants to hear about. A decode/write error with
/// nothing missing is OUR machine's problem - a full disk, a permission
/// denied, a bad sector. Folding the two into one "download incomplete:
/// N file(s) with missing segments, M decode/write errors" told the
/// indexer a healthy release was dead and armed a retry straight back
/// onto the same full disk. Both counts still appear when both happened;
/// only the leading clause decides.
///
/// Known causes ride along AFTER the classifying clause (the daemon's
/// `fail_kind` and the tests pin the opening, so additions must append):
/// segments excluded by a configured `retention_days`, transport-error
/// losses with the first error quoted, servers that never held a usable
/// connection for the whole run, and repair's block arithmetic. All of
/// it turns "missing segments" from a dead-post verdict into something
/// the user can act on - the Hblife report ("every file failed, SAB got
/// them fine") was undiagnosable precisely because the summary never
/// said WHY the pool gave up on an article.
///
/// One opening is special: when NOT ONE loss was a server saying 430
/// (all transport, or transport plus retention exclusions), the message
/// opens "download failed on connection errors" instead - the daemon
/// classifies that `FailKind::Transport`, which still auto-retries but
/// never reports the post to an indexer as dead. A flaky provider under
/// load used to file takedown reports for healthy releases.
pub(crate) struct LossCauses<'a> {
    /// Segments where every live server was asked and said 430/423.
    pub(crate) missing_430: u64,
    /// Never requested: outside every server's configured retention.
    pub(crate) retention_excluded: u64,
    /// Lost to transport errors (timeouts, resets, exhausted retries).
    pub(crate) transport_failed: u64,
    /// First transport error, verbatim.
    pub(crate) transport_sample: Option<String>,
    /// First decode/write error, verbatim.
    pub(crate) decode_sample: Option<String>,
    /// Servers with no usable connection at any point in the run.
    pub(crate) dead_servers: &'a [String],
    /// PAR2 recovery slots the NZB carries. Zero means the post has no
    /// parity at all, so a confirmed-missing segment can never be
    /// reconstructed and no amount of retrying changes that.
    pub(crate) par2_slots: usize,
    /// The stall watchdog aborted the tail: no decode progress for its
    /// whole window while segments were still outstanding.
    ///
    /// This one outranks every count below it, because when it is set
    /// the counts describe a run that STOPPED rather than a post that is
    /// short. The abandoned segments were never asked and refused - most
    /// were never asked at all - so they arrive here as neither
    /// `missing_430` nor `transport_failed`, and the ordinary opening
    /// then reports the most alarming thing it can say ("N file(s) with
    /// missing segments") about a release nobody has shown to be
    /// missing anything. Observed 31 Jul on a 94-file post: the pool
    /// wedged with 8851 segments outstanding, and the history entry read
    /// exactly like a dead release.
    pub(crate) stalled: bool,
    /// Segments that never arrived - terminally missing, or still
    /// unresolved when the run gave up - and how many the job asked for
    /// in all. A file count cannot separate "short one segment each,
    /// one repair away" from "short every segment, the post is gone";
    /// these can. Both 0 when a caller has no per-slot accounting, which
    /// suppresses every clause that reads them.
    pub(crate) missing_segments: u64,
    pub(crate) total_segments: u64,
    /// Raw bytes the servers actually delivered. Zero is the single most
    /// diagnostic number a failed job has: it says the run never got
    /// anything, as opposed to getting most of it and falling short.
    pub(crate) bytes_arrived: u64,
    /// Distinct backbones behind the servers that took part. Five
    /// resellers of one backbone are ONE opinion, and "no server had it"
    /// otherwise reads like five independent votes.
    pub(crate) backbones: &'a [String],
    /// Age of the youngest article in the post, days. 0 when the NZB
    /// carries no usable date - see `GONE_MIN_AGE_DAYS`.
    pub(crate) post_age_days: u32,
}

/// How old a post must be before "every article 430" may be called DEAD
/// rather than "not here yet".
///
/// Both look identical from the pool's side. Propagation across the
/// backbones is normally minutes and occasionally hours; three days is
/// far outside that and still well inside the window where a retry could
/// plausibly have helped, so nothing that a retry would have fixed is
/// classified away. Below it (and for a dateless NZB, which reads as age
/// 0) the classic transient opening stands and the automatic retry runs.
pub(crate) const GONE_MIN_AGE_DAYS: u32 = 3;

pub(crate) fn incomplete_reason(incomplete: usize, derrs: u64, causes: &LossCauses) -> String {
    if incomplete > 0 {
        // A stall is OUR failure and has to say so, before any count is
        // read as evidence about the post. It opens with the connection
        // errors clause deliberately: `fail_kind` maps that to
        // `Transport`, which is exactly right here - retry freely, and
        // never report the release to an indexer as dead.
        if causes.stalled {
            let mut msg = format!(
                "download failed on connection errors: the connection pool stalled \
                 and the download was cut short with {incomplete} file(s) still \
                 incomplete, {derrs} decode/write errors."
            );
            // Do NOT claim the post is healthy when servers have said
            // otherwise. A run can both stall AND collect real 430s, and
            // the first version of this message told the user "not
            // evidence that anything is missing" about a release where
            // four providers had said exactly that, thousands of times.
            match causes.missing_430 {
                0 => msg.push_str(
                    " No server said any article was missing, so this is a fault on \
                     THIS machine or its link rather than evidence about the post - \
                     most of the outstanding articles were never requested.",
                ),
                n => msg.push_str(&format!(
                    " {n} segment(s) WERE confirmed missing by every server that has \
                     the post, so this release is short as well as cut off; the rest \
                     were never requested and say nothing either way.",
                )),
            }
            msg.push_str(" Retrying resumes from the journal and refetches only the gaps");
            if !causes.dead_servers.is_empty() {
                // The usual reason a pool starves into a stall: a server
                // in the fleet that never worked, so its share of the
                // articles has nowhere to go.
                msg.push_str(&format!(
                    "; no usable connection was ever made to {} - a server that never \
                     connects starves the pool of the articles routed to it",
                    causes.dead_servers.join(", ")
                ));
            }
            return msg;
        }
        // No server ever said "gone" - blaming the post would be a lie.
        let all_transport = causes.missing_430 == 0
            && causes.retention_excluded == 0
            && causes.transport_failed > 0;
        // Nothing whatsoever arrived, and every loss was a server saying
        // 430 with all of them answering: the post is not damaged, it is
        // GONE. Its own opening, because the daemon must treat it
        // differently from a post that is merely short - `FailKind::Gone`
        // still reports to an indexer but does NOT arm an automatic retry,
        // which against a wholly dead post only spends the same minutes
        // again. Positive evidence only (a segment census that accounts
        // for every article asked for), never the mere ABSENCE of other
        // causes - a caller with no per-slot accounting leaves the totals
        // at 0 and must fall through to the classic opening.
        let post_gone = causes.total_segments > 0
            && causes.missing_segments >= causes.total_segments
            && causes.bytes_arrived == 0
            && causes.missing_430 > 0
            && causes.transport_failed == 0
            && causes.retention_excluded == 0
            && causes.dead_servers.is_empty()
            && causes.post_age_days >= GONE_MIN_AGE_DAYS;
        // Every article accounted for, nothing lost anywhere, and files
        // short all the same: that is the yEnc coverage census speaking,
        // not missing segments. It must NOT open with "download
        // incomplete", which `fail_kind` maps to `MissingArticles` and
        // so arms an automatic retry - and the retry resumes from the
        // journal, replays exactly the same spans, and arrives at
        // exactly the same gap. A deterministic loop, whose message
        // meanwhile blamed the post for lost segments the census itself
        // says never happened ("1 file(s) with missing segments; 0 of
        // 240 segment(s) never arrived" in one breath). Falls through to
        // `FailKind::Local`, which does not retry.
        // `derrs == 0` belongs here as much as the rest of it. A decode
        // or write error decrements `remaining` and increments only the
        // error counters, so `missing_segments` stays at zero while the
        // failed article's bytes ARE a real gap - and the census flags
        // the slot. Without this term the opening claimed "every article
        // arrived and decoded" in the same breath as "1 decode/write
        // errors", and worse, it moved the job from
        // `FailKind::MissingArticles` to `Local`, which does not retry.
        // A corrupt article is exactly the case a journal-resume retry
        // can heal, so the previous opening was RIGHT for it: the bytes
        // were posted, they merely arrived damaged.
        let size_header_lies = causes.total_segments > 0
            && causes.missing_segments == 0
            && derrs == 0
            && causes.missing_430 == 0
            && causes.transport_failed == 0
            && causes.retention_excluded == 0;
        let mut msg = if size_header_lies {
            format!(
                "post size header disagrees with its parts: every article arrived and \
                 decoded, but {incomplete} file(s) declare more bytes than the post \
                 actually carries, {derrs} decode/write errors. Re-downloading cannot \
                 change this - the missing bytes were never posted"
            )
        } else if post_gone {
            format!(
                "post is gone: not one of the {} article(s) is on any server - all \
                 {incomplete} file(s) came back empty and not a byte arrived, \
                 {derrs} decode/write errors",
                causes.total_segments
            )
        } else if all_transport {
            format!(
                "download failed on connection errors: {incomplete} file(s) lost segments \
                 to transport failures ({} in all - no server said any article was \
                 missing), {derrs} decode/write errors",
                causes.transport_failed
            )
        } else {
            format!(
                "download incomplete: {incomplete} file(s) with missing segments, \
                 {derrs} decode/write errors"
            )
        };
        // The segment census, right behind the classifying clause. "94
        // file(s) with missing segments" was the whole story a user got,
        // and it is the same sentence whether one segment or twelve
        // thousand went astray. Suppressed on the `post_gone` opening,
        // which has already said every article of every file was absent.
        if causes.total_segments > 0 && !post_gone {
            msg.push_str(&format!(
                "; {} of {} segment(s) never arrived ({:.0} MB did)",
                causes.missing_segments,
                causes.total_segments,
                causes.bytes_arrived as f64 / 1e6
            ));
        }
        // No parity in the post: a confirmed-missing segment cannot be
        // rebuilt, so say so plainly. Deliberately a CLAUSE and not its
        // own verdict - an earlier cut made this final and stopped the
        // automatic retry, which broke the case the retry exists for: a
        // freshly posted article 430s on every server until it
        // propagates, and looks identical to one that is gone for good.
        // `post_gone` is the properly-gated version of that verdict (it
        // additionally requires nothing to have arrived and the post to
        // be older than propagation explains), so this stands down when
        // that fired rather than saying the same thing twice.
        if causes.missing_430 > 0 && causes.par2_slots == 0 && !post_gone {
            msg.push_str(&format!(
                "; {} segment(s) were confirmed missing by every server AND this post \
                 carries no PAR2 recovery data, so nothing can rebuild them. If the \
                 post is not brand new (where the servers may simply not have it yet), \
                 retrying will not help and another version is the answer",
                causes.missing_430
            ));
        }
        if causes.retention_excluded > 0 {
            msg.push_str(&format!(
                "; {} segment(s) were never requested because they are older than every \
                 server's configured retention - check retention_days in the server \
                 settings (0 = unlimited)",
                causes.retention_excluded
            ));
        }
        if causes.transport_failed > 0 && !all_transport {
            msg.push_str(&format!(
                "; {} segment(s) lost to transport/connection errors, not takedowns",
                causes.transport_failed
            ));
        }
        if causes.transport_failed > 0
            && let Some(e) = &causes.transport_sample
        {
            msg.push_str(&format!(" (first error: {e})"));
        }
        if !causes.dead_servers.is_empty() {
            msg.push_str(&format!(
                "; no usable connection to {} for the entire run (unreachable, or it \
                 refused the login) - segments only that server carries were counted \
                 as missing",
                causes.dead_servers.join(", ")
            ));
        }
        // How many INDEPENDENT opinions the verdict rests on. Only where
        // a server actually said 430: on a transport-only failure nobody
        // gave an opinion about the post at all, and naming the backbones
        // there would dress a provider wobble up as a unanimous verdict.
        if causes.missing_430 > 0 && !causes.backbones.is_empty() {
            msg.push_str(&format!(
                "; asked {} backbone(s): {} (resellers of one backbone answer alike)",
                causes.backbones.len(),
                causes.backbones.join(", ")
            ));
        }
        msg
    } else {
        // DECODE and WRITE errors share one counter but have opposite
        // remedies, and the sample says which happened: a decode error
        // means the SERVER handed us bytes that failed their own yEnc
        // CRC or length check, where free space and permissions are
        // irrelevant and a re-fetch (often from another provider) is the
        // fix. Sending someone to check their disk over a corrupt
        // article is a wild goose chase - found by the wire-corruption
        // leg of the 11 Aug soak, which serves deliberately damaged
        // articles from a healthy machine.
        let corrupt = causes
            .decode_sample
            .as_deref()
            .is_some_and(|s| s.starts_with("decode error"));
        let mut msg = if corrupt {
            format!(
                "the articles did not decode: {derrs} damaged article(s) and no missing \
                 segments - every article arrived, but their contents failed the yEnc \
                 checks, so the copies on the server are corrupt. Retrying re-fetches \
                 them, and a second provider usually carries a clean copy"
            )
        } else {
            format!(
                "could not write the download: {derrs} decode/write error(s) and no missing \
                 segments - every article arrived, so check free space, permissions and the \
                 log above"
            )
        };
        if let Some(e) = &causes.decode_sample {
            msg.push_str(&format!(" (first error: {e})"));
        }
        msg
    }
}

/// A zip an extraction pass reported and could not produce, with the
/// severity a caller needs to decide what to do about it.
pub(crate) struct UnsupportedArchive {
    /// What to show the user: the archive name, prefixed with its
    /// subdirectory when it isn't at the top of the output dir.
    pub display: String,
    /// `zip` / `spanned zip` / `split zip`.
    pub shape: &'static str,
    /// Nothing else landed, so this archive IS the payload - the user
    /// got nothing they can use. False for a sidecar (a `Subs/subs.zip`
    /// beside a feature that unpacked fine): still worth a log line,
    /// not worth alarming anyone over.
    pub blocking: bool,
}

impl UnsupportedArchive {
    /// The sentence the user reads, in the log and (when blocking) on
    /// the job in history.
    pub(crate) fn message(&self) -> String {
        if self.blocking {
            format!(
                "⚠ {} ({}) could not be unpacked - it is damaged, encrypted, or uses a \
                 compression method this build does not carry, so the payload is still \
                 packed. The verified archive is in the output directory; unpack it \
                 with your own tool.",
                self.display, self.shape
            )
        } else {
            format!(
                "note: {} ({}) left packed beside the payload - it could not be \
                 unpacked. The rest of the download is complete.",
                self.display, self.shape
            )
        }
    }
}

/// The first zip anywhere under the output dir, if any.
///
/// This is what downgrades "zip present" from a job failure to a
/// reported gap, so it has to see everything the detection side sees -
/// which since zip joined [`is_extractable_archive`] means the whole
/// tree, not just the top level: a pass now descends into a subfolder
/// zip and reports it, and a `false` this function could not explain
/// would fail the job with the wrong reason.
///
/// Traversal skips our own scratch dirs, exactly like `snapshot_recursive`.
pub(crate) fn unsupported_archive_present(root: &std::path::Path) -> Option<UnsupportedArchive> {
    // Usenet furniture is not payload: a directory holding nothing but a
    // zip and its par2 set still means the user got nothing usable.
    const FURNITURE: &[&str] = &[
        "par2", "sfv", "nfo", "nzb", "url", "txt", "srr", "srs", "diz", "md5", "sha", "sha256",
        "website",
    ];
    let mut dirs = vec![root.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        let Ok(rd) = std::fs::read_dir(&dirs[i]) else {
            i += 1;
            continue;
        };
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir())
                && !e.file_name().to_string_lossy().starts_with(".nzbfast")
            {
                dirs.push(e.path());
            }
        }
        i += 1;
    }
    dirs.sort();

    let mut first: Option<(nzbkit::zip::Finding, PathBuf)> = None;
    let mut parts: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for d in &dirs {
        for f in nzbkit::zip::scan(d) {
            // Still a zip part either way: whether or not we unpacked it,
            // the container is not the user's payload, so the test below
            // must not count it as one.
            parts.extend(f.parts.iter().cloned());
            // ...but a container whose contents ALREADY sit beside it is
            // not a gap. The spent-intermediate sweep keeps a container
            // whenever two independent sets share a directory (it cannot
            // prove either is consumed), so a job that unlocked two
            // encrypted zips from the passwords file and delivered both
            // payloads still ends with the containers on disk - and this
            // function reported one of them as "left packed ... it could
            // not be unpacked", which is the opposite of what happened.
            if zip_already_delivered(d, &f) {
                continue;
            }
            if first.is_none() {
                first = Some((f, d.clone()));
            }
        }
    }
    let (found, dir) = first?;

    // Payload = anything that isn't one of the zip parts and isn't
    // furniture. If none exists, the zip is all the user got.
    let mut payload = false;
    for d in &dirs {
        let Ok(rd) = std::fs::read_dir(d) else {
            continue;
        };
        for e in rd.flatten() {
            if !e.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let p = e.path();
            if parts.contains(&p) {
                continue;
            }
            // Our own bookkeeping (`.nzbfast.journal`) and the OS's
            // droppings are not the user's payload - counting the journal
            // as one made every still-packed post look like it had
            // landed something usable beside the archive.
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let ext = p
                .extension()
                .map(|x| x.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !FURNITURE.contains(&ext.as_str()) {
                payload = true;
            }
        }
    }

    let display = match dir.strip_prefix(root) {
        Ok(rel) if !rel.as_os_str().is_empty() => {
            format!("{}/{}", rel.display(), found.name)
        }
        _ => found.name.clone(),
    };
    Some(UnsupportedArchive {
        display,
        shape: found.shape.label(),
        blocking: !payload,
    })
}

/// Has this container's content already been written beside it?
///
/// True only when EVERY file entry exists at its own path under `dir`
/// with the declared uncompressed size. That is deliberately strict: a
/// partial match means some of the archive is still unexploded, which is
/// exactly the gap this module exists to report, and a size match is what
/// separates "we extracted it" from "an entry happens to share a name
/// with something in the download".
///
/// A container we cannot open answers false - unreadable is a gap, not a
/// delivery. So does one naming a path outside `dir` (`../`, absolute,
/// or a Windows drive letter): the extractor refuses those, so nothing
/// under `dir` can be its output, and resolving them here would let a
/// crafted entry name point the check at an unrelated file.
pub(crate) fn zip_already_delivered(dir: &std::path::Path, f: &nzbkit::zip::Finding) -> bool {
    let Ok(archive) = nzbkit::zip::Archive::open(&f.parts) else {
        return false;
    };
    let files: Vec<_> = archive.entries().iter().filter(|e| !e.is_dir).collect();
    if files.is_empty() {
        return false;
    }
    files.iter().all(|e| {
        let name = e.name.replace('\\', "/");
        let safe = !name.starts_with('/')
            && !name.contains(':')
            && name.split('/').all(|c| c != ".." && c != ".");
        safe && std::fs::metadata(dir.join(&name)).is_ok_and(|m| m.is_file() && m.len() == e.size())
    })
}

/// `Release.Name{{password}}.nzb` (also `{pw}` / `password=pw`) → the
/// embedded password (the conventions SABnzbd/NZBGet users and several
/// indexers rely on). Shared parser: crate::smart::name_password.
pub(crate) fn braces_password(nzb_path: &std::path::Path) -> Option<String> {
    let name = nzb_path.file_name()?.to_string_lossy();
    let name = name.trim_end_matches(".nzb");
    crate::smart::name_password(name).map(|(pw, _)| pw)
}

/// Is this demote one the 7z disk post-pass already owns? A top-level `.7z`
/// chase that gives up materializes its archive into the output directory,
/// which is exactly that pass's input.
///
/// It is filtered out of the unrar ladder entirely rather than added to
/// [`fallback_needs_disk_unpack`]'s exclusions, because its reason text
/// steers all three arms of that ladder and every one of them is wrong for a
/// 7z: the retention-cap wording reads as an unowned RAR set, the
/// encrypted-7z wording reads as a locked one, and both end at `try_unrar`
/// over a directory with no RAR in it - which answers false and fails a job
/// whose payload unpacks perfectly one pass later.
pub(crate) fn sevenz_disk_fallback(why: &str) -> bool {
    why.starts_with(nzbkit::extract::SEVENZ_DISK_FALLBACK_PREFIX)
        // A demoted top-level ZIP chase is the same story with a
        // different ladder step: the materialized `.zip` is the disk
        // post-pass's own input (its step 5), and its reason text -
        // "encrypted", "held-bytes cap" - would steer the RAR arms just
        // as wrongly.
        || why.starts_with(nzbkit::extract::ZIP_DISK_FALLBACK_PREFIX)
}

/// Does a level-0 extraction fallback leave its volumes UNOWNED, i.e. is the
/// on-disk unrar pass the only thing left that would unpack them?
///
/// Answered by exclusion rather than by listing the demote reasons, because
/// that list was wrong twice. Memory pressure ("held-bytes cap", "incomplete
/// mapping") once let a 2 GB NAS finish a 190 GB job with 431 loose volumes
/// and exit 0; then the integrity gate's own demotes (a BLAKE2sp-only entry,
/// a stored CRC that did not match, headers that do not describe a complete
/// file) shipped a directory of loose .rar volumes with no payload at all,
/// reported Completed. A demote says "let the disk path check it", and only
/// the unrar pass actually does that: it verifies CRC32 *and* BLAKE2sp, so a
/// set that is fine unpacks and the job still succeeds (cost: double I/O),
/// while an incomplete or header-broken one fails the job honestly. Any
/// reason added later therefore lands here by default.
///
/// The exclusions are the reasons somebody else already owns:
///   - "nested fallback:" (see `extract::nested_reason`) - the inner layer is
///     already materialized and belongs to the post-extraction pass, which
///     runs the inner PAR2 repair BEFORE unpacking; unrarring it here would
///     fail on damage that repair is about to fix.
///   - encrypted / password / compressed - the caller's own branches.
///   - "not a RAR volume", "never classified", "unclassified-holds budget" -
///     the slot never was an archive, so there is no set for unrar to open
///     and it would fail a job that is fine today.
///   - "materialized for repair" - the PAR2 path demoted the group itself so
///     par2 could see the volumes on disk, and it re-extracts them (and then
///     REMOVES them) as soon as the repair lands. Running the disk pass over
///     what it leaves behind finds no volumes at all.
///
/// A demote the 7z post-pass owns never reaches here at all - see
/// [`sevenz_disk_fallback`], which filters it out of the whole ladder.
pub(crate) fn fallback_needs_disk_unpack(why: &str) -> bool {
    !why.starts_with("nested fallback:")
        && !why.contains("encrypted")
        && !why.contains("password")
        && !why.contains("compressed")
        && !why.contains("not a RAR volume")
        && !why.contains("never classified")
        && !why.contains("unclassified-holds budget")
        && !why.contains("materialized for repair")
}

/// Unpack compressed RAR volumes with a bundled/system unrar. Volumes are
/// already PAR2-verified; without a password `-p-` refuses prompts
/// (encrypted sets are left alone), `-o+` overwrites partials from
/// aborted attempts. The daemon also calls this with a job's password
/// (mode=set_password) to unlock encrypted sets after the fact.
/// First volume of the RAR set: the lowest-numbered `.partNNN.rar` at any
/// digit width (part1 / part01 / part001 - literal ".part01."/".part1."
/// matching missed 3-digit sets and let a stray sample.rar/subs.rar shadow
/// the real first volume), else the lexically first plain `.rar`.
pub(crate) fn first_rar_volume(rars: &[PathBuf]) -> Option<PathBuf> {
    rars.iter()
        .min_by_key(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase();
            let part = n.rfind(".part").and_then(|i| {
                let d: String = n[i + 5..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                d.parse::<u64>().ok()
            });
            (part.is_none(), part.unwrap_or(0), n)
        })
        .cloned()
}

#[cfg(test)]
mod main_tests {
    use super::LossCauses;

    /// The 31 Jul failure this exists for. The pool wedged with 8851
    /// segments outstanding, the tail was aborted to recover, and the
    /// job was filed as "94 file(s) with missing segments" - which says
    /// the release is dead on every server the user has. It was not:
    /// almost none of those articles had been ASKED for.
    ///
    /// The counts cannot catch this on their own, which is the trap.
    /// Abandoned segments are neither `missing_430` (nobody said 430)
    /// nor `transport_failed` (nothing failed in transit), so every
    /// cause count is zero and the existing all-transport rule - which
    /// needs `transport_failed > 0` - cannot fire. Zero evidence of
    /// anything therefore produced the most damning message available.
    ///
    /// Two things have to hold: the text must not blame the post, and
    /// the daemon's classifier must read it as Transport, which is what
    /// keeps a healthy release from being reported to an indexer as dead
    /// and what shortens the retry.
    ///
    /// A run can BOTH stall and collect real 430s, and the first cut of
    /// the stall message told the user "not evidence that anything is
    /// missing" about a release four providers had just said was short -
    /// thousands of times. Denying the inference is right only when
    /// nothing was actually confirmed.
    #[test]
    fn a_stall_with_real_430s_reports_both_not_just_the_stall() {
        let both = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                stalled: true,
                missing_430: 2031,
                par2_slots: 4,
                ..no_causes()
            },
        );
        assert!(both.contains("connection pool stalled"), "{both}");
        assert!(
            both.contains("2031 segment(s) WERE confirmed missing"),
            "{both}"
        );
        assert!(
            !both.contains("No server said any article was missing"),
            "the stall must not vouch for a post that servers have called short: {both}"
        );
        // Still Transport: the run was cut off, and with parity present a
        // retry can still finish it.
        assert_eq!(
            crate::serve::fail_kind(&both),
            crate::serve::FailKind::Transport
        );
    }

    /// A post with confirmed-missing segments and NO parity cannot be
    /// rebuilt, and the message has to say so - the user is otherwise
    /// left retrying a release that arithmetic says will never complete.
    ///
    /// But it stays a CLAUSE, not a verdict. An earlier cut made this
    /// final and stopped the automatic retry; the daemon suite caught
    /// that it breaks the exact case the retry exists for, because a
    /// freshly posted article 430s on every server until it propagates
    /// and is indistinguishable from one that is gone for good. So the
    /// classification - and the single cheap retry - must not change.
    #[test]
    fn no_parity_and_confirmed_missing_is_said_plainly_but_still_retries() {
        let dead = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                missing_430: 2031,
                par2_slots: 0,
                ..no_causes()
            },
        );
        assert!(dead.contains("no PAR2 recovery data"), "{dead}");
        assert!(dead.contains("another version is the answer"), "{dead}");
        let kind = crate::serve::fail_kind(&dead);
        assert_eq!(kind, crate::serve::FailKind::MissingArticles);
        assert!(
            kind.transient(),
            "this must stay retryable: a brand-new post 430s everywhere until it \
             propagates, and refusing to retry would strand it permanently"
        );

        // Parity present: no such clause, nothing to warn about.
        let repairable = super::incomplete_reason(
            2,
            0,
            &LossCauses {
                missing_430: 5,
                par2_slots: 4,
                ..no_causes()
            },
        );
        assert!(
            !repairable.contains("no PAR2 recovery data"),
            "{repairable}"
        );
    }

    #[test]
    fn a_stalled_pool_does_not_report_a_healthy_post_as_missing() {
        let stalled = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                stalled: true,
                ..no_causes()
            },
        );
        assert!(
            !stalled.starts_with("download incomplete"),
            "a stall opened with the dead-post verdict: {stalled}"
        );
        assert!(stalled.contains("connection pool stalled"), "{stalled}");
        assert!(
            stalled.contains("rather than evidence about the post"),
            "the message has to deny the inference it used to invite: {stalled}"
        );
        assert_eq!(
            crate::serve::fail_kind(&stalled),
            crate::serve::FailKind::Transport,
            "a stall must classify as Transport - MissingArticles reports the release \
             to the indexer as dead and makes the user sit out a propagation wait for \
             a fault on their own machine"
        );

        // A server that never connected is the usual cause, and naming
        // it turns the message into something actionable.
        let dead = ["news.tweaknews.eu".to_string()];
        let with_dead = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                stalled: true,
                dead_servers: &dead,
                ..no_causes()
            },
        );
        assert!(with_dead.contains("news.tweaknews.eu"), "{with_dead}");

        // And the ordinary path is untouched: real 430s still read as a
        // short post, or the fix would hide genuine takedowns.
        let real = super::incomplete_reason(
            3,
            0,
            &LossCauses {
                missing_430: 9,
                ..no_causes()
            },
        );
        assert!(real.starts_with("download incomplete"), "{real}");
        assert_eq!(
            crate::serve::fail_kind(&real),
            crate::serve::FailKind::MissingArticles
        );
    }

    /// A LossCauses with nothing known - each test overrides one field.
    fn no_causes() -> LossCauses<'static> {
        LossCauses {
            missing_430: 0,
            retention_excluded: 0,
            transport_failed: 0,
            transport_sample: None,
            decode_sample: None,
            dead_servers: &[],
            par2_slots: 1,
            stalled: false,
            missing_segments: 0,
            total_segments: 0,
            bytes_arrived: 0,
            backbones: &[],
            post_age_days: 0,
        }
    }

    /// BUG (MEDIUM): a full disk, a permission error or a bad sector used
    /// to bail with a message that OPENED "download incomplete: 0 file(s)
    /// with missing segments" - which the daemon read as a dead post
    /// (reporting a healthy release to the indexer) and as transient
    /// (arming an automatic retry straight back onto the same full disk).
    /// The leading clause now says which of the two it was.
    #[test]
    fn a_local_write_fault_does_not_claim_missing_segments() {
        let c = LossCauses {
            missing_430: 3,
            ..no_causes()
        };
        let missing = super::incomplete_reason(3, 0, &c);
        assert!(missing.starts_with("download incomplete"));
        assert!(missing.contains("3 file(s) with missing segments"));
        // No known extra cause: nothing speculative appended.
        assert!(!missing.contains("retention"), "{missing}");
        assert!(!missing.contains("connection"), "{missing}");

        // Both happened: still the post's problem, and both counts show.
        let both = super::incomplete_reason(2, 5, &c);
        assert!(both.starts_with("download incomplete"));
        assert!(both.contains("5 decode/write errors"));

        // Nothing missing: the articles all arrived, so this is ours.
        let local = super::incomplete_reason(0, 5, &no_causes());
        assert!(!local.starts_with("download incomplete"), "{local}");
        assert!(local.contains("5 decode/write error"));
        assert!(local.contains("no missing segments"));

        // The first decode error rides along - a daemon user has no
        // console, and ENOSPC vs EACCES are different stories.
        let sampled = super::incomplete_reason(
            0,
            5,
            &LossCauses {
                decode_sample: Some("write a.mkv: No space left on device".into()),
                ..no_causes()
            },
        );
        assert!(sampled.contains("No space left on device"), "{sampled}");
    }

    /// A run where NO server ever said 430 is a provider problem, not a
    /// dead post: it must open with its own clause (FailKind::Transport
    /// - auto-retried, never reported to an indexer), and quote the
    /// first real error.
    #[test]
    fn all_transport_losses_do_not_blame_the_post() {
        let all_transport = super::incomplete_reason(
            5,
            0,
            &LossCauses {
                transport_failed: 40,
                transport_sample: Some("unexpected response to BODY: 999 huh".into()),
                ..no_causes()
            },
        );
        assert!(
            all_transport.starts_with("download failed on connection errors"),
            "{all_transport}"
        );
        assert!(
            !all_transport.starts_with("download incomplete"),
            "{all_transport}"
        );
        assert!(all_transport.contains("40 in all"), "{all_transport}");
        assert!(all_transport.contains("999 huh"), "{all_transport}");

        // One real 430 in the mix: the post IS damaged, so the classic
        // opening stands and transport losses append as a clause.
        let mixed = super::incomplete_reason(
            5,
            0,
            &LossCauses {
                missing_430: 2,
                transport_failed: 38,
                transport_sample: Some("read timed out".into()),
                ..no_causes()
            },
        );
        assert!(mixed.starts_with("download incomplete"), "{mixed}");
        assert!(
            mixed.contains("38 segment(s) lost to transport/connection errors"),
            "{mixed}"
        );
        assert!(mixed.contains("read timed out"), "{mixed}");
    }

    /// Hblife (Reddit, v1.0.12): "every file failed - incomplete articles
    /// - but SAB got them fine". The two silent ways an article goes
    /// Missing WITHOUT every server saying 430 - a retention_days setting
    /// excluding it pre-flight, and a server that never held a connection
    /// shrinking the unanimity mask - now name themselves in the failure
    /// summary. The opening clause must NOT move: the daemon's fail_kind
    /// and the *arr health mapping key on it.
    #[test]
    fn known_missing_causes_are_named_after_the_classifying_clause() {
        let ret = super::incomplete_reason(
            4,
            0,
            &LossCauses {
                retention_excluded: 1200,
                ..no_causes()
            },
        );
        assert!(ret.starts_with("download incomplete: 4 file(s)"), "{ret}");
        assert!(
            ret.contains("1200 segment(s) were never requested"),
            "{ret}"
        );
        assert!(ret.contains("retention_days"), "{ret}");

        let hosts = ["news.eu.example".to_string()];
        let dead = super::incomplete_reason(
            2,
            0,
            &LossCauses {
                missing_430: 9,
                dead_servers: &hosts,
                ..no_causes()
            },
        );
        assert!(dead.starts_with("download incomplete: 2 file(s)"), "{dead}");
        assert!(
            dead.contains("no usable connection to news.eu.example for the entire run"),
            "{dead}"
        );

        // Both causes, both named, both after the opening clause.
        let two = ["a.example".to_string(), "b.example".to_string()];
        let both = super::incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 1,
                retention_excluded: 7,
                dead_servers: &two,
                ..no_causes()
            },
        );
        assert!(both.starts_with("download incomplete: 1 file(s)"), "{both}");
        assert!(both.contains("7 segment(s)"), "{both}");
        assert!(both.contains("a.example, b.example"), "{both}");

        // A decode/write-only failure never mentions network causes -
        // every article arrived, so retention/server clauses would lie.
        let one = ["a.example".to_string()];
        let local = super::incomplete_reason(
            0,
            3,
            &LossCauses {
                dead_servers: &one,
                ..no_causes()
            },
        );
        assert!(!local.contains("a.example"), "{local}");
    }

    /// Field report, 31 Jul: "94 file(s) with missing segments" for a post that
    /// was in fact entirely gone. The file count is the same sentence
    /// whether one segment or twelve thousand went astray, so the census
    /// rides behind the classifying clause - and the clause itself does
    /// not move, because `fail_kind` and the *arr health mapping key on
    /// it.
    #[test]
    fn the_segment_census_rides_behind_the_opening() {
        let short = super::incomplete_reason(
            2,
            0,
            &LossCauses {
                missing_430: 3,
                missing_segments: 3,
                total_segments: 12_018,
                bytes_arrived: 8_100_000_000,
                ..no_causes()
            },
        );
        assert!(
            short.starts_with("download incomplete: 2 file(s)"),
            "{short}"
        );
        assert!(
            short.contains("3 of 12018 segment(s) never arrived"),
            "{short}"
        );
        assert!(short.contains("8100 MB did"), "{short}");
        // Nearly everything arrived: nothing here may say "gone".
        assert!(!short.starts_with("post is gone"), "{short}");

        // No per-slot accounting (any caller that cannot census): the
        // clause is suppressed rather than printing a bare "0 of 0".
        let censusless = super::incomplete_reason(
            2,
            0,
            &LossCauses {
                missing_430: 3,
                ..no_causes()
            },
        );
        assert!(
            !censusless.contains("segment(s) never arrived"),
            "{censusless}"
        );
    }

    /// A post where NOTHING is retrievable is not a damaged post, and
    /// treating it as one spends an automatic retry re-proving it. It
    /// earns its own opening (`FailKind::Gone`: still reported to an
    /// indexer, never auto-retried) - but ONLY on positive evidence,
    /// never on the absence of other causes.
    #[test]
    fn a_wholly_dead_post_says_so() {
        let backbones = ["omicron".to_string(), "usenetexpress".to_string()];
        let gone = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                missing_430: 12_018,
                missing_segments: 12_018,
                total_segments: 12_018,
                bytes_arrived: 0,
                backbones: &backbones,
                post_age_days: 21,
                ..no_causes()
            },
        );
        assert!(gone.starts_with("post is gone"), "{gone}");
        assert!(gone.contains("not one of the 12018 article(s)"), "{gone}");
        assert!(gone.contains("all 94 file(s)"), "{gone}");
        // Two providers of one backbone are ONE opinion; the count says so.
        assert!(
            gone.contains("asked 2 backbone(s): omicron, usenetexpress"),
            "{gone}"
        );
        // Already said every article was absent - no census on top.
        assert!(!gone.contains("segment(s) never arrived"), "{gone}");

        // One byte arrived: the post is damaged, not dead.
        let damaged = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                missing_430: 12_017,
                missing_segments: 12_017,
                total_segments: 12_018,
                bytes_arrived: 1,
                post_age_days: 21,
                ..no_causes()
            },
        );
        assert!(damaged.starts_with("download incomplete"), "{damaged}");

        // A server that never connected did not vote, so unanimity is
        // unproven and "gone" would be a lie - the dead-server clause
        // still owns this case.
        // A slot the coverage census flagged, with EVERY article
        // accounted for: the size header over-declared, re-downloading
        // cannot change it, and `fail_kind` must NOT read this as
        // missing articles (that arms a retry which replays the same
        // spans to the same gap).
        let lying = super::incomplete_reason(
            1,
            0,
            &LossCauses {
                total_segments: 240,
                ..no_causes()
            },
        );
        assert!(
            lying.starts_with("post size header disagrees with its parts"),
            "{lying}"
        );

        // ...but a DECODE error is not that. The article was posted and
        // arrived, it merely arrived damaged, so `missing_segments`
        // stays at zero while the bytes are a real gap. Claiming "every
        // article arrived and decoded" beside a non-zero decode count is
        // self-contradicting, and routing it away from MissingArticles
        // suppresses exactly the journal-resume retry that can heal it.
        let corrupt = super::incomplete_reason(
            1,
            1,
            &LossCauses {
                total_segments: 240,
                ..no_causes()
            },
        );
        assert!(
            corrupt.starts_with("download incomplete"),
            "a decode error must keep the retryable opening: {corrupt}"
        );

        let hosts = ["news.eu.example".to_string()];
        let unproven = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                missing_430: 12_018,
                missing_segments: 12_018,
                total_segments: 12_018,
                bytes_arrived: 0,
                dead_servers: &hosts,
                post_age_days: 21,
                ..no_causes()
            },
        );
        assert!(unproven.starts_with("download incomplete"), "{unproven}");

        // Transport losses in the mix: nobody proved anything about the
        // post, so it must not be declared dead.
        let flaky = super::incomplete_reason(
            94,
            0,
            &LossCauses {
                missing_430: 12_000,
                transport_failed: 18,
                missing_segments: 12_018,
                total_segments: 12_018,
                bytes_arrived: 0,
                post_age_days: 21,
                ..no_causes()
            },
        );
        assert!(flaky.starts_with("download incomplete"), "{flaky}");
    }

    /// A post nobody carries YET is the same picture as a post nobody
    /// carries ANY MORE - every article 430, not a byte arrived - and
    /// calling the first one dead would skip the automatic retry that
    /// exists precisely for it. (This is what the daemon's auto-retry
    /// tests caught: a release grabbed off an indexer minutes after its
    /// pre 430s everywhere until it propagates.)
    #[test]
    fn a_post_still_propagating_is_not_a_dead_one() {
        let fresh = |age| {
            super::incomplete_reason(
                8,
                0,
                &LossCauses {
                    missing_430: 900,
                    missing_segments: 900,
                    total_segments: 900,
                    bytes_arrived: 0,
                    post_age_days: age,
                    ..no_causes()
                },
            )
        };
        // Hours old, then a day, then the day before the threshold: all
        // still transient, all still eligible for the retry.
        for age in 0..super::GONE_MIN_AGE_DAYS {
            let m = fresh(age);
            assert!(m.starts_with("download incomplete"), "age {age}: {m}");
        }
        // Old enough that propagation cannot be the explanation.
        let old = fresh(super::GONE_MIN_AGE_DAYS);
        assert!(old.starts_with("post is gone"), "{old}");

        // An NZB with no usable date reads as age 0 - unknown is not old,
        // so it keeps the retry rather than being written off.
        assert_eq!(super::nzb_age_days(0), 0);
        assert_eq!(super::nzb_age_days(-1), 0);
    }

    /// Backbones are named only where a server actually said 430. On a
    /// transport-only failure nobody gave an opinion about the post, and
    /// listing the backbones there dresses a provider wobble up as a
    /// unanimous verdict.
    #[test]
    fn backbones_are_named_only_when_someone_voted() {
        let backbones = ["omicron".to_string()];
        let voted = super::incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 5,
                backbones: &backbones,
                ..no_causes()
            },
        );
        assert!(voted.contains("asked 1 backbone(s): omicron"), "{voted}");

        let no_vote = super::incomplete_reason(
            1,
            0,
            &LossCauses {
                transport_failed: 5,
                backbones: &backbones,
                ..no_causes()
            },
        );
        assert!(!no_vote.contains("backbone"), "{no_vote}");

        // A server addressed by IP names no backbone: `backbone_of` on a
        // dotted quad reduces to the label "0", which the collector drops
        // rather than printing a digit as though it were a provider.
        // (Caught live on a scratch daemon: "asked 1 backbone(s): 0".)
        assert_eq!(nzbkit::oracle::backbone_of("127.0.0.1"), "0");
        let none = super::incomplete_reason(
            1,
            0,
            &LossCauses {
                missing_430: 5,
                backbones: &[],
                ..no_causes()
            },
        );
        assert!(!none.contains("backbone"), "{none}");
    }

    /// The version tag appends and never disturbs the opening clause the
    /// daemon classifies on.
    #[test]
    fn build_tag_appends_without_moving_the_opening() {
        let tagged = super::with_build("download incomplete: 1 file(s)".into());
        assert!(
            tagged.starts_with("download incomplete: 1 file(s)"),
            "{tagged}"
        );
        assert!(tagged.contains("[nzbfast "), "{tagged}");
        assert!(tagged.ends_with(']'), "{tagged}");
    }
}

//! The download pipeline: get_with_progress, the whole one-pass fetch/decode/verify/extract drive shared by the get command and the daemon.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use std::path::Path;
use tracing::{info, warn};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_with_progress(
    config: &Path,
    nzb_path: &Path,
    out_dir: &Path,
    connections: usize,
    window: usize,
    decoders: usize,
    // PAR2 fast verify (TODO §10): CRC32-only in-stream block claims.
    // NZBFAST_FAST_VERIFY=0/1 overrides for bench A/Bs.
    fast_verify: bool,
    // M32 "lean" verify (slow-CPU boost): with fast verify on, also skip
    // the per-article yEnc CRC once PAR2 covers a file - in-stream
    // integrity rests on the PAR2 block CRC32 alone (one CRC32 layer
    // instead of two). Settle read-back + repair authority unchanged;
    // PAR2-less downloads keep full article CRCs automatically.
    verify_lean: bool,
    no_extract: bool,
    // Delete the spent recovery set once a repair has VERIFIED: the
    // daemon's `par_cleanup`, threaded in because the only place that
    // reads it today (the job tail's extension sweep) cannot see the
    // files this one deletes. Bears solely on the obfuscated disk-side
    // arm below, which removes magic-sniffed volumes no extension rule
    // can ever match; named `*.par2` stays the job tail's business.
    par_cleanup: bool,
    // Explicit archive password (CLI/API). NZB `<meta type="password">`
    // and the `Name{{password}}.nzb` filename convention are picked up
    // automatically; this overrides both.
    password: Option<String>,
    // TODO 101: this job's own yes to the volume-eating unpack, given in
    // the disk-full drawer. Consulted only in `low_disk` mode - `always`
    // is itself the consent and `off` cannot be talked into it - and
    // never enough on its own: the set must still have verified.
    eat_consent: bool,
    progress: Option<Arc<AtomicU64>>,
    hub: Option<Arc<StreamHub>>,
    // The nzo_id that owns this run's hub extractor (daemon jobs); empty for
    // CLI downloads. Tags the installed extractor so /stream ownership is
    // checked atomically with the clone (finding 11).
    stream_owner: &str,
    // net_done fires when the network phase is done (all articles
    // terminal, consumers drained) - the daemon starts the next job's
    // download then, while this job's tail (settle/repair/extract) runs.
    net_done: Option<tokio::sync::oneshot::Sender<()>>,
    budget: nzbkit::mem::MemBudget,
) -> Result<()> {
    use nzbkit::nzb::FileKind;
    use nzbkit::pool::{ArticleReq, BufPool, FetchOutcome, PoolConfig, fetch_all_multi_ctl};
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    // B4: on small-RAM boxes clamp job concurrency to the machine's tier
    // - spill-churn on an HDD costs more than the connections buy, so
    // consistency wins over peak. A clamp on the effective values, not a
    // config rewrite: settings stay portable and apply in full on bigger
    // hardware. Above 1 GB the caps are None and nothing changes.
    let (connections, window, decoders) = match nzbkit::mem::concurrency_caps() {
        Some(caps) => {
            let clamped = caps.apply(connections, window, decoders);
            if clamped != (connections, window, decoders) {
                info!(
                    target: "mem",
                    "small-RAM machine: clamping to {} conns × window {} × {} decoders (was {connections}×{window}×{decoders})",
                    clamped.0, clamped.1, clamped.2
                );
            }
            clamped
        }
        None => (connections, window, decoders),
    };
    // Rotational output on a NAS-class box: one decoder, so the article
    // lanes stop being seek lanes. See disk::decoders_for_storage for why
    // it is gated on the box as well as the disk.
    let decoders = {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        let storage = nzbkit::disk::detect_storage(out_dir);
        let picked = nzbkit::disk::decoders_for_storage(storage, cores, decoders);
        if picked != decoders {
            info!(
                target: "disk",
                "rotational output on a {cores}-core box: {picked} decoder \
                 (was {decoders}) to keep writes in order - override with \
                 NZBFAST_STORAGE=ssd"
            );
        }
        picked
    };

    // Queue-row activity token, advanced at section transitions only
    // (never per article): the daemon's queue payload reads it to say
    // what the pipeline is doing right now. No hub (CLI) means no one
    // is listening; a sidecar's hub is never read by the queue payload.
    let note_activity = |tok: &'static str| {
        if let Some(h) = &hub {
            h.activity.lock_ok().insert(stream_owner.to_string(), tok);
        }
    };
    let mut cfg_all = Config::load(config)?;
    // Which servers were taken OUT of the pool, and why. Only ever read
    // when the pool ends up empty: "no usable servers" named nothing at
    // all, so the one failure whose cause is entirely inside the user's
    // own settings was also the one that said least about itself.
    let mut sidelined: Vec<String> = Vec::new();
    // Soft-disabled servers never join a pool.
    cfg_all.servers.retain(|s| {
        if !s.enabled {
            info!(target: "config", "{} disabled - not in the pool", s.host);
            sidelined.push(format!("{} (switched off)", s.host));
        }
        s.enabled
    });
    // Exhausted block accounts (daemon-computed): out of the pool.
    if let Some(h) = &hub {
        let excluded = h.excluded_hosts.lock_ok().clone();
        if !excluded.is_empty() {
            cfg_all.servers.retain(|s| {
                let keep = !excluded.contains(&s.host);
                if !keep {
                    // The exclusion list carries three different reasons
                    // (busy with the active job, auth-refused, or a spent
                    // block account) - saying "exhausted" for all of them
                    // sent a bench investigation chasing a phantom quota
                    // bug, so say what it means.
                    info!(
                        target: "block",
                        "{} excluded for this download (busy with the active job, refused, or block-exhausted)",
                        s.host
                    );
                    sidelined
                        .push(format!("{} (busy, refused the login, or out of block data)", s.host));
                }
                keep
            });
        }
    }
    if cfg_all.servers.is_empty() {
        // Opens with the same four words either way: `fail_hint` keys the
        // dashboard's "open Server settings" button on that prefix.
        if sidelined.is_empty() {
            anyhow::bail!(
                "no usable servers: none are set up yet - add your provider in Server settings"
            );
        }
        anyhow::bail!(
            "no usable servers: every one you have set up is out of the pool right now - {}",
            sidelined.join(", ")
        );
    }
    let xml = std::fs::read(nzb_path).with_context(|| format!("reading {}", nzb_path.display()))?;
    // Arc'd because the in-stream PAR2 sniff (issue #14) needs the file
    // list on the decode threads, which outlive this scope's borrows.
    let nzb = Arc::new(Nzb::parse(&xml).context("parsing NZB")?);

    // The release's dominant group family - one NZB ≈ one family. Used
    // both for the oracle routing gate below and the ledger sink context.
    let job_family = {
        let mut freq: HashMap<&str, usize> = HashMap::new();
        for f in &nzb.files {
            for g in &f.groups {
                *freq.entry(g.as_str()).or_default() += 1;
            }
        }
        freq.into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(g, _)| nzbkit::oracle::group_family(g))
            .unwrap_or_else(|| "misc".into())
    };
    // Newest article post date, or None when the release is fully undated.
    // Undated jobs carry no usable age, so the oracle IGNORES them entirely
    // (no routing verdict, no ledger recording): an undated outcome would
    // otherwise mis-file as bucket 0 ("fresh") for the writer but read back
    // as bucket 6 ("3y+") on every read - a split-brain that can even
    // false-flag an undated retention-expired family as "being reaped".
    let job_posted: Option<i64> = nzb
        .files
        .iter()
        .filter_map(|f| (f.date > 0).then_some(f.date))
        .max();

    // M29 opt-in routing (`oracle_route`, OFF unless the daemon installed
    // a snapshot): drop enabled servers whose backbone the availability
    // ledger is confident is GONE for this release's (family, age-bucket),
    // saving the doomed primary round-trips on takedown'd content. Guarded
    // three ways: needs an installed snapshot, needs a real post date to
    // pick an age bucket, and NEVER empties the pool - so a wrong verdict
    // only costs latency (a surviving server + the fill ladder still try),
    // never the last path.
    if let Some(snap) = hub.as_ref().and_then(|h| h.route_gone.lock_ok().clone())
        && let Some(date) = job_posted
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        let age = ((now - date).max(0) / 86_400) as u32;
        let gone: Vec<String> = cfg_all
            .servers
            .iter()
            .filter(|s| snap.backbone_gone(&nzbkit::oracle::backbone_of(&s.host), &job_family, age))
            .map(|s| s.host.clone())
            .collect();
        // Only skip if at least one server survives (never the last path).
        if !gone.is_empty() && gone.len() < cfg_all.servers.len() {
            cfg_all.servers.retain(|s| {
                    let keep = !gone.contains(&s.host);
                    if !keep {
                        info!(
                            target: "oracle",
                            "{} predicted gone for {job_family} (age {age}d) - skipping it this download",
                            s.host
                        );
                    }
                    keep
                });
        }
    }

    // Archive password, in priority order: explicit > NZB meta > filename
    // convention. Only consulted if the set turns out to be encrypted.
    let password: Option<String> = match password {
        Some(p) => {
            info!(target: "password", "using supplied archive password");
            Some(p)
        }
        None => {
            if let Some(p) = nzb.password() {
                info!(target: "password", "NZB carries an archive password (meta)");
                Some(p.to_string())
            } else if let Some(p) = braces_password(nzb_path) {
                info!(target: "password", "archive password taken from {{{{…}}}} in the NZB filename");
                Some(p)
            } else {
                None
            }
        }
    };

    // Crash-resume journal: completed articles from a previous run of this
    // exact NZB are already on disk - at final offsets in their own file
    // (v1 lines) or at journal-recorded placements (direct-extracted
    // spans), which the restore pass copies back into volume files now.
    let (journal, resume_state) = nzbkit::journal::Journal::open(out_dir, &xml)?;
    let journal = Arc::new(journal);
    // Plaintext-once (`D`) records re-encrypt through the password; with
    // no password those articles refetch instead - never guessed.
    let restored = nzbkit::journal::restore(out_dir, &resume_state, password.as_deref());
    let mut completed = resume_state.completed;
    if !restored.ids.is_empty() {
        let moved: u64 = restored
            .seeds
            .iter()
            .flat_map(|s| s.spans.iter().map(|&(_, l)| l))
            .sum();
        println!(
            "resume: restored {} article(s) ({:.1} MB) from previous run's output files",
            restored.ids.len(),
            moved as f64 / 1e6
        );
        completed.extend(restored.ids.iter().cloned());
    }
    let resuming = !completed.is_empty();

    // Eager set: everything except PAR2 recovery volumes (minimality layer 1).
    // Par2-main segments go FIRST in the queue so the recovery set activates
    // within the first round-trips and verification runs in-stream.
    //
    // Obfuscated posts often ship recovery volumes but no plain `.par2`
    // index. The critical packets (Main/FileDesc/IFSC) are duplicated in
    // every volume, so bootstrap the set from the smallest volume instead -
    // its recovery slices also count toward any later repair.
    let has_main = nzb.files.iter().any(|f| f.kind() == FileKind::Par2Main);
    let bootstrap_vol: Option<usize> = if has_main {
        None
    } else {
        nzb.files
            .iter()
            .enumerate()
            .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
            .min_by_key(|(_, f)| f.bytes())
            .map(|(i, _)| i)
    };
    if let Some(bi) = bootstrap_vol {
        println!(
            "no main .par2 in NZB - bootstrapping set from smallest volume ({:.1} MB)",
            nzb.files[bi].bytes() as f64 / 1e6
        );
    }
    // Issue #14 on resume: a journal-completed head article never
    // re-decodes, so the in-stream sniff cannot fire for it - but its
    // bytes are on disk (restore() just wrote them), so classify restored
    // slots by reading the first bytes of their files instead. Slots
    // recognised here are deferred AT BUILD TIME (their unfetched
    // articles never enter the queue) and never elected bootstrap: a
    // resumed run settles and repairs from disk anyway, and an on-disk
    // volume needs no capture.
    let resume_vols: HashMap<usize, PathBuf> = restored
        .seeds
        .iter()
        .filter(|s| s.spans.iter().any(|&(o, l)| o == 0 && l >= 8))
        .filter_map(|s| {
            use std::io::Read;
            let p = out_dir.join(&s.name);
            let mut buf = [0u8; 8];
            (std::fs::File::open(&p)
                .and_then(|mut f| f.read_exact(&mut buf))
                .is_ok()
                && &buf == nzbkit::par2::MAGIC)
                .then_some((s.slot, p))
        })
        .collect();
    let mut resume_sniffed_slots: Vec<usize> = Vec::new();
    let mut resume_deferred_arts = 0usize;
    let mut resume_deferred_bytes = 0u64;
    // Bytes of articles this resume will SKIP because the journal already
    // has them on disk. Published on the hub below (never added into the
    // progress counter) so the queue row can pick the bar up where the
    // last run left it - see the publish site for why the two stay apart.
    let mut resume_have_bytes = 0u64;
    let mut slots: Vec<Arc<FileSlot>> = Vec::new();
    let mut id_to_slot: crate::unpack::IdSlots = HashMap::new();
    // UX §15 honest percentage. `fetch_plan` is the declared NZB byte
    // size of every article this run is responsible for, `fetch_done`
    // the same measure for the ones already accounted for. Both count
    // ONE thing - declared bytes of the eager article set - so the bar
    // reaches exactly 100% when the fetch drains and can never pass it.
    //
    // The pair it replaces on the queue row could do neither: the
    // numerator was decoded payload (all slots, PAR2 included), the
    // denominator the NZB's encoded bytes minus recovery volumes. A
    // clean download therefore stopped around 97% still claiming a
    // gigabyte "left" that did not exist, and a damaged one - where the
    // extra recovery bytes land on the numerator alone - pinned at
    // 100% / 0 left with articles still in flight.
    let mut plan_bytes = 0u64;
    // Slot index → NZB file index, for the in-stream sniff and the repair
    // planner (slots skip NZB-classified volumes, so the numberings differ).
    let mut slot_file: Vec<usize> = Vec::new();
    // M11: per-slot article ladder (encoded cumulative offset → id) for
    // seek promotion; aligned with `slots` (empty for par2 slots).
    let mut slot_arts: Vec<(Vec<(u64, String)>, u64)> = Vec::new();
    let mut par2_ids: Vec<ArticleReq> = Vec::new();
    // Each data file's FIRST segment goes right after the par2 index:
    // the offset-0 article carries the RAR signature + headers, so the
    // extractor classifies every slot within the first round-trips instead
    // of holding gigabytes of unclassifiable spans (M3 scheduling rule).
    let mut head_ids: Vec<ArticleReq> = Vec::new();
    let mut data_ids: Vec<ArticleReq> = Vec::new();
    let mut dup_segments = 0usize;
    for (fi, f) in nzb.files.iter().enumerate() {
        // Articles inherit their file's post date; per-server retention
        // routing (M14e) keys off this age.
        let age_days = nzb_age_days(f.date);
        let is_bootstrap = bootstrap_vol == Some(fi);
        if f.kind() == FileKind::Par2Volume && !is_bootstrap {
            continue;
        }
        let is_par2_main = f.kind() == FileKind::Par2Main || is_bootstrap;
        let idx = slots.len();
        let resume_sniffed = !is_par2_main && resume_vols.contains_key(&idx);
        if resume_sniffed {
            resume_sniffed_slots.push(idx);
        }
        slot_file.push(fi);
        slots.push(Arc::new(FileSlot {
            hint: f
                .filename_hint()
                .map(str::to_string)
                .unwrap_or_else(|| format!("file{idx:03}")),
            is_par2_main,
            par2_sniffed: std::sync::atomic::AtomicBool::new(resume_sniffed),
            // A parser-dropped segment (empty or wire-unsafe message-id)
            // is one this slot can never fetch: it counts toward the
            // total and starts out missing, so the file either repairs
            // through PAR2 or fails the job - it must not vanish from
            // the manifest and finish green zero-filled.
            total_segments: f.segments.len() + f.dropped_segments,
            remaining: AtomicUsize::new(f.segments.len()),
            missing: AtomicUsize::new(f.dropped_segments),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(is_par2_main.then(Vec::new)),
        }));
        let mut arts: Vec<(u64, String)> = Vec::new();
        let mut enc_cum = 0u64;
        for (si, seg) in f.segments.iter().enumerate() {
            let bracketed = format!("<{}>", seg.message_id);
            // Malformed NZBs repeat a message-id, within one file or across
            // two. The pool fetches each id exactly once (a second request
            // would never turn terminal - the duplicate-id forever-hang),
            // so a repeat is settled here: the FIRST occurrence owns the
            // article. A same-file repeat is covered by that one fetch
            // (yEnc offsets come from the article, not the NZB); a
            // cross-file repeat means these bytes never reach THIS file -
            // count it missing and let PAR2 repair fill the hole.
            if let Some(&(owner, _)) = id_to_slot.get(&bracketed) {
                dup_segments += 1;
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                if owner as usize != idx {
                    slots[idx].missing.fetch_add(1, Ordering::Relaxed);
                }
                enc_cum += seg.bytes;
                continue;
            }
            id_to_slot.insert(bracketed.clone(), (idx as u32, seg.bytes as u32));
            // Every article with an owner is this run's responsibility -
            // including the ones already satisfied below, which are added
            // to `have_bytes` as well so a resumed job's bar starts where
            // its bytes actually are instead of at zero. A duplicate id
            // (the `continue` above) is fetched once under its first
            // owner and never counted twice; a segment the parser dropped
            // has no entry at all and so cannot hold the bar short of
            // 100%.
            plan_bytes += seg.bytes;
            if !is_par2_main {
                arts.push((enc_cum, bracketed.clone()));
            }
            enc_cum += seg.bytes;
            // On resume, journal-completed data articles are skipped -
            // their bytes are on disk and the settle pass verifies them.
            // Par2-main articles always refetch (tiny; activation needs
            // the packets in memory).
            if !is_par2_main && completed.contains(&bracketed) {
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                resume_have_bytes += seg.bytes;
                continue;
            }
            // A resume-recognised recovery volume: everything not already
            // on disk is deferred outright - never queued.
            if resume_sniffed {
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                slots[idx].deferred.fetch_add(1, Ordering::Relaxed);
                resume_deferred_arts += 1;
                resume_deferred_bytes += seg.bytes;
                continue;
            }
            let req = ArticleReq {
                id: bracketed,
                age_days,
            };
            if is_par2_main {
                par2_ids.push(req);
            } else if si == 0 {
                head_ids.push(req);
            } else {
                data_ids.push(req);
            }
        }
        slot_arts.push((arts, enc_cum));
    }
    if dup_segments > 0 {
        println!("  ⚠ NZB repeats {dup_segments} segment id(s) - each article is fetched once");
    }
    // Publish the fetch plan before the first article can land. The
    // daemon zeroed both counters at the Downloading transition, and the
    // queue payload treats a zero plan as "not ready yet" and falls back
    // to the old arithmetic, so the window between the two is covered.
    // `fetch_done` is the local handle either way: a CLI run has no hub
    // and pays one uncontended atomic add per terminal article.
    let fetch_done = hub
        .as_ref()
        .map(|h| h.fetch_done.clone())
        .unwrap_or_default();
    // Seeded with what is in hand before a byte moves: the articles the
    // journal already satisfied, plus the recovery volumes a resume
    // recognised on disk and deliberately never queued. Both are bytes of
    // the plan this run is responsible for, so a resumed job's bar
    // continues from where it stopped instead of restarting at 0%.
    fetch_done.store(
        resume_have_bytes.saturating_add(resume_deferred_bytes),
        Ordering::Relaxed,
    );
    if let Some(h) = hub.as_ref() {
        h.fetch_plan.store(plan_bytes, Ordering::Relaxed);
    }
    // M11 head+tail burst (hub-attached runs, i.e. the daemon): the first
    // volume's opening ~16 MB and the last volume's closing ~8 MB jump the
    // data queue, so a media player gets the container header AND the
    // end-of-file seek index (MKV Cues / MP4 moov both live at the end)
    // within seconds of queue-add. These are ordinary file bytes - nothing
    // is wasted if nobody ever streams.
    if hub.is_some() {
        let mut data_slots: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_par2_main)
            .map(|(i, _)| i)
            .collect();
        data_slots.sort_by_key(|&i| nzbkit::extract::vol_sort_key(&slots[i].hint));
        let mut burst: std::collections::HashSet<&str> = Default::default();
        if let Some(&first) = data_slots.first() {
            for (off, id) in &slot_arts[first].0 {
                if *off >= 16_000_000 {
                    break;
                }
                burst.insert(id.as_str());
            }
        }
        if let Some(&last) = data_slots.last() {
            let (arts, total) = &slot_arts[last];
            for (off, id) in arts.iter().rev() {
                if off + 8_000_000 <= *total {
                    break;
                }
                burst.insert(id.as_str());
            }
        }
        if !burst.is_empty() {
            let (mut early, rest): (Vec<_>, Vec<_>) = data_ids
                .into_iter()
                .partition(|r| burst.contains(r.id.as_str()));
            early.extend(rest);
            data_ids = early;
        }
    }
    let mut ids = par2_ids;
    ids.extend(head_ids);
    ids.extend(data_ids);
    if resuming {
        println!(
            "resuming: {} article(s) already on disk, {} to fetch",
            completed.len(),
            ids.len()
        );
    }

    let verifier_seed_slots: Vec<usize> = slots
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            // remaining == 0 alone is not "complete": a slot whose
            // segments were parser-dropped (or claimed by another file)
            // never had anything to fetch and is missing, not done.
            !s.is_par2_main
                && s.remaining.load(Ordering::Relaxed) == 0
                && s.missing.load(Ordering::Relaxed) == 0
        })
        .map(|(i, _)| i)
        .collect();

    let verifier = Arc::new(nzbkit::live::LiveVerifier::with_partials_cap(
        slots.len(),
        budget.partials_cap(),
    ));
    // Fast verify (TODO §10): default ON - bench-validated 2.9× on
    // CPU-bound boxes (Europe bench box E-core round, 21 Jul), nzbget parity.
    // The env var overrides flag/config either way (bench A/Bs).
    let fast_verify = match std::env::var("NZBFAST_FAST_VERIFY") {
        Ok(v) => v != "0",
        Err(_) => fast_verify,
    };
    verifier.set_fast_verify(fast_verify);
    verifier.set_lean(fast_verify && verify_lean);
    if !fast_verify {
        println!("verify: full (per-block MD5+CRC32)");
    } else if verify_lean {
        println!(
            "verify: lean - article CRCs skipped once PAR2 covers a file \
             (single-CRC32 in-stream; end-of-job verification unchanged)"
        );
    }
    let n_par2_slots = slots.iter().filter(|s| s.is_par2_main).count();
    let par2_outstanding = Arc::new(AtomicUsize::new(n_par2_slots));
    // NOTE: no `verifier.set_off()` when n_par2_slots == 0 any more. A
    // fully obfuscated post (issue #14) names no par2 anywhere, yet its
    // recovery volumes identify themselves by packet magic in the first
    // round-trips - the verifier stays in Waiting so that sniff can still
    // activate the set mid-download. For a post with genuinely no par2
    // the Waiting cost is a few bytes of pre-span bookkeeping per article
    // and a 16 KiB head capture per file, and settle behaves as before.
    //
    // Issue #14 runtime state: slots reclassified as recovery data by the
    // offset-0 `PAR2\0PKT` sniff. A dynamic bootstrap is only electable
    // when the NZB gave us no par2 slot at all - otherwise the activation
    // counter belongs to the static slots and sniffed volumes just defer.
    let sniff = Arc::new(SniffCtl {
        nzb: nzb.clone(),
        slot_file: slot_file.clone(),
        allow_bootstrap: n_par2_slots == 0,
        state: Default::default(),
        deferred_articles: AtomicUsize::new(resume_deferred_arts),
        deferred_bytes: AtomicU64::new(resume_deferred_bytes),
        // The same counter the resume seeding above already credited
        // its deferred bytes into - a live deferral has to reach it too
        // (Codex sweep 2, 3 Aug ML2).
        fetch_done: fetch_done.clone(),
    });
    if !resume_sniffed_slots.is_empty() {
        println!(
            "resume: {} restored file(s) are recovery volumes by content - \
             deferring {resume_deferred_arts} unfetched article(s)",
            resume_sniffed_slots.len()
        );
        // Registered as sniffed-but-never-bootstrap: the repair planner
        // sees them (deferred_files) while the election stays open for
        // volumes whose heads still fetch and decode this run.
        sniff
            .state
            .lock_ok()
            .sniffed
            .extend(resume_sniffed_slots.iter().copied());
    }
    // All file writing goes through the extractor: plain files write
    // through; store-mode RAR volumes extract in-stream (M3). Resumed
    // runs without NZBFAST_RESUME_MAP disable in-stream mapping
    // (restored spans then never flow through `write`, so headers would
    // be incomplete) - volumes materialize and extraction happens from
    // disk after verification instead. With it, the replay below feeds
    // the restored spans through `write` first, and mapping proceeds as
    // on a fresh run.
    // The archive shape prints ONCE, folded into the first volume line
    // that lands after the mappers have worked it out - several decode
    // consumers race for that line, so the flag is shared.
    let shape_said = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // §94 A: resumed jobs map in-stream. Restored spans REPLAY through
    // the normal write path before the network opens, so the mappers
    // re-derive their state from replayed headers and the run continues
    // one-pass; only the still-missing fraction transits the wire, and
    // only the resumed fraction is read back off disk. Opt-in while it
    // soaks (NZBFAST_RESUME_MAP=1); without it a resumed run
    // materializes volumes and extracts from disk, as before. `resume`
    // stays true either way - writers must adopt restored files without
    // truncating them.
    let resume_map =
        resuming && !no_extract && std::env::var("NZBFAST_RESUME_MAP").is_ok_and(|v| v == "1");
    let extractor = Arc::new(nzbkit::extract::Extractor::with_resume(
        out_dir,
        slots.len(),
        !no_extract && (!resuming || resume_map),
        resuming,
    ));
    // The root has to know its own Arc before any span arrives, or a
    // top-level chase (a posted .7z) has nothing for its worker to reach
    // the extractor through and quietly declines. Unconditional: the
    // promote hook below anchors too, but it only exists on the daemon
    // path, and `nzbfast get` chases the same archives.
    extractor.anchor();
    // §94 B, opt-in while it soaks (NZBFAST_CHASE_VERIFY_GATE=1): the
    // chase decode gates on the PAR2 verified-block watermark, so a
    // repair can never rewrite consumed bytes and the "repair rewrote
    // chased bytes" demote becomes unreachable for gated sets. The
    // frontier's conflict tripwire stays armed underneath either way.
    if std::env::var("NZBFAST_CHASE_VERIFY_GATE").is_ok_and(|v| v == "1") {
        let gate = nzbkit::live::VerifyGate::new(slots.len());
        verifier.set_gate(gate.clone());
        extractor.set_verify_gate(gate);
    }
    extractor.set_holds_cap(budget.holds_cap());
    // One-pass zip, split sets: a byte-split zip cannot be sized from
    // its own bytes (no part carries a container-sizing header, unlike
    // 7z), so the NZB's file list - which we have and the extractor
    // does not - declares each set's part count. Declared only when the
    // indices run exactly 1..=n: a set the NZB itself has a hole in can
    // never stream, and not declaring it keeps every part on the
    // phase-1 disk path.
    {
        let mut sets: HashMap<String, Vec<u32>> = HashMap::new();
        for s in slots.iter().filter(|s| !s.is_par2_main) {
            // Bare-numeric sets (`movie.001`, no `.zip.` infix) declare
            // too - the declaration is speculative (RAR numeric volumes
            // share the grammar), and that is fine: RAR and 7z magic
            // classify before the zip split arm is consulted, and a
            // declared set whose part 1 does not sniff `PK\x03\x04`
            // forfeits to the disk path exactly as an undeclared one
            // would have landed there.
            if let Some((base, idx)) = nzbkit::zip::split_part_name(&s.hint)
                .or_else(|| nzbkit::zip::numeric_split_part_name(&s.hint))
            {
                sets.entry(base).or_default().push(idx);
            }
        }
        for (base, mut idxs) in sets {
            idxs.sort_unstable();
            let n = idxs.len() as u32;
            if idxs.first() == Some(&1)
                && idxs.last() == Some(&n)
                && idxs.windows(2).all(|w| w[0] < w[1])
            {
                extractor.declare_zip_split(&base, n);
            }
        }
    }
    // An inner file's declared `unpacked_size` is an attacker-controlled
    // RAR header vint, and on Linux preallocation is a real fallocate - so
    // a few-hundred-KB post declaring 8 TB used to genuinely reserve the
    // volume's free space until the finish-time gates demoted it. The
    // NZB's own posted byte count is the defensible bound: nothing posted
    // here can legitimately unpack to more than what was posted (compressed
    // inner files can, but preallocation is an optimisation - writes past
    // the reservation extend the file exactly as they do on macOS, where
    // nothing is reserved at all). Deliberately a RESERVATION ceiling and
    // not a clamp on the declared size, which resume truncation and the
    // reported extracted size both depend on.
    // The posted count is itself an untrusted attribute an attacker can
    // inflate alongside the yEnc `size=`, and an NZB with NO byte
    // attributes used to get no ceiling at all - so the post's article
    // geometry (articles x a generous per-article max) bounds it both
    // ways. Same bound as the recovery-volume side-fetch.
    extractor.set_prealloc_ceiling(crate::repair::volume_prealloc_cap(&nzb));
    // Decompression-bomb budget for the IN-STREAM extractor - the same
    // guard `write_archives_to`/`extract_one_sevenz` put on the disk and
    // post-pass sinks, which until now covered only the fallback and not
    // the default path. Shared across every inner file and every nesting
    // level, so a bomb split over many outputs gets one allowance.
    if let Some(free) = crate::serve::free_bytes(out_dir) {
        extractor.set_extract_budget(free.saturating_sub(EXTRACT_RESERVE));
        // Holds-paging scratch ceiling: transient relief for the RAM
        // holds cap, not a second copy of the download - 4x the RAM cap,
        // and never more than a quarter of post-reserve free space (the
        // payload itself still has to fit). Exceeding it demotes with
        // the same "held-bytes cap" reasons as a RAM breach.
        extractor.set_holds_scratch_cap(
            (4 * budget.holds_cap() as u64).min(free.saturating_sub(EXTRACT_RESERVE) / 4),
        );
    }
    // With a password, RAR5 encrypted STORE sets stay on the in-stream
    // path: ciphertext assembles at plain store offsets and one AES pass
    // at finish decrypts it - no materialized volumes, no unrar.
    if let Some(pw) = &password {
        extractor.set_password(pw);
    }
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
    {
        let dir = out_dir.to_path_buf();
        let tried: std::sync::Mutex<std::collections::HashSet<([u8; 16], String)>> =
            Default::default();
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
    // That AES pass replaces the ciphertext this journal's placement
    // records point INTO. Once a file holds plaintext it is no longer the
    // bytes the journal describes, so a resume that still trusted it would
    // copy translated fragments out of it into the volume files and mark
    // those articles restored - skipping the refetch, and without PAR2
    // looping forever on poisoned local bytes while the provider still has
    // every original article. Gate the publish on retiring the claim
    // first: the extractor hands over the output names and moves no byte
    // until this returns Ok, and `invalidate` is durable before it does.
    //
    // Weak, like the promote hook: the extractor outlives this scope, and
    // a strong clone parked in it would defeat the `Arc::try_unwrap` that
    // retires the whole journal after a verified finish. A journal that is
    // already gone claims nothing, so publishing is free.
    {
        let j = Arc::downgrade(&journal);
        extractor.set_decrypt_barrier(Arc::new(move |names: &[String]| match j.upgrade() {
            Some(j) => j.invalidate(names),
            None => Ok(()),
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
    // Fully-resumed slots see no articles - seed their names so PAR2
    // matching and read-back verification still reach them.
    for &si in &verifier_seed_slots {
        verifier.set_name_hint(si, &slots[si].hint);
    }
    // M11: seek re-prioritization handle. QueueControl attaches to the
    // pool's pending queue when the fetch starts; SeekCtl turns player
    // read positions into promotions through it.
    let queue_ctl = Arc::new(nzbkit::pool::QueueControl::default());
    let abort_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The promote ladder is built for EVERY run, not just the daemon's.
    // A player seek needs the hub; the 7z tail prefetch does not - it is
    // the extractor asking for the articles carrying an archive's end
    // header, and without it the chase cannot read the archive map until
    // the tail arrives on its own, which in a sequential download is
    // last. That turns one-pass into a decode burst at the end, and it
    // denies drop-behind trimming the read watermark it needs, so a `get`
    // of a large .7z demoted where the daemon streamed it.
    let seek = {
        let mut vol_slots: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_par2_main)
            .map(|(i, _)| i)
            .collect();
        vol_slots.sort_by_key(|&i| nzbkit::extract::vol_sort_key(&slots[i].hint));
        // First insertion wins on a duplicate hint - same article ladder
        // either way for the split-volume sets where hints repeat.
        let mut slot_by_name = std::collections::HashMap::new();
        for &i in &vol_slots {
            slot_by_name
                .entry(nzbkit::disk::sanitize_filename(&slots[i].hint))
                .or_insert(i);
        }
        let slot_articles = std::mem::take(&mut slot_arts);
        let observed = slot_articles
            .iter()
            .map(|_| std::sync::atomic::AtomicBool::new(false))
            .collect();
        Arc::new(SeekCtl {
            slot_articles,
            ctl: queue_ctl.clone(),
            extractor: extractor.clone(),
            vol_slots,
            slot_by_name,
            observed_by_name: std::sync::RwLock::new(std::collections::HashMap::new()),
            observed,
        })
    };
    // The decode consumers register observed yEnc names (obfuscated
    // sets) - cloned HERE because `seek` itself moves into the hub.
    let seek_names = seek.clone();
    // Weak - the hook must not pin the SeekCtl/Extractor pair into a
    // reference cycle.
    let weak_seek = Arc::downgrade(&seek);
    extractor.set_promote_hook(Arc::new(
        move |name: &str, size: u64, spans: &[(u64, u64)], urgent: bool| {
            if let Some(s) = weak_seek.upgrade() {
                s.promote_output_spans(name, size, spans, urgent);
            }
        },
    ));
    if let Some(h) = &hub {
        *h.extractor.lock_ok() = Some((stream_owner.to_string(), extractor.clone()));
        *h.verifier.lock_ok() = Some(verifier.clone());
        *h.seek.lock_ok() = Some(seek);
        *h.abort.lock_ok() = Some(abort_flag.clone());
        *h.queue_ctl.lock_ok() = Some(queue_ctl.clone());
    }
    let eager_bytes = nzb.eager_bytes();
    println!(
        "{}: {} files ({:.1} MB eager of {:.1} MB total) → {}",
        nzb_path.display(),
        slots.len(),
        eager_bytes as f64 / 1e6,
        nzb.total_bytes() as f64 / 1e6,
        out_dir.display()
    );

    let buf_pool = BufPool::new(budget.bufpool_bufs());
    // Decoded-payload buffers, recycled the same way as the network-side
    // `buf_pool` - the decoder writes each article's bytes into a buffer
    // taken from here and the consumer returns it after write+verify, so
    // the hot path does no per-article ~800 KB payload allocation.
    let out_pool = BufPool::new(budget.bufpool_bufs());
    // Stall-detection timeout; env override exists for the chaos suite
    // (a mock stall shouldn't cost a test 30 wall-clock seconds).
    let read_timeout = std::env::var("NZBFAST_READ_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or_else(|| PoolConfig::default().read_timeout);
    // TODO 96.1, dark until benched: two-phase adaptive read bounds in
    // place of the flat whole-response timeout.
    let adaptive_timeout = std::env::var("NZBFAST_ADAPTIVE_TIMEOUT").is_ok_and(|v| v == "1");
    // Per-server budget: the CLI --connections is a ceiling; a server's
    // config `connections` (its account limit) caps its own pool; a
    // fresh auto-tuned knee (conntune.json, M7b.1) caps below that -
    // over-asking a provider measured 3-4× SLOWER than the knee.
    // Two knees are NOT applied: any knee while the auto_connections
    // toggle is off (off must mean off - the user's escape hatch from a
    // bad probe), and a `suspect` one (a low knee awaiting a second
    // probe's corroboration) even while it's on.
    let tuned = if crate::conntune::enabled(config) {
        crate::conntune::load(config)
    } else {
        Default::default()
    };
    // Say what the cap IS and what it is capping, not just a bare
    // number. `connection auto-tune: news.example.com 6` was the entire
    // explanation a v1.0.14 tester had for why the 24 he had typed into
    // Settings never took effect, and it read as a status line rather
    // than as "something overrode you". Name the asked-for count and
    // the switch that turns it off.
    let tuned_note: Vec<String> = cfg_all
        .servers
        .iter()
        .filter_map(|s| {
            let t = tuned.get(&s.host)?;
            let asked = crate::conntune::effective_limit(connections, s.connections);
            (!t.suspect && t.connections > 0 && t.connections < asked)
                .then(|| format!("{} capped at {} of {asked}", s.host, t.connections))
        })
        .collect();
    if !tuned_note.is_empty() {
        println!(
            "  connection auto-tune: {} (measured sweet spot; \
             Settings → Auto-tune connections turns this off)",
            tuned_note.join(" · ")
        );
    }
    // Config is reloaded for every daemon job, while the warm pool lives
    // across jobs. Reconcile the cache before building the new fleet so
    // sessions authenticated with a removed password/user, proxy or bind
    // address stop occupying the provider's connection cap immediately.
    if let Some(warm) = hub.as_ref().and_then(|h| h.warm()) {
        warm.retain_servers(&cfg_all.servers).await;
        // Idle release is settled PER SERVER and read straight off the
        // config this job is about to use, so a provider added, removed
        // or re-tuned since the last job is reflected before any of its
        // connections are parked.
        warm.set_release_policies(&cfg_all.servers);
    }
    // Sidecar connection borrowing: caps a host's pool below its normal
    // budget when this hub is a prefetch sidecar borrowing from a server
    // that is busy on the active job. Empty on every other hub.
    let host_caps = hub
        .as_ref()
        .map(|h| h.host_conn_caps.lock_ok().clone())
        .unwrap_or_default();
    let mut servers: Vec<_> = cfg_all
        .servers
        .iter()
        .map(|s| {
            let mut base = connections.min(s.connections.max(1) as usize);
            if let Some(cap) = host_caps.get(&s.host) {
                base = base.min((*cap).max(1));
            }
            let cfg = PoolConfig {
                connections: match tuned.get(&s.host) {
                    Some(t) if t.connections > 0 && !t.suspect => base.min(t.connections),
                    _ => base,
                },
                window,
                buf_pool: Some(buf_pool.clone()),
                read_timeout,
                adaptive_timeout,
                rate: hub.as_ref().map(|h| h.rate.clone()),
                // B3: wire-side in-flight bytes are budget-exempt (window
                // × connections × ~800 KB); this cap throttles pipeline
                // top-up globally when the budget is small. Shared uses
                // the same value in every server's config - the counter
                // it gates lives on the pool's Shared state.
                inflight_cap: budget.inflight_cap(),
                // Daemon only (`hub` is absent for a one-shot CLI `get`,
                // which has no next job to hand connections to), and only
                // for a server the user has switched ON. §36: the pool is
                // off by default and settled PER SERVER, because whether
                // it helps is a property of the link - worth -19.5% on a
                // controlled 50 ms path, and indistinguishable from
                // nothing on a real jittery one. `mode=warm_bench`
                // measures this server and recommends.
                warm: match s.warm_pool {
                    true => hub.as_ref().and_then(|h| h.warm()),
                    false => None,
                },
                ..PoolConfig::default()
            };
            (s.clone(), cfg)
        })
        .collect();
    // Per-server live gauges for the dashboard (workers update, API reads).
    let pool_live = nzbkit::pool::LiveStats::for_servers(&servers);
    for (_, cfg) in servers.iter_mut() {
        cfg.live = Some(pool_live.clone());
    }
    if let Some(h) = &hub {
        *h.pool_live.lock_ok() = Some(pool_live.clone());
    }
    // M29 oracle: every server pool records per-article hit/430 outcomes
    // into the daemon's per-job sink (in-memory; flushed to the ledger at
    // net-drain). Context = pool host order + the NZB's dominant group's
    // family. Undated jobs are skipped (job_posted is None): their outcomes
    // have no reliable age bucket, so recording them would pollute the
    // fresh buckets and skew the takedown fingerprint.
    if let Some(sink) = hub
        .as_ref()
        .filter(|_| job_posted.is_some())
        .and_then(|h| h.oracle.lock_ok().clone())
    {
        sink.set_context(
            servers.iter().map(|(s, _)| s.host.clone()).collect(),
            job_family.clone(),
        );
        for (_, cfg) in servers.iter_mut() {
            cfg.oracle = Some(sink.clone());
        }
    }

    // B2: channel depth scales with the budget - a fixed 256 held up to
    // ~200 MB of raw articles OUTSIDE the budget, more than a small
    // box's entire allowance. See MemBudget::channel_depth.
    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(budget.channel_depth());
    // Consumers are dedicated OS threads (A6, constrained-CPU): decode +
    // pwrite + verify are all synchronous CPU/disk work, and running them
    // inline on tokio workers starves the socket reactor on 2-4 core
    // boxes (every worker stuck in MD5/pwrite → TCP reads stall →
    // throughput craters). A std Mutex around the receiver is fine
    // between OS threads: the handoff is microseconds against ~800 KB
    // of decode work per article, and no async scheduler hop is involved.
    let rx = Arc::new(std::sync::Mutex::new(rx));
    // The daemon shares this counter to report live queue progress.
    let decoded_bytes = progress.unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    // Publish what the journal already holds, so the queue row can add
    // it to this counter and pick the bar up where the last run left it.
    // A resume that stopped at 62% otherwise re-drew from 0 and climbed
    // back, which reads as "it started over" however loudly the copy
    // says nothing is re-downloaded - and is what a good share of the
    // reports of a lost journal actually are.
    //
    // Beside the counter rather than added INTO it, deliberately. This
    // one is every consumer's idea of "bytes off the wire this run": the
    // quota ledger bills it, history divides it by network seconds, the
    // resulting average feeds `best_rate_bps` (the stall watchdog's
    // reference for what the line can do), the CLI ticker differences it
    // per 2 s, and the daemon's rolling speed window differences it per
    // sample. Crediting 40 GB of already-downloaded articles into it in
    // one instant would answer all six of those with a number no line
    // has ever run at. The reader that wants "how much of this release
    // is on disk" adds the two; nothing else has to know.
    //
    // The figure is the NZB's encoded segment size, where a fetched
    // article credits its decoded length - so the seeded stretch of the
    // bar runs a few percent generous against an encoded denominator
    // that the fetched stretch runs a few percent shy of. Squaring those
    // two ends is audit #15's job; the percentage is clamped, so neither
    // can overshoot the bar.
    if let Some(h) = &hub {
        h.resume_seeded.store(resume_have_bytes, Ordering::Relaxed);
    }
    let decode_errors = Arc::new(AtomicU64::new(0));
    // Segments the pool never asked anyone for: outside every configured
    // server's retention window. Reported by cause in the failure summary
    // - to the user these were indistinguishable from real takedowns.
    let retention_excluded = Arc::new(AtomicU64::new(0));
    // The other two loss ledgers the failure summary reads. A real 430
    // verdict and a transport failure demand opposite responses (the
    // post is dead vs the provider flaked), yet both used to land in the
    // same per-slot "missing" count - a flaky provider read as a
    // takedown, all the way to the indexer failure report.
    let missing_430 = Arc::new(AtomicU64::new(0));
    let transport_failed = Arc::new(AtomicU64::new(0));
    // First error of each kind, verbatim, for the failure summary to
    // quote - the counter alone says nothing a bug report can act on.
    let transport_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let decode_error_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    // Test knob: cap the consumer (decode+write) stage to N MB/s to
    // simulate a slow disk. The correct systemic response - proven by the
    // backpressure test - is that the bounded channel fills, workers stop
    // reading sockets, TCP windows close, and providers slow to match,
    // with RSS flat. Async sleep, so pool I/O tasks stay unstarved.
    let throttle_mbps: Option<f64> = std::env::var("NZBFAST_THROTTLE_WRITE_MBPS")
        .ok()
        .and_then(|v| v.parse().ok());
    if let Some(m) = throttle_mbps {
        println!("⚠ consumer throttle active: {m} MB/s (slow-disk simulation)");
    }
    let throttle_t0 = Instant::now();

    // M15b backfill: filled by whichever consumer wins the activation
    // race; awaited (and reported) before the settle pass.
    let backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>> =
        Arc::new(std::sync::Mutex::new(None));
    // NOTE: the par2 flags for the M15b backfill are computed AT ACTIVATION
    // TIME from the slots themselves (not snapshotted here): the in-stream
    // sniff can flip a slot to recovery data long after this point.

    // Handle for the two par2-activation spawn_blocking sites below -
    // decode threads are plain OS threads with no implicit runtime context.
    let rt = tokio::runtime::Handle::current();
    let mut consumers = Vec::new();
    // Plaintext-once D records parked until their seam bytes settle on
    // disk (see the PlacedCrypto arm below). Shared across the decode
    // threads; leftovers at join time simply refetch on resume.
    type PendingD = (usize, String, String, u64, Vec<nzbkit::extract::Frag>);
    let pending_d: Arc<std::sync::Mutex<Vec<PendingD>>> = Default::default();
    // More decode threads than cores is pure scheduler churn (measured on
    // the 2-CPU cgroup rig): the default 4 stands on big metal, small
    // boxes get one per core.
    let n_decoders = decoders
        .max(1)
        .min(std::thread::available_parallelism().map_or(usize::MAX, |n| n.get()));
    for i in 0..n_decoders {
        let rx = rx.clone();
        let pending_d = pending_d.clone();
        let pool = buf_pool.clone();
        let out_pool = out_pool.clone();
        let slots = slots.clone();
        let id_to_slot = id_to_slot.clone();
        let seek_names = seek_names.clone();
        let decoded_bytes = decoded_bytes.clone();
        let fetch_done = fetch_done.clone();
        let decode_errors = decode_errors.clone();
        let retention_excluded = retention_excluded.clone();
        let missing_430 = missing_430.clone();
        let transport_failed = transport_failed.clone();
        let transport_sample = transport_sample.clone();
        let decode_error_sample = decode_error_sample.clone();
        let verifier = verifier.clone();
        let extractor = extractor.clone();
        let shape_said = shape_said.clone();
        let par2_outstanding = par2_outstanding.clone();
        let journal = journal.clone();
        let backfill = backfill.clone();
        let sniff = sniff.clone();
        let queue_ctl = queue_ctl.clone();
        let rt = rt.clone();
        let thread = std::thread::Builder::new()
            .name(format!("decode-{i}"))
            .spawn(move || {
                loop {
                    // Drain a batch per lock hold: the futex wake + context
                    // switch of a blocking_recv handoff is per-batch, not
                    // per-article - at loopback article rates (8k+/s) the
                    // per-article version tripled sys time on 2 CPUs. At NAS
                    // rates the batch is 1 and behavior is identical.
                    let mut batch: Vec<FetchOutcome> = Vec::with_capacity(8);
                    {
                        let mut rx = rx.lock_ok();
                        if let Some(first) = rx.blocking_recv() {
                            batch.push(first);
                            while batch.len() < 8 {
                                match rx.try_recv() {
                                    Ok(o) => batch.push(o),
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    if batch.is_empty() {
                        break; // channel closed and drained
                    }
                    for outcome in batch {
                        match outcome {
                            FetchOutcome::Done { id, raw } => {
                                let Some(&(sidx, nbytes)) = id_to_slot.get(&id) else {
                                    pool.give(raw);
                                    continue;
                                };
                                let (sidx, nbytes) = (sidx as usize, nbytes as u64);
                                // This article is now accounted for,
                                // whatever the decode below makes of it.
                                fetch_done.fetch_add(nbytes, Ordering::Relaxed);
                                let slot = &slots[sidx];
                                let mut out = out_pool.take();
                                // M32 perf: once live verify (full-MD5 mode) has
                                // matched this slot to a PAR2 file, the article
                                // CRC is a redundant pass over bytes the verifier
                                // hashes anyway - skip it and feed the span
                                // untrusted. First article per slot (and every
                                // article under fast verify / no PAR2) keeps it.
                                let delegated = verifier.delegates_integrity(sidx);
                                match nzbkit::yenc_simd::decode_into_integrity(
                                    &raw, &mut out, !delegated,
                                ) {
                                    Ok((dec, integrity)) => {
                                        let crc_checked = integrity.crc_checked;
                                        let name = if dec.name.is_empty() {
                                            slot.hint.clone()
                                        } else {
                                            dec.name.clone()
                                        };
                                        // Issue #14: the offset-0 article of a
                                        // payload-classified slot decoding to
                                        // the PAR2 packet magic identifies
                                        // recovery data with certainty (nothing
                                        // else starts with it). Reclassify NOW,
                                        // before the scheduler fetches any more
                                        // of the volume.
                                        if !slot.is_par2()
                                            && dec.offset() == 0
                                            && out.starts_with(nzbkit::par2::MAGIC)
                                        {
                                            reclassify_sniffed_par2(
                                                &sniff,
                                                &slots,
                                                sidx,
                                                &out,
                                                dec.file_size,
                                                &queue_ctl,
                                                &id_to_slot,
                                                &par2_outstanding,
                                            );
                                        }
                                        // BEFORE the write: the offset-0 probe
                                        // fires from inside write_verified and
                                        // promotes by this yEnc name - on an
                                        // obfuscated set the hint-keyed lookup
                                        // alone would miss it.
                                        if !slot.is_par2() {
                                            seek_names.note_slot_name(sidx, &name);
                                        }
                                        match extractor.write_verified(
                                            sidx,
                                            &name,
                                            dec.file_size,
                                            dec.offset(),
                                            &out,
                                            // The checked pcrc32 over exactly these
                                            // bytes: a STORE span that is this whole
                                            // article composes from it instead of
                                            // hashing them again.
                                            integrity.verified_article_crc,
                                        ) {
                                            Err(e) => {
                                                eprintln!("write {name}: {e}");
                                                decode_error_sample
                                                    .lock()
                                                    .unwrap()
                                                    .get_or_insert_with(|| {
                                                        format!("write {name}: {e}")
                                                    });
                                                decode_errors.fetch_add(1, Ordering::Relaxed);
                                                slot.errors.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Ok(persist) => {
                                                match &persist {
                                                    nzbkit::extract::Persist::Placed(frags) => {
                                                        if slot.is_par2_main {
                                                            journal.record(&id);
                                                        } else {
                                                            journal.record_placed(
                                                                sidx,
                                                                &id,
                                                                extractor.slot_file_info(sidx),
                                                                &name,
                                                                dec.file_size,
                                                                frags,
                                                            );
                                                        }
                                                    }
                                                    // Plaintext-once span: parked
                                                    // until its seam slivers are on
                                                    // disk (usually one neighboring
                                                    // article later) - a D record for
                                                    // RAM-held bytes would survive a
                                                    // kill the bytes did not.
                                                    nzbkit::extract::Persist::PlacedCrypto(
                                                        frags,
                                                    ) => {
                                                        pending_d.lock_ok().push((
                                                            sidx,
                                                            id.clone(),
                                                            name.clone(),
                                                            dec.file_size,
                                                            frags.clone(),
                                                        ));
                                                    }
                                                    nzbkit::extract::Persist::No => {}
                                                }
                                                // Flush every parked D whose bytes
                                                // have settled; E/K/T facts go first
                                                // so the records they support are
                                                // never orphaned.
                                                {
                                                    let mut pd = pending_d.lock_ok();
                                                    if !pd.is_empty() {
                                                        let ev = extractor.drain_crypto_events();
                                                        journal.record_crypto_events(&ev);
                                                        pd.retain(
                                                            |(sidx, id, name, size, frags)| {
                                                                if extractor
                                                                    .crypto_span_on_disk(frags)
                                                                {
                                                                    journal.record_placed_crypto(
                                                                        *sidx,
                                                                        id,
                                                                        extractor
                                                                            .slot_file_info(*sidx),
                                                                        name,
                                                                        *size,
                                                                        frags,
                                                                        &extractor
                                                                            .crypto_frag_mask(
                                                                                frags,
                                                                            ),
                                                                    );
                                                                    false
                                                                } else {
                                                                    true
                                                                }
                                                            },
                                                        );
                                                    }
                                                }
                                                decoded_bytes
                                                    .fetch_add(out.len() as u64, Ordering::Relaxed);
                                                if let Some(mbps) = throttle_mbps {
                                                    let target = decoded_bytes
                                                        .load(Ordering::Relaxed)
                                                        as f64
                                                        / (mbps * 1e6);
                                                    let actual =
                                                        throttle_t0.elapsed().as_secs_f64();
                                                    if target > actual {
                                                        // Dedicated thread: a plain sleep
                                                        // stalls only this decoder.
                                                        std::thread::sleep(
                                                            std::time::Duration::from_secs_f64(
                                                                (target - actual).min(0.25),
                                                            ),
                                                        );
                                                    }
                                                }
                                                if slot.is_par2() {
                                                    // Par2 main (or the sniffed in-stream
                                                    // bootstrap): mirror the bytes in memory
                                                    // for mid-download set activation. A
                                                    // sniffed slot WITHOUT a capture is a
                                                    // deferred volume - its stragglers are
                                                    // recovery data, not payload, and stay
                                                    // out of the verifier.
                                                    //
                                                    // `off` is the article's declared yEnc
                                                    // `begin - 1`, clamped only to >= 1 -
                                                    // never to the file size. Unlike the
                                                    // extractor's disk path (a sparse
                                                    // write_all_at at a huge offset costs no
                                                    // RAM), this resize ZERO-FILLS real
                                                    // memory, so one article declaring
                                                    // begin=10^15 in a file whose name merely
                                                    // contains ".par2" allocated a petabyte
                                                    // and aborted the daemon. A main .par2
                                                    // packet is small; cap the mirror well
                                                    // above any real one and drop the rest -
                                                    // an oversized "main" packet is not a
                                                    // set we could have activated anyway.
                                                    let mut cap = slot.capture.lock_ok();
                                                    if let Some(buf) = cap.as_mut() {
                                                        let off = dec.offset() as usize;
                                                        let end = off.saturating_add(out.len());
                                                        if end <= MAX_PAR2_CAPTURE {
                                                            if buf.len() < end {
                                                                buf.resize(end, 0);
                                                            }
                                                            buf[off..end].copy_from_slice(&out);
                                                        }
                                                    }
                                                } else if crc_checked {
                                                    verifier.on_data(
                                                        sidx,
                                                        &dec.name,
                                                        dec.file_size,
                                                        dec.offset(),
                                                        &out,
                                                    );
                                                } else {
                                                    // CRC skipped (or absent): not
                                                    // decoder-vouched. Full MD5
                                                    // under delegation; CRC-only
                                                    // under lean (its contract).
                                                    verifier.on_data_unverified(
                                                        sidx,
                                                        &dec.name,
                                                        dec.file_size,
                                                        dec.offset(),
                                                        &out,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("decode error ({id}): {e}");
                                        decode_error_sample
                                            .lock()
                                            .unwrap()
                                            .get_or_insert_with(|| format!("decode error: {e}"));
                                        decode_errors.fetch_add(1, Ordering::Relaxed);
                                        slot.errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                out_pool.give(out);
                                pool.give(raw);
                                if slot.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
                                    if extractor.is_mapped(sidx) {
                                        let shape = match extractor.archive_shape() {
                                            Some(sh)
                                                if !shape_said.swap(true, Ordering::Relaxed) =>
                                            {
                                                format!(" [{}]", sh.display())
                                            }
                                            _ => String::new(),
                                        };
                                        println!("  ✔ {} → extracting in-stream{shape}", slot.hint);
                                    } else if extractor.is_chased(sidx) {
                                        // A chased slot may own a file since
                                        // drop-behind trimming - but it is a
                                        // partial spill, not a finished download,
                                        // and announcing it as one is a lie.
                                        println!("  ✔ {} → extracting in-stream", slot.hint);
                                    } else if let Some(p) = extractor.slot_path(sidx) {
                                        println!(
                                            "  ✔ {}",
                                            p.file_name().unwrap_or_default().to_string_lossy()
                                        );
                                    }
                                    // A sniffed bootstrap volume owes the
                                    // activation counter a completion just
                                    // like a static par2-main slot does;
                                    // deferred sniffed slots do not.
                                    if (slot.is_par2_main
                                        || (slot.is_par2() && sniff.note_completed(sidx)))
                                        && maybe_activate_par2(
                                            &slots,
                                            &verifier,
                                            &par2_outstanding,
                                            &sniff,
                                            &queue_ctl,
                                            &extractor,
                                        )
                                    {
                                        let v = verifier.clone();
                                        let ex = extractor.clone();
                                        let sl = slots.clone();
                                        let n = slots.len();
                                        *backfill.lock_ok() = Some(rt.spawn_blocking(move || {
                                            let flags: Vec<bool> =
                                                sl.iter().map(|s| s.is_par2()).collect();
                                            backfill_pre_activation(&v, &ex, n, &flags)
                                        }));
                                    }
                                }
                            }
                            FetchOutcome::Missing { id, cause } => {
                                match cause {
                                    nzbkit::pool::MissingCause::Retention => {
                                        retention_excluded.fetch_add(1, Ordering::Relaxed);
                                    }
                                    nzbkit::pool::MissingCause::Gone => {
                                        missing_430.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                if let Some(&(sidx, nbytes)) = id_to_slot.get(&id) {
                                    let sidx = sidx as usize;
                                    // Terminal is terminal: an article
                                    // that will never arrive still ends
                                    // the fetch's responsibility for it,
                                    // and leaving it out would hold the
                                    // bar short of 100% on every damaged
                                    // set while repair ran.
                                    fetch_done.fetch_add(nbytes as u64, Ordering::Relaxed);
                                    slots[sidx].missing.fetch_add(1, Ordering::Relaxed);
                                    if slots[sidx].remaining.fetch_sub(1, Ordering::AcqRel) == 1
                                        && (slots[sidx].is_par2_main
                                            || (slots[sidx].is_par2()
                                                && sniff.note_completed(sidx)))
                                        && maybe_activate_par2(
                                            &slots,
                                            &verifier,
                                            &par2_outstanding,
                                            &sniff,
                                            &queue_ctl,
                                            &extractor,
                                        )
                                    {
                                        let v = verifier.clone();
                                        let ex = extractor.clone();
                                        let sl = slots.clone();
                                        let n = slots.len();
                                        *backfill.lock_ok() = Some(rt.spawn_blocking(move || {
                                            let flags: Vec<bool> =
                                                sl.iter().map(|s| s.is_par2()).collect();
                                            backfill_pre_activation(&v, &ex, n, &flags)
                                        }));
                                    }
                                }
                            }
                            FetchOutcome::Failed { id, error } => {
                                transport_failed.fetch_add(1, Ordering::Relaxed);
                                transport_sample.lock_ok().get_or_insert(error);
                                if let Some(&(sidx, nbytes)) = id_to_slot.get(&id) {
                                    let sidx = sidx as usize;
                                    // Terminal is terminal: an article
                                    // that will never arrive still ends
                                    // the fetch's responsibility for it,
                                    // and leaving it out would hold the
                                    // bar short of 100% on every damaged
                                    // set while repair ran.
                                    fetch_done.fetch_add(nbytes as u64, Ordering::Relaxed);
                                    slots[sidx].missing.fetch_add(1, Ordering::Relaxed);
                                    if slots[sidx].remaining.fetch_sub(1, Ordering::AcqRel) == 1
                                        && (slots[sidx].is_par2_main
                                            || (slots[sidx].is_par2()
                                                && sniff.note_completed(sidx)))
                                        && maybe_activate_par2(
                                            &slots,
                                            &verifier,
                                            &par2_outstanding,
                                            &sniff,
                                            &queue_ctl,
                                            &extractor,
                                        )
                                    {
                                        let v = verifier.clone();
                                        let ex = extractor.clone();
                                        let sl = slots.clone();
                                        let n = slots.len();
                                        *backfill.lock_ok() = Some(rt.spawn_blocking(move || {
                                            let flags: Vec<bool> =
                                                sl.iter().map(|s| s.is_par2()).collect();
                                            backfill_pre_activation(&v, &ex, n, &flags)
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            })
            .expect("spawn decode thread");
        consumers.push(thread);
    }

    // Live rate ticker (2 s), driven by the consumer-side decoded counter.
    // Missing-article churn shows too: a mostly-taken-down post decodes
    // nothing while the pool grinds through 430s, and without the count
    // that phase is indistinguishable from a hard stall (seen live on a
    // 12k-segment post that flatlined at "0.0 MB/s" for minutes).
    let ticker_bytes = decoded_bytes.clone();
    let ticker_slots = slots.clone();
    let ticker = tokio::spawn(async move {
        let mut last = 0u64;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = ticker_bytes.load(Ordering::Relaxed);
            let missing: usize = ticker_slots
                .iter()
                .map(|s| s.missing.load(Ordering::Relaxed))
                .sum();
            let miss = if missing > 0 {
                format!("  ({missing} missing)")
            } else {
                String::new()
            };
            println!(
                "  … {:>7.1} MB/s ({:.2} Gbps)  written {:.2} GB{miss}",
                (now - last) as f64 / 2e6,
                (now - last) as f64 * 8.0 / 2e9,
                now as f64 / 1e9
            );
            last = now;
        }
    });

    // Deadlock watchdog. A pool bug that leaves an article non-terminal
    // wedges the whole job AFTER its bytes are downloaded: fetch_all_multi
    // never returns, silently, until something external kills it (seen on
    // a 190 GB low-memory run - 3 h frozen, download complete, no output).
    // Pausing aborts the transfer rather than freezing it, so a job that
    // is neither decoding NOR resolving articles, with segments still
    // outstanding, is unambiguously the deadlock. When that holds, dump
    // the pool state and abort: the stuck slot's blocks then fall into
    // PAR2 repair (usually recovered) or fail loud, and the journal makes
    // either outcome resume cleanly.
    //
    // BOTH signals, because decoded bytes alone do not mean "alive". An
    // article that goes terminally Missing decodes nothing, and a post
    // that is wholly gone decodes NOTHING AT ALL, for however long it
    // takes to ask every server for every article - so a dead post is
    // byte-frozen by definition while the pool works through its queue
    // perfectly. Watching bytes alone, the watchdog aborted exactly that
    // (31 Jul, live: a 30-day-old dead post killed mid-ladder, then
    // reported as a fault on the user's own machine with most of its
    // articles never requested). `remaining` counts down on Hit, Missing
    // AND Failed, so it moves whenever the pool resolves anything by any
    // route: it is the liveness signal a refusal-only run still has. A
    // genuine wedge freezes both, and still fires.
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let decoded = decoded_bytes.clone();
        let slots = slots.clone();
        let qc = queue_ctl.clone();
        let abort_flag = abort_flag.clone();
        let stalled = stalled.clone();
        let secs: u64 = std::env::var("NZBFAST_STALL_ABORT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(180);
        // Poll several times per stall window (bounded 1..=15 s) so a short
        // override fires promptly in tests and production stays low-churn.
        let poll = (secs / 4).clamp(1, 15);
        tokio::spawn(async move {
            let outstanding_now = |sl: &[Arc<FileSlot>]| -> usize {
                sl.iter().map(|s| s.remaining.load(Ordering::Relaxed)).sum()
            };
            let mut last = decoded.load(Ordering::Relaxed);
            let mut last_outstanding = outstanding_now(&slots);
            let mut frozen = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(poll)).await;
                if abort_flag.load(Ordering::Relaxed) {
                    return;
                }
                let now = decoded.load(Ordering::Relaxed);
                let outstanding = outstanding_now(&slots);
                if now != last || outstanding != last_outstanding {
                    last = now;
                    last_outstanding = outstanding;
                    frozen = 0;
                    continue;
                }
                frozen += poll;
                if frozen >= secs && outstanding > 0 {
                    eprintln!(
                        "⚠ download stalled: no decode progress AND no article \
                         resolved for {frozen}s with {outstanding} segment(s) still \
                         outstanding - the connection pool has wedged. Dumping state \
                         and aborting; the journal keeps what landed, PAR2 fills any \
                         gap, and a retry resumes."
                    );
                    qc.dump_state();
                    stalled.store(true, Ordering::Relaxed);
                    qc.abort();
                    return;
                }
            }
        })
    };

    let t0 = Instant::now();
    // M2c.5 speculative recovery prefetch: the moment ANY article goes
    // terminally Missing/Failed, damage is certain - fetch the smallest
    // recovery volume on a tiny side pool (1 conn/server; the main pool
    // owns the provider grants) so the post-settle exact-fit pass starts
    // with recovery blocks already on disk. The daemon gates this via
    // hub.spec_prefetch (off when a quota is configured - mirrors the
    // sidecar-prefetch guard); CLI runs opt out with
    // NZBFAST_NO_SPEC_PREFETCH=1. Risk is bounded to one small volume of
    // possibly-wasted bytes. Skipped when the set bootstraps from a
    // volume (one is already inbound) or the NZB ships no volumes.
    let prefetched: Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let prefetch_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spec_prefetch_task: Option<tokio::task::JoinHandle<()>> = {
        let allowed = match &hub {
            Some(h) => h.spec_prefetch.load(Ordering::Relaxed),
            None => std::env::var_os("NZBFAST_NO_SPEC_PREFETCH").is_none(),
        };
        let target = (allowed && has_main)
            .then(|| {
                nzb.files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                    .min_by_key(|(_, f)| f.bytes())
                    .map(|(fi, f)| (fi, f.bytes()))
            })
            .flatten();
        target.map(|_| {
            // Smallest-first ladder of every recovery volume: (fi, reqs,
            // declared/estimated slice count). The watcher escalates one
            // rung at a time while the missing count outruns the blocks
            // already prefetched - missing articles are CERTAIN damage,
            // so cover for the observed count is never wasted bytes.
            let mut ladder: Vec<(usize, Vec<ArticleReq>, HashMap<String, usize>, usize, u64)> =
                nzb.files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                    .map(|(fi, f)| {
                        let age_days = nzb_age_days(f.date);
                        let mut reqs = Vec::new();
                        let mut idm = HashMap::new();
                        for seg in &f.segments {
                            let b = format!("<{}>", seg.message_id);
                            idm.insert(b.clone(), fi);
                            reqs.push(ArticleReq { id: b, age_days });
                        }
                        let name = f.filename_hint().unwrap_or(&f.subject);
                        // Conservative when the name doesn't declare a
                        // count: claim 1 so escalation keeps going rather
                        // than stopping on an inflated estimate.
                        let count = vol_count_from_name(name).unwrap_or(1);
                        (fi, reqs, idm, count, f.bytes())
                    })
                    .collect();
            ladder.sort_by_key(|(_, _, _, _, bytes)| *bytes);
            let side_servers = side_pool_servers(&servers);
            let slots2 = slots.clone();
            let out2 = out_dir.to_path_buf();
            let bp = buf_pool.clone();
            let vol_cap = volume_prealloc_cap(&nzb);
            let pre = prefetched.clone();
            let stop = prefetch_stop.clone();
            tokio::spawn(async move {
                let mut covered = 0usize;
                let mut ladder = ladder;
                loop {
                    if stop.load(Ordering::Acquire) {
                        return; // network phase over - settle takes it from here
                    }
                    let miss: usize =
                        slots2.iter().map(|s| s.missing.load(Ordering::Relaxed)).sum();
                    if miss > covered {
                        // Exact-fit rung: the smallest unfetched volume
                        // covering the whole deficit (else the biggest
                        // left) - the pure smallest-first ladder
                        // over-fetched ~2x once the damage count ran
                        // ahead of the rungs.
                        let deficit = miss - covered;
                        if ladder.is_empty() {
                            return; // every volume already prefetched
                        }
                        let at = ladder
                            .iter()
                            .position(|(_, _, _, count, _)| *count >= deficit)
                            .unwrap_or(ladder.len() - 1);
                        let (fi, reqs, idm, count, bytes) = ladder.remove(at);
                        info!(
                            target: "repair",
                            "{miss} article(s) terminally missing - prefetching recovery volume ({:.1} MB) alongside the download",
                            bytes as f64 / 1e6
                        );
                        match fetch_volume_articles(&side_servers, reqs, idm, &out2, &bp, vol_cap)
                            .await
                        {
                            Ok(paths) if !paths.is_empty() => {
                                covered += count.max(1);
                                pre.lock_ok().push((fi, paths));
                            }
                            Ok(_) => {
                                // Not one byte of that volume landed (every
                                // article failed, or it was unwritable).
                                // Claiming its blocks as covered would stall
                                // escalation, and recording the file index
                                // would strike it off the post-settle fetch
                                // list - so do neither and try the next rung.
                                info!(
                                    target: "repair",
                                    "that volume produced no file - trying the next one"
                                );
                            }
                            Err(e) => {
                                info!(
                                    target: "repair",
                                    "speculative prefetch failed ({e}) - the post-settle fetch covers it"
                                );
                                return;
                            }
                        }
                        continue; // re-check immediately - miss may have grown
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            })
        })
    };
    // D1 (big-link): the single-runtime path tops out at ~4.1 Gbps per
    // process - one I/O driver thread saturates while the NIC has headroom.
    // On big machines with enough connections, shard the fleet across
    // independent runtimes (the soak-proven fetch_all_sharded). Small
    // boxes stay on the single-runtime path: extra runtimes are pure
    // overhead below the ceiling. NZBFAST_SHARDS=n forces either way
    // (1 = force single-runtime).
    let total_conns: usize = servers.iter().map(|(_, c)| c.connections).sum();
    let shards = std::env::var("NZBFAST_SHARDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        // Clamp the operator override: each shard spins its own 2-thread
        // runtime, and an absurd value (NZBFAST_SHARDS=100000) would panic
        // on thread exhaustion and take down the download. 16 covers any
        // real fleet.
        .map(|n| n.clamp(1, 16))
        .unwrap_or_else(|| {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            if cores >= 12 && total_conns >= 24 {
                (total_conns / 16).clamp(2, 4)
            } else {
                1
            }
        });
    let stats = if shards > 1 {
        println!("  sharding {total_conns} connections across {shards} I/O runtimes");
        let servers_owned = servers.clone();
        let qc = queue_ctl.clone();
        tokio::task::spawn_blocking(move || {
            nzbkit::pool::fetch_all_sharded(servers_owned, ids, tx, shards, Some(&qc))
        })
        .await
        .expect("sharded fetch panicked")
    } else {
        fetch_all_multi_ctl(&servers, ids, tx, Some(&queue_ctl)).await
    };
    // Network phase over: stop a still-waiting watcher, and let a
    // mid-fetch prefetch finish before settle harvests the directory.
    prefetch_stop.store(true, Ordering::Release);
    if let Some(t) = spec_prefetch_task {
        let _ = t.await;
    }
    // Decode threads exit when the channel closes (fetch dropped tx).
    // Join off the reactor - thread::join blocks.
    let _ = tokio::task::spawn_blocking(move || {
        for c in consumers {
            let _ = c.join();
        }
    })
    .await;
    // Final D-record flush: seams that closed after the last article's
    // own flush pass settle now; anything still RAM-held refetches on
    // resume, which is exactly the truthful record.
    {
        let mut pd = pending_d.lock_ok();
        if !pd.is_empty() {
            let ev = extractor.drain_crypto_events();
            journal.record_crypto_events(&ev);
            pd.retain(|(sidx, id, name, size, frags)| {
                if extractor.crypto_span_on_disk(frags) {
                    journal.record_placed_crypto(
                        *sidx,
                        id,
                        extractor.slot_file_info(*sidx),
                        name,
                        *size,
                        frags,
                        &extractor.crypto_frag_mask(frags),
                    );
                    false
                } else {
                    true
                }
            });
        }
    }
    let elapsed = t0.elapsed();
    ticker.abort();
    watchdog.abort();
    if stalled.load(Ordering::Relaxed) {
        println!(
            "  ⚠ recovered from a stalled pool by aborting the tail - \
             verifying and repairing what landed"
        );
    }
    // User cancelled: skip settle/repair/extract on the partial data.
    // The journal keeps what landed - a later retry resumes from it.
    // (Bailing drops net_done, which the daemon reads as network-drained.)
    if abort_flag.load(Ordering::Relaxed) {
        anyhow::bail!("stopped by user");
    }
    // Graceful pause: the pool admitted no new work and let every in-flight
    // article finish and journal, so a resume re-fetches only the unstarted
    // queue - nothing here is wasted. Park it like an abort (skip settle),
    // but say so: this is a clean wind-down, not a cancel.
    if queue_ctl.is_draining() {
        anyhow::bail!("paused (drained in-flight; queue kept for resume)");
    }
    // Network drained: everything from here is disk/CPU. Tell the daemon
    // so the next queued download can start soaking the line now.
    //
    // The token moves FIRST, and it is what the queue row's status is
    // read from - so by the time the daemon can act on the signal and
    // start the next download, this job has already stopped calling
    // itself a download. Announced here rather than at the verify pass
    // below because the settle read-back, the backfill join and the
    // deferred-payload sweep in between are all part of checking what
    // landed; leaving the token on "fetching" for them is what made a
    // finished transfer read as "downloading, 100%, 0 MB/s" for minutes.
    note_activity("verifying");
    if let Some(tx) = net_done {
        let _ = tx.send(());
    }
    // M24 late attach (C1): a password set via mode=set_password while
    // this job downloaded. The `password` binding above was resolved at
    // start; without this re-read the whole disk tail (re-extraction,
    // recovery-record repair, the unrar ladder, the nested pass) ran with
    // the stale None, parked the job as password_required, and the very
    // password the user had already supplied sat unread until a manual
    // retry. Late wins over captured: a user re-typing mid-download is
    // correcting the one the job started with.
    let password: Option<String> = hub
        .as_ref()
        .and_then(|h| h.late_password_for(stream_owner))
        .or(password);
    // Any pre-activation spans the backfill is still hashing belong to
    // this tail - wait so settle sees final block states (M15b).
    let bf = backfill.lock_ok().take();
    if let Some(h) = bf
        && let Ok(fed) = h.await
        && fed > 0
    {
        println!(
            "  » backfilled {:.1} MB of pre-activation spans during download",
            fed as f64 / 1e6
        );
    }

    // Issue #14 drain fallback: a deferred slot the ACTIVE set covers is
    // payload the sniff got wrong (a posted par2 file the set includes).
    // The live reconcile at activation requeues such slots while the pool
    // still runs; on a short post the pool is gone by activation time, so
    // whatever is still deferred-and-matched is fetched here on the side
    // machinery and fed to the verifier off disk - delivered and
    // verified, never recreated from recovery blocks.
    if let Some(set) = verifier.set() {
        for (sidx, file_size) in sniff.matched_deferred(&set) {
            println!(
                "  ▸ {} is payload the recovery set covers - fetching it now",
                slots[sidx].hint
            );
            let fi = slot_file[sidx];
            if let Err(e) = fetch_volumes(&servers, &nzb, out_dir, &buf_pool, &[fi]).await {
                println!("  ⚠ fetching it failed ({e}) - leaving it to the repair pass");
                continue;
            }
            // Deferral ledger: these bytes were downloaded after all.
            let undeferred_bytes = sniff
                .state
                .lock_ok()
                .cancelled_ids
                .get(&sidx)
                .map(|(_, b)| *b)
                .unwrap_or(0);
            sniff.mark_reconciled(sidx);
            // Deliberately NOT undoing the deferral's fetch_done credit
            // the way the pool-side reconcile does: these bytes came in
            // through `fetch_volumes` on the side machinery, so no
            // terminal outcome will ever credit them again and dropping
            // the credit would leave the bar short (Codex sweep 2,
            // 3 Aug ML2).
            slots[sidx].par2_sniffed.store(false, Ordering::Release);
            // The side fetch re-attempted every article of the file, so
            // the sniff-era counters are stale; the verification feed
            // below is the authority on what is actually good.
            let undeferred = slots[sidx].deferred.swap(0, Ordering::Relaxed);
            slots[sidx].missing.store(0, Ordering::Relaxed);
            sniff
                .deferred_articles
                .fetch_sub(undeferred, Ordering::Relaxed);
            sniff
                .deferred_bytes
                .fetch_sub(undeferred_bytes, Ordering::Relaxed);
            // Feed the whole file from disk: the first chunk carries the
            // 16k head, so the verifier claims the slot by md5-16k, and
            // every block gets a full-MD5 disk-provenance check before
            // settle reads the result.
            let path = extractor.slot_path(sidx).unwrap_or_else(|| {
                out_dir.join(nzbkit::disk::sanitize_filename(&slots[sidx].hint))
            });
            match std::fs::File::open(&path) {
                Ok(mut f) => {
                    use std::io::Read;
                    let mut off = 0u64;
                    let mut buf = vec![0u8; 4 << 20];
                    loop {
                        match f.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                verifier.on_data_from_disk(sidx, "", file_size, off, &buf[..n]);
                                off += n as u64;
                            }
                            Err(e) => {
                                println!("  ⚠ reading {} back failed: {e}", path.display());
                                break;
                            }
                        }
                    }
                }
                Err(e) => println!("  ⚠ {} not readable after fetch: {e}", path.display()),
            }
        }
    }

    let total: u64 = stats.iter().map(|s| s.bytes).sum();
    println!(
        "\n{:.1} MB raw in {:.2?} → {:.1} MB/s ({:.2} Gbps); {:.1} MB written",
        total as f64 / 1e6,
        elapsed,
        total as f64 / 1e6 / elapsed.as_secs_f64(),
        total as f64 * 8.0 / 1e9 / elapsed.as_secs_f64(),
        decoded_bytes.load(Ordering::Relaxed) as f64 / 1e6,
    );
    // Servers that never held a usable connection: their articles' fates
    // were decided by the others alone, and the failure summary must say
    // so - one dead backup silently turns a single 430 into "missing".
    let mut dead_servers: Vec<String> = Vec::new();
    for ((s, _), st) in servers.iter().zip(&stats) {
        if st.ever_connected {
            println!(
                "  {:<28} {:>8.1} MB · {} conns, {} reconnects",
                s.host,
                st.bytes as f64 / 1e6,
                st.connects,
                st.reconnects
            );
        } else {
            println!(
                "  {:<28} ⚠ no usable connection for the entire run \
                 (unreachable, or it refused the login)",
                s.host
            );
            dead_servers.push(s.host.clone());
        }
    }
    // Distinct BACKBONES that actually took part. Five resellers of one
    // backbone are one opinion, not five, and "no server had it" reads
    // like five independent votes - so the failure summary counts the
    // opinions, not the hostnames.
    let mut backbones: Vec<String> = servers
        .iter()
        .zip(&stats)
        .filter(|(_, st)| st.ever_connected)
        .map(|((s, _), _)| nzbkit::oracle::backbone_of(&s.host))
        // A server addressed by IP (or any host that reduces to no
        // letters) names no backbone - `backbone_of("127.0.0.1")` is the
        // label "0". It cannot support a claim about independent
        // opinions either way, so it sits the clause out rather than
        // printing a digit as though it were a provider.
        .filter(|b| b.chars().any(|c| c.is_ascii_alphabetic()))
        .collect();
    backbones.sort();
    backbones.dedup();
    // The post's own age - as young as its youngest article. A post
    // nobody carries YET and a post nobody carries ANY MORE are the same
    // picture from in here (every article 430, not a byte arrived), and
    // only the calendar tells them apart: a release grabbed minutes after
    // its pre routinely 430s everywhere while it propagates, and that is
    // precisely the case the one automatic retry exists for. An NZB whose
    // dates are missing or unusable reads as age 0, which keeps it out of
    // the "gone" verdict - unknown is not old.
    let post_age_days = nzb
        .files
        .iter()
        .map(|f| nzb_age_days(f.date))
        .min()
        .unwrap_or(0);
    // Recovery data, by whichever route it was identified: issue #14's
    // in-stream sniff, or the NZB naming a file `.par2` outright. Such a
    // slot's counters describe recovery data, not payload - deferred
    // articles are a CHOICE, and a 430 on the bootstrap volume is a
    // shortfall the repair arithmetic will surface if it ever matters.
    // Counting either as "incomplete" failed a job whose payload was
    // perfect (the recovery set is duplicated per volume, so a bootstrap
    // hole rarely even dents activation). So the completeness accounting
    // below skips every recovery slot - the runtime analogue of an
    // NZB-classified Par2Volume, which never gets a slot at all.
    //
    // `is_par2()` and not the narrower "sniffed" test: a plainly-named
    // .par2 is recovery data for exactly the same reason a sniffed one
    // is, and excluding only the sniffed ones failed a job whose payload
    // was complete and byte-correct because the recovery data it never
    // needed arrived corrupt (or not at all). What losing recovery data
    // actually costs is ASSURANCE, not bytes, and that is reported as
    // such below rather than by failing the job. A post carrying no par2
    // at all has always succeeded on this same path.
    let sniff_bootstrap = sniff.bootstrap_slot();
    let slot_recovery = |i: usize| slots[i].is_par2();
    let deferred_arts = sniff.deferred_articles.load(Ordering::Relaxed);
    if deferred_arts > 0 {
        println!(
            "  ▸ in-stream PAR2 identification deferred {deferred_arts} article(s) - \
             {:.1} MB of recovery data not downloaded",
            sniff.deferred_bytes.load(Ordering::Relaxed) as f64 / 1e6
        );
    }
    let mut incomplete = 0;
    // Segment-level totals for the failure summary. A file count alone
    // cannot tell "94 files short one segment each" (a repair away) from
    // "94 files short every segment" (the post is gone) - and those are
    // the two ends of what one user actually needs to know.
    let mut missing_segments: u64 = 0;
    let mut total_segments: u64 = 0;
    // Which slots the coverage census below may NOT speak for, because
    // this run's interval map is not the whole story about their bytes
    // (Codex sweep 2, 3 Aug M2 - see the census itself for why each
    // one is here).
    let set_names: Option<std::collections::HashSet<String>> = verifier.set().map(|set| {
        set.files
            .iter()
            .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
            .collect()
    });
    let reconciled: std::collections::HashSet<usize> =
        sniff.state.lock_ok().reconciled.iter().copied().collect();
    // Slots that arrived complete by every counter and STILL do not
    // cover the range the post declared. Carried out of the loop
    // because the repair branch has to fail on them too: they sit
    // outside the recovery set by construction, so no repair can heal
    // them, and its own hole scan only looks at slots with a non-zero
    // counter.
    let mut sparse_slots: Vec<String> = Vec::new();
    for (i, slot) in slots.iter().enumerate() {
        if slot_recovery(i) {
            continue;
        }
        let miss = slot.missing.load(Ordering::Relaxed);
        let unresolved = slot.remaining.load(Ordering::Relaxed);
        // Disjoint by construction: `remaining` counts down as articles
        // resolve, `missing` counts the ones that resolved to nothing.
        total_segments += slot.total_segments as u64;
        missing_segments += (miss + unresolved) as u64;
        if miss > 0 || unresolved > 0 {
            incomplete += 1;
            println!(
                "  ⚠ {}: {} missing, {} unresolved of {} segments",
                slot.hint, miss, unresolved, slot.total_segments
            );
            continue;
        }
        // Every article accounted for, but did the bytes actually COVER
        // the file the post declared? The decoder validates each part
        // against its own `=ypart` range and deliberately not against
        // `=ybegin size` (posters do misstate totals, and rejecting on
        // that would break real posts), while the writer is sized from
        // exactly that untrusted total. So a self-consistent post can
        // declare 16 MiB, ship one CRC-valid byte, retire every counter
        // to zero, and leave a file that is one byte plus a hole - which
        // used to complete green (Codex sweep 3 Aug M7). The interval
        // map is the ground truth and costs one lock to ask.
        //
        // The interval map records what THIS run's decoder wrote, which
        // is not the same as what the file legitimately holds, so some
        // slots have to sit the census out. Which ones is a PER-SLOT
        // question, and asking it globally - `verifier.set().is_none()
        // && deferred_arts == 0` - exempted every slot in the job the
        // moment any set existed or anything anywhere was deferred
        // (Codex sweep 2, 3 Aug M2). A sparse out-of-set `.nfo` beside
        // a healthy covered RAR therefore completed green with a
        // one-byte-plus-hole file, and one unactivatable sniffed
        // recovery volume exempted the entire payload of the post.
        //
        // The two real exemptions, both narrow:
        //  - the recovery set NAMES the file, or the verifier has
        //    matched this slot to one of its entries: repair rebuilds
        //    such a file from parity, bytes no decoder in this run ever
        //    wrote, and the set's own verification is the stronger
        //    statement about it anyway;
        //  - the slot was deferred as par2-shaped and then reconciled
        //    back to payload, whose bytes arrive by side fetch
        //    (`fetch_volumes` straight to disk) rather than through the
        //    writer.
        // Both were real false positives on the e2e suite. A stable
        // plain slot outside the set is neither, and is exactly the
        // case where NOTHING else checks the bytes - `slot_uncovered`
        // itself returns None for the mapped and chased shapes that
        // legitimately hold less than they declare.
        let covered_by_set = verifier.slot_in_set(i)
            || set_names.as_ref().is_some_and(|n| {
                n.contains(&nzbkit::disk::sanitize_filename(&slot.hint).to_lowercase())
            });
        if !covered_by_set
            && !reconciled.contains(&i)
            && slot.deferred.load(Ordering::Relaxed) == 0
            && let Some(gap) = extractor.slot_uncovered(i)
            && gap > 0
        {
            incomplete += 1;
            sparse_slots.push(slot.hint.clone());
            println!(
                "  ⚠ {}: every article arrived but {:.1} MB of the declared \
                 {:.1} MB was never written - the post's size header and its \
                 parts disagree",
                slot.hint,
                gap as f64 / 1e6,
                extractor
                    .slot_file_info(i)
                    .map(|(_, sz)| sz)
                    .unwrap_or_default() as f64
                    / 1e6,
            );
        }
    }
    // Same exclusion for decode/write errors: one charged to a recovery
    // slot (a deferred straggler, a bootstrap article, the main .par2
    // itself) is a recovery-data problem for the repair arithmetic, not a
    // payload failure.
    let recovery_errs: u64 = slots
        .iter()
        .enumerate()
        .filter(|(i, _)| slot_recovery(*i))
        .map(|(_, s)| s.errors.load(Ordering::Relaxed) as u64)
        .sum();
    let derrs = decode_errors
        .load(Ordering::Relaxed)
        .saturating_sub(recovery_errs);
    if derrs > 0 {
        println!("  ⚠ {derrs} decode/write errors");
    }
    // What the exclusions above just held back. Not a failure, but not
    // nothing either: it is the whole reason a job can finish with its
    // payload complete and no way to prove it. `remaining` is safe to
    // read as loss here because deferral decrements it (a deferred
    // article is a choice, counted separately).
    let recovery_missing: u64 = slots
        .iter()
        .enumerate()
        .filter(|(i, _)| slot_recovery(*i))
        .map(|(_, s)| {
            (s.missing.load(Ordering::Relaxed) + s.remaining.load(Ordering::Relaxed)) as u64
        })
        .sum();
    let retention_skipped = retention_excluded.load(Ordering::Relaxed);
    if retention_skipped > 0 {
        println!(
            "  ⚠ {retention_skipped} segment(s) never requested: older than every \
             server's configured retention (retention_days in the server settings)"
        );
    }
    if incomplete == 0 && derrs == 0 {
        // Payload slots only - the same set the census just walked. Saying
        // "all 4 files complete" while the 4th is a .par2 that arrived
        // corrupt would be a plain untruth, and now that recovery damage
        // no longer fails the job this line is reachable with one broken.
        println!(
            "all {} files complete ✔",
            slots.iter().filter(|s| !s.is_par2()).count()
        );
    }

    // Slots whose offset-0 article never landed are still unclassified,
    // their spans held in memory - flush them to plain files so settle
    // read-back and PAR2 repair see the bytes on disk.
    note_activity("verifying");
    extractor.settle_unclassified()?;

    // --- settle verification (in-stream results; read-back only for gaps) ---
    let mut damage_in_mapped = false;
    let mut all_good;
    // The bytes on disk are fine but turning them into the output file
    // failed - a distinct failure from an incomplete or unrepaired
    // download. Holds WHICH extraction path gave up: several reach here
    // on jobs that never needed (or ran) a PAR2 repair at all, so the
    // reason travels with the flag rather than being assumed at the end.
    // A String rather than a &'static str: the nested-archive arms below
    // know WHICH archive stopped them, and "the log above names the
    // archive" asked the user to go and find in a log ring what the
    // sentence could simply have said.
    let mut reextract_failed: Option<String> = None;
    // (needed, have) when repair died on recovery-block arithmetic - the
    // counts belong in the fail message, not just the console log.
    let mut repair_shortfall: Option<(usize, usize)> = None;
    // Deobfuscated names a CHASED slot could not take while its writer was
    // live (see the rename below). Applied after `extractor.finish()`,
    // when nothing holds an fd on the partial file any more - otherwise
    // the slot keeps the posted name for good, and an obfuscated
    // `hash.bin` is what the user is left looking at.
    let mut deferred_renames: Vec<(usize, String)> = Vec::new();
    // Issue #14: the active set's FileDesc names, recorded for the
    // end-of-job sniffed-leftover sweep (payload that is itself par2 must
    // be spared). None when no set activated - the sweep then reads the
    // names off the on-disk packets instead.
    let mut sniff_covered: Option<std::collections::HashSet<String>> = None;
    match verifier.set() {
        Some(set) => {
            let vt0 = Instant::now();
            // Settle every slot in parallel - read-back hashing (MD5) is
            // single-thread ~0.6 GB/s, and a big-block set can push
            // gigabytes through this path.
            let settled: Vec<(usize, Option<nzbkit::live::SlotReport>)> = {
                let verifier = &verifier;
                let extractor = &extractor;
                let slot_list: Vec<usize> = slots
                    .iter()
                    .enumerate()
                    // is_par2() and not just is_par2_main: a sniffed slot
                    // (bootstrap or deferred) is recovery data - the set
                    // never claims it, and read-back would report every
                    // deferred article as a bad block.
                    .filter(|(_, s)| !s.is_par2())
                    .map(|(i, _)| i)
                    .collect();
                let next = AtomicUsize::new(0);
                let results: std::sync::Mutex<Vec<(usize, Option<nzbkit::live::SlotReport>)>> =
                    std::sync::Mutex::new(Vec::new());
                std::thread::scope(|scope| {
                    for _ in 0..std::thread::available_parallelism()
                        .map_or(4, |n| n.get())
                        .min(12)
                    {
                        scope.spawn(|| {
                            loop {
                                let i = next.fetch_add(1, Ordering::Relaxed);
                                if i >= slot_list.len() {
                                    break;
                                }
                                let sidx = slot_list[i];
                                // A chased slot has no file either - its bytes
                                // are in the frontier buffer - and read_at
                                // serves it byte-exact, so it takes the same
                                // reader. Sending it down the path branch
                                // would read-back against a file that does not
                                // exist and report every pending block bad.
                                let r = if extractor.is_mapped(sidx) || extractor.is_chased(sidx) {
                                    let reader = |off: u64, buf: &mut [u8]| {
                                        extractor.read_at(sidx, off, buf)
                                    };
                                    verifier.finish_slot_from(
                                        sidx,
                                        nzbkit::live::ReadAt::Reader(&reader),
                                    )
                                } else {
                                    // Fully-resumed slots never created a writer
                                    // this run - the run-1 file (yEnc name ==
                                    // hint for unobfuscated posts) backs them.
                                    let path = extractor.slot_path(sidx).or_else(|| {
                                        let p = out_dir.join(nzbkit::disk::sanitize_filename(
                                            &slots[sidx].hint,
                                        ));
                                        p.exists().then_some(p)
                                    });
                                    verifier.finish_slot(sidx, path.as_deref())
                                };
                                results.lock_ok().push((sidx, r));
                            }
                        });
                    }
                });
                let mut v = results.into_inner().unwrap();
                v.sort_by_key(|(s, _)| *s);
                v
            };
            let mut reports: Vec<(usize, nzbkit::live::SlotReport)> = Vec::new();
            for (sidx, r) in settled {
                let slot = &slots[sidx];
                let mapped = extractor.is_mapped(sidx);
                if let Some(r) = r {
                    if !r.bad_blocks.is_empty() {
                        println!(
                            "  ✘ {} - {}/{} blocks bad",
                            r.par2_name.as_deref().unwrap_or(&slot.hint),
                            r.bad_blocks.len(),
                            r.total_blocks
                        );
                        if mapped {
                            damage_in_mapped = true;
                        }
                    }
                    // Deobfuscation: the PAR2 FileDesc name is the real one.
                    if let Some(pname) = &r.par2_name {
                        extractor.rename(sidx, pname);
                        // A CHASED slot is excluded from the on-disk half
                        // for the same reason a mapped one is: it has no
                        // finished file. It can now have a PARTIAL one -
                        // drop-behind trimming spills the archive's
                        // consumed prefix there - and renaming that moves
                        // the path out from under a live writer's open
                        // fd, so the rest of the spill lands in a file
                        // nothing points at.
                        //
                        // Deferred, not dropped. The chase may still
                        // demote, and then that partial file IS the
                        // archive: leaving it under the posted name meant
                        // the deobfuscated name was lost for good, since
                        // `Extractor::rename` also declines once a writer
                        // exists. Queue it for after finish(), when the
                        // writer is gone.
                        if !mapped {
                            if extractor.is_chased(sidx) {
                                deferred_renames.push((sidx, pname.clone()));
                            } else if let Some(path) = extractor.slot_path(sidx) {
                                publish_verified_name(&path, pname, out_dir);
                            }
                        }
                    }
                    reports.push((sidx, r));
                }
            }
            let live: u64 = reports.iter().map(|(_, r)| r.live_blocks).sum();
            let readback: u64 = reports.iter().map(|(_, r)| r.readback_blocks).sum();
            let bad: usize = reports.iter().map(|(_, r)| r.bad_blocks.len()).sum();
            let missing_files = verifier.unclaimed_files();
            // `damage` decides WHETHER repair runs; `needed` (the deficit
            // after slices already on hand) decides how much to FETCH.
            // Conflating them skipped repair entirely whenever on-hand
            // slices covered the damage count - silent corruption with
            // exit 0 (latent for bootstrap sets, wide open once M2c.5
            // prefetched volumes mid-download).
            let mut damage = bad;
            for name in &missing_files {
                if let Some(f) = set.files.iter().find(|f| f.name == *name) {
                    damage += f.length.div_ceil(set.block_size.max(1)) as usize;
                    println!("  ✘ {} - file missing entirely", f.name);
                }
            }
            // Slices already on hand: seen while building the set (the
            // bootstrap volume) + M2c.5 prefetched volumes on disk -
            // counted from the files themselves (exact, so a partial
            // prefetch discounts only what actually landed), and their
            // NZB entries leave the fetch-candidate list.
            // The sniffed bootstrap's capture can have holes: an article
            // decoded BEFORE the head's sniff was written to disk but
            // never mirrored, so recovery_blocks_seen can undercount -
            // while the bootstrap's file index goes into `already` and is
            // never refetched. Count its slices off the DISK file, which
            // write_verified kept whole. On a sniffed post the bootstrap
            // capture is the only one carrying recovery slices (demoted
            // captures are dropped), so this REPLACES recovery_blocks_seen
            // rather than adding to it.
            let mut on_hand = match sniff_bootstrap.and_then(|s| extractor.slot_path(s)) {
                Some(p) => std::fs::read(&p)
                    .map(|bytes| {
                        nzbkit::par2repair::recovery_slice_locators(&bytes, &set.recovery_set_id)
                            .into_iter()
                            .filter(|(_, _, len)| *len == set.block_size as usize)
                            .count()
                    })
                    .unwrap_or(set.recovery_blocks_seen),
                None => set.recovery_blocks_seen,
            };
            let mut already: Vec<usize> = bootstrap_vol.into_iter().collect();
            // The sniffed in-stream bootstrap (issue #14) is on hand the
            // same way a static bootstrap volume is: its slices were
            // counted at activation, so its NZB entry leaves the fetch
            // list. The other sniffed slots are the deferred volumes -
            // subject-line classification cannot see them, so the repair
            // planner is told about them explicitly.
            already.extend(sniff_bootstrap.map(|s| slot_file[s]));
            // Resume-recognised volumes are already (at least partly) on
            // disk: count their restored slices into on_hand and strike
            // their NZB entries off the fetch list, exactly like an
            // M2c.5 prefetch. The repair itself reads them off disk by
            // packet magic regardless - this only keeps the fetch
            // arithmetic honest.
            for (&s, pth) in resume_vols.iter() {
                already.push(slot_file[s]);
                if let Ok(bytes) = std::fs::read(pth) {
                    on_hand +=
                        nzbkit::par2repair::recovery_slice_locators(&bytes, &set.recovery_set_id)
                            .into_iter()
                            .filter(|(_, _, len)| *len == set.block_size as usize)
                            .count();
                }
            }
            let sniffed_vols: Vec<usize> = sniff.deferred_files();
            for (fi, paths) in prefetched.lock_ok().iter() {
                already.push(*fi);
                for pth in paths {
                    if let Ok(bytes) = std::fs::read(pth) {
                        on_hand += nzbkit::par2repair::recovery_slice_locators(
                            &bytes,
                            &set.recovery_set_id,
                        )
                        .into_iter()
                        .filter(|(_, _, len)| *len == set.block_size as usize)
                        .count();
                    }
                }
            }
            let needed = damage.saturating_sub(on_hand);
            // Slots the recovery set does NOT cover. A PAR2 repair proves the
            // files in its own set and says nothing whatever about the rest,
            // but the repair branches below set `all_good` from the repair
            // alone: a covered RAR with one repairable block plus a `.nfo`
            // (or a second payload file) posted outside the set whose
            // articles all 430'd finished Completed, journal deleted, with
            // that file never having arrived. The clean-PAR2 and no-PAR2
            // branches already apply the equivalent test.
            //
            // Requiring the GLOBAL counters to be zero would be wrong - a
            // covered slot's missing bytes are exactly what the repair just
            // healed - so the test is per slot.
            //
            // "Covered" is the recovery set NAMING the file, not the
            // verifier having reported on it. Report presence alone is too
            // strict: a slot claims its set entry off arriving bytes, so a
            // file whose every article 430'd never claims one and reaches
            // here with no report at all - which is precisely the file the
            // repair below then recreates whole from parity. Calling that
            // "outside the PAR2 set" failed the par-only shape (100%
            // recovery posted, every archive article 430) with its payload
            // already rebuilt and extracted byte-correct: bench leg
            // a2-par-only, 2 Aug. The disk-side fallback arm has always
            // tested coverage by name (`slot_is_uncovered_hole`); this is
            // the same test against the set the NZB gave us.
            //
            // Split rather than merged, because only a repair that verified
            // the whole set OFF DISK proves the files it names - see
            // `set_proven_on_disk` below.
            // Slot index carried alongside the hint: the obfuscated-alias
            // reconciliation below needs the slot's declared size, which
            // only the NZB file behind it knows.
            let (in_set_pairs, mut uncovered_pairs): (Vec<(usize, &str)>, Vec<(usize, &str)>) = {
                let covered: std::collections::HashSet<usize> =
                    reports.iter().map(|(s, _)| *s).collect();
                let set_names: std::collections::HashSet<String> = set
                    .files
                    .iter()
                    .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
                    .collect();
                slots
                    .iter()
                    .enumerate()
                    .filter(|(i, s)| {
                        // is_par2(): a sniffed volume (bootstrap or
                        // deferred) is recovery data, not a payload file
                        // the set failed to cover.
                        !s.is_par2()
                            && !covered.contains(i)
                            && (s.missing.load(Ordering::Relaxed) > 0
                                || s.remaining.load(Ordering::Relaxed) > 0
                                || s.errors.load(Ordering::Relaxed) > 0)
                    })
                    .map(|(i, s)| (i, s.hint.as_str()))
                    .partition(|(_, hint)| {
                        set_names.contains(&nzbkit::disk::sanitize_filename(hint).to_lowercase())
                    })
            };
            let in_set_bad: Vec<&str> = in_set_pairs.iter().map(|(_, h)| *h).collect();
            println!(
                "verified {} file(s): {} blocks in-stream, {} by read-back, {} bad - settled in {:.0} ms",
                reports.len(),
                live,
                readback,
                bad,
                vt0.elapsed().as_secs_f64() * 1000.0,
            );
            if damage > 0 {
                note_activity("repairing");
                // M2c.1: first try repairing straight INTO the extracted
                // output through the block→payload mapping - no volume
                // files ever touch disk. Every declined case (gate miss,
                // I/O error, MD5 verify failure) returns false and the
                // materialize path below runs unchanged.
                // Par2 names the mapped repair recreated WHOLE from parity
                // (empty unless it succeeded) - each proved by its
                // whole-file MD5, so they answer the "still short" verdict
                // below.
                let mut recreated_names: Vec<String> = Vec::new();
                let mapped_ok = if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_none() {
                    try_mapped_repair(
                        &servers,
                        &nzb,
                        out_dir,
                        &set,
                        needed,
                        &already,
                        &sniffed_vols,
                        buf_pool.clone(),
                        &extractor,
                        &reports,
                        &missing_files,
                        &mut recreated_names,
                        // Fast verify is the default and CRC32 is what the
                        // in-stream path trusts too; an operator who turned
                        // it off is asking for MD5 everywhere, including
                        // here.
                        !fast_verify,
                    )
                    .await?
                } else {
                    false
                };
                // Mapped repair writes corrected plaintext through the
                // crypto shim, which refreshes chain checkpoints and
                // final-block padding. Persist those facts before any
                // crash can leave a truthful D placement paired with
                // stale pre-repair K/T records.
                journal.record_crypto_events(&extractor.drain_crypto_events());
                // Did a repair actually PROVE the files the set names? Only
                // then does "the set names this file" prove the file: native
                // repair_dir (and par2cmdline behind it) require every file
                // in the set to match its FileDesc whole-file MD5 or the
                // repair fails. The RAR recovery-record fallback never looks
                // at the par2 set at all, so it can never speak for one.
                //
                // The mapped repair proves exactly what it REBUILT: parity
                // as a source recreates a wholly-missing file and
                // `repair_mapped` whole-file-MD5s it through the same view
                // before returning - the same standard, so those names count
                // (`recreated_names`). A file it merely left alone still
                // does not.
                let mut set_files_proven: Vec<String> = Vec::new();
                if mapped_ok {
                    set_files_proven = std::mem::take(&mut recreated_names);
                    // A mapped repair proves ITSELF: `repair_mapped`
                    // re-reads every file of the set back through the same
                    // block→payload view it wrote through - whole-file MD5
                    // for the files it rebuilt into, per-block CRC32 for
                    // the rest - and a mismatch declines the repair instead
                    // of returning true. A covered file whose pwrite failed
                    // therefore cannot reach here: the bytes that never
                    // landed read back wrong. Covered slots are exactly the
                    // set's files (the verifier claims each one for at most
                    // one slot, and only a claimed slot gets a report), so
                    // that re-read leaves none of them untested.
                    //
                    // A per-slot error counter used to gate this instead,
                    // from when the self-prove covered only the rebuilt
                    // files. It outlived that fix, and it was never the
                    // right test anyway: `slot.errors` counts DECODE errors
                    // alongside write errors, and a yEnc CRC failure is
                    // precisely the hole the repair just filled. A post
                    // with one corrupt article per volume repaired
                    // perfectly and then finished Failed, with byte-correct
                    // output sitting in the directory.
                    //
                    // Slots the set does NOT cover are still tested below -
                    // there a decode error IS lost bytes, because no
                    // recovery block speaks for them.
                    all_good = true;
                } else {
                    // PAR2 repair operates on volume FILES - materialize every
                    // mapped slot of the set (complete ones too: par2 verifies
                    // the whole set from disk) under its PAR2 name. A CHASED
                    // slot (a posted .7z streaming out of RAM) has no file
                    // either and must come down too, or par2 sees it missing
                    // and tries to recreate a whole archive we are holding.
                    let any_mapped = reports.iter().any(|(s, _)| extractor.is_mapped(*s));
                    let any_chased = reports.iter().any(|(s, _)| extractor.is_chased(*s));
                    // A RAR chase (depth-0 compressed set) must be claimed for
                    // the post-repair re-extract too: its "materialized for
                    // repair" demote reason is excluded from the unrar ladder
                    // on the promise that this path re-extracts what it
                    // materialized, and no other pass owns the set - without
                    // the claim the job shipped repaired-but-packed volumes as
                    // its output with exit 0. A materialized .7z stays out:
                    // the 7z post-pass runs regardless and re-extracting here
                    // would only double the work.
                    let any_rar_chased = reports.iter().any(|(s, _)| extractor.is_rar_chased(*s));
                    if any_mapped || any_chased {
                        note_activity("repairing");
                        println!("materializing volumes for repair…");
                        damage_in_mapped |= any_mapped || any_rar_chased;
                        for (sidx, r) in &reports {
                            if extractor.is_mapped(*sidx) || extractor.is_chased(*sidx) {
                                if let Some(pname) = &r.par2_name {
                                    extractor.rename(*sidx, pname);
                                }
                                if let Err(e) = extractor.materialize(*sidx) {
                                    eprintln!("materialize slot {sidx}: {e}");
                                }
                            }
                        }
                    }
                    let main_par2 = {
                        let mut p = None;
                        for (sidx, slot) in slots.iter().enumerate() {
                            if slot.is_par2_main
                                && let Some(path) = extractor.slot_path(sidx)
                            {
                                p = Some(path);
                                break;
                            }
                        }
                        // Obfuscated post: the sniffed bootstrap's on-disk
                        // file carries the same critical packets a named
                        // main would - good enough for the par2cmdline
                        // fallback's set argument.
                        p.or_else(|| sniff_bootstrap.and_then(|s| extractor.slot_path(s)))
                    };
                    let repaired = fetch_and_repair(
                        &servers,
                        &nzb,
                        out_dir,
                        &set,
                        needed,
                        main_par2,
                        &already,
                        &sniffed_vols,
                        buf_pool.clone(),
                        &extractor,
                        &mut repair_shortfall,
                    )
                    .await?;
                    // A successful disk repair re-read the WHOLE set off
                    // disk, so it speaks for every file the set names.
                    if repaired {
                        set_files_proven = set.files.iter().map(|f| f.name.clone()).collect();
                    }
                    // Repaired volume files on disk → re-extract them cleanly.
                    // rc=0 requires the END state to be usable output, not
                    // just a successful repair.
                    //
                    // Whole-file recreation: any set file no slot claimed
                    // (`missing_files`) was just rebuilt on disk by this
                    // repair - `repaired` re-read the whole set, so the file
                    // is there and proven. A recreated file sits on disk
                    // exactly like a materialized one and needs the same
                    // re-extract pass; without it the job exits 0 with the
                    // recreated volumes still packed (the nested pass skips
                    // them as the downloaded outer set). Covers the par-only
                    // post (no data slots at all, `reports` empty) and the
                    // MIXED set - a clean .nfo that reports beside a wholly
                    // ghosted .rar. The old test was `reports.is_empty() &&
                    // ...`, which read the .nfo's report as proof nothing
                    // was recreated and greened the mixed job still packed
                    // (Codex H2, 2 Aug). A recreated bare payload passes
                    // through reextract_dir untouched (no volumes → Ok(true)).
                    let recreated_set = !missing_files.is_empty();
                    if repaired && (damage_in_mapped || recreated_set) {
                        all_good = reextract_dir(out_dir, password.as_deref())?;
                        if !all_good {
                            reextract_failed =
                                Some("PAR2 repair succeeded but re-extraction failed".into());
                        }
                    } else {
                        all_good = repaired;
                        if !all_good {
                            // PAR2 could not repair - the volumes' own embedded
                            // recovery records are the last remaining redundancy.
                            all_good = try_rar_rr_repair(out_dir, password.as_deref());
                        }
                    }
                } // mapped_ok else
                // An obfuscated post names its files nothing like the PAR2
                // set does - issue #9's shape is par2 created FIRST and
                // every file renamed after - so a file the set covers and
                // parity just rebuilt still lands in `uncovered_pairs`,
                // purely because its posted subject is a hash. Left alone
                // that fails a job whose output is complete and MD5-proved.
                //
                // Reconcile those against set files that no slot claimed
                // and THIS repair rebuilt whole and proved: one FileDesc
                // per slot, only for a slot that arrived nothing at all,
                // and only when the declared sizes agree. Whatever stays
                // unpaired still fails the job, so a genuine out-of-set
                // loss is untouched.
                if all_good && !uncovered_pairs.is_empty() {
                    let mut spare: Vec<_> = set
                        .files
                        .iter()
                        .filter(|f| {
                            missing_files.iter().any(|m| m == &f.name)
                                && set_files_proven.iter().any(|p| p == &f.name)
                        })
                        .collect();
                    uncovered_pairs.retain(|(i, _)| {
                        // Only a slot that arrived NOTHING can be an alias:
                        // one that wrote bytes had a yEnc name to claim its
                        // FileDesc with, and did not.
                        let s = &slots[*i];
                        if s.missing.load(Ordering::Relaxed) != s.total_segments {
                            return true;
                        }
                        let posted = nzb.files[slot_file[*i]].bytes();
                        // NZB byte counts are yEnc-ENCODED and explicitly
                        // approximate, so this is a sanity band and not an
                        // equality - it is here to stop an unrelated extra
                        // file pairing off against a set file of a quite
                        // different size. A sizeless NZB pairs nothing.
                        let Some(k) = spare.iter().position(|f| {
                            posted > 0
                                && f.length > 0
                                && posted.saturating_mul(100) >= f.length.saturating_mul(90)
                                && posted.saturating_mul(100) <= f.length.saturating_mul(120)
                        }) else {
                            return true;
                        };
                        let f = spare.remove(k);
                        println!(
                            "  ✔ {} never arrived under its posted name, and the set rebuilt \
                             it as {} ({} bytes, MD5-proved)",
                            s.hint, f.name, f.length
                        );
                        false
                    });
                }
                let uncovered_bad: Vec<&str> = uncovered_pairs.iter().map(|(_, h)| *h).collect();
                // Whatever the repair did, it did it inside the recovery set.
                if all_good && !uncovered_bad.is_empty() {
                    all_good = false;
                    println!(
                        "  ✘ repair succeeded, but {} file(s) outside the PAR2 set are still \
                         incomplete: {}",
                        uncovered_bad.len(),
                        uncovered_bad.join(", ")
                    );
                }
                // Short their articles, named by the set, but on a path that
                // never re-read the whole set off disk: unproven bytes, so
                // they fail the job just the same. Reported separately - they
                // are NOT outside the set, and saying so would send a user
                // hunting for a file that is sitting in the recovery set.
                let unproven_bad: Vec<&str> = if all_good {
                    let proven: std::collections::HashSet<String> = set_files_proven
                        .iter()
                        .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
                        .collect();
                    in_set_bad
                        .iter()
                        .copied()
                        .filter(|h| {
                            !proven.contains(&nzbkit::disk::sanitize_filename(h).to_lowercase())
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                if all_good && !unproven_bad.is_empty() {
                    all_good = false;
                    println!(
                        "  ✘ repaired in place, but {} file(s) the PAR2 set covers are still \
                         short and were never proved against the set: {}",
                        unproven_bad.len(),
                        unproven_bad.join(", ")
                    );
                }
                // The ⚠ census above is the last thing the log says about
                // these files, and on its own it reads like the loss stood.
                // Repair rebuilt them from parity and proved each against its
                // whole-file MD5, so the census stays and this line settles
                // what became of it.
                if all_good && !in_set_bad.is_empty() {
                    println!(
                        "  ✔ {} file(s) that never arrived were rebuilt in full from PAR2 \
                         recovery data: {}",
                        in_set_bad.len(),
                        in_set_bad.join(", ")
                    );
                }
            } else {
                println!("clean download - no repair, no post-verify pass ✔");
                // PAR2 verifying clean is NOT the same as the download being
                // whole: `damage` only ever counts files the recovery set
                // covers (`unclaimed_files` walks `set.files`), and the
                // in-stream verifier hashes bytes as they ARRIVE, not off
                // disk. So a .nfo/sample/.sfv posted outside the par2 set
                // whose articles all 430'd, or a covered file whose write hit
                // ENOSPC after its blocks verified in flight, both land here
                // with damage == 0. Reporting success then deletes the
                // journal - the only record of what is still missing - and
                // hands an *arr an incomplete directory to import. Same test
                // the no-PAR2 branch below already applies.
                all_good = incomplete == 0 && derrs == 0;
            }
            // The end-of-job sniffed-leftover sweep (below, after
            // extractor.finish()) needs the set's FileDesc names to spare
            // payload that is ITSELF par2 - record them while the set is
            // in scope.
            sniff_covered = Some(
                set.files
                    .iter()
                    .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
                    .collect(),
            );
        }
        None => {
            // No PAR2 set in the NZB (or activation failed): best-effort
            // post-download verify against whatever par2 files landed.
            let disk_verified = verify_dir(out_dir)?;
            all_good = incomplete == 0 && derrs == 0;
            // Succeeding here with the post's recovery data damaged means
            // shipping output nothing ever checked. The payload is whole -
            // every article arrived and decoded, which is why this is not a
            // failure - but "complete" and "verified" are different claims
            // and only the first one is true. Say which, in as many words:
            // the alternative is a silent success that reads exactly like a
            // verified one. Skipped when `verify_dir` proved the files off
            // disk anyway (an obfuscated post's sniffed volumes land there),
            // and when the post simply carried no recovery data at all -
            // that has always succeeded quietly and is not news.
            if all_good && !disk_verified && recovery_errs + recovery_missing > 0 {
                let mut how = Vec::new();
                if recovery_errs > 0 {
                    how.push(format!("{recovery_errs} article(s) arrived corrupt"));
                }
                if recovery_missing > 0 {
                    // The noun rides on the first clause only, so both the
                    // one-cause and two-cause forms read as English.
                    how.push(if how.is_empty() {
                        format!("{recovery_missing} article(s) never arrived")
                    } else {
                        format!("{recovery_missing} never arrived")
                    });
                }
                println!(
                    "  ⚠ the PAR2 recovery data this post carries did not survive ({})",
                    how.join(", ")
                );
                println!(
                    "    the download itself is complete: every payload article arrived and \
                     decoded, and the files are in place. There was just no usable recovery \
                     set left to check them against, so this download is unverified."
                );
            }
            // Slots still short articles that the disk-side PAR2 fallback
            // below turns out not to cover. Held across the RR fallback
            // too: neither repair can certify a file no recovery set ever
            // named.
            let mut uncovered_after_par2: Vec<String> = Vec::new();
            if !all_good {
                // Public issue #9. Getting here with a damaged download
                // does NOT mean the post shipped no recovery data - on a
                // fully obfuscated post it usually means we could not SEE
                // it. Classification runs off the NZB's subject lines, and
                // when the index and every recovery volume is a hash with
                // no extension there is nothing in a subject to read, so
                // all of it arrives classified as payload and the whole
                // repair ladder above is unreachable. That is why SABnzbd
                // repaired posts we failed: it identifies par2 from the
                // file contents instead.
                //
                // The bytes are on disk either way, so ask the directory
                // rather than the NZB. `dir_has_par2` sniffs the
                // `PAR2\0PKT` packet magic, and `repair_dir` is already
                // obfuscation-complete underneath it: it magic-sniffs
                // packets and hash-matches obfuscated data files during
                // its adoption scan, restoring them under their true
                // FileDesc names. `extract_local` has always driven it
                // this way; this path simply never asked.
                //
                // Strictly a last resort, and it can only ever ADD an
                // outcome: it runs exclusively where no set was activated,
                // which is exactly the case that had no repair at all.
                //
                // Issue #14: volumes identified in-stream were DEFERRED,
                // and reaching this arm means their set never activated
                // (a damaged bootstrap, or unparseable packets) - so the
                // recovery data the disk repair below needs is not on
                // disk yet. Fetch all of it: without a set there is no
                // block arithmetic to fit exactly, and this is the rare
                // fallback where correctness outranks bandwidth.
                {
                    // Only slots that actually HAVE deferred articles: a
                    // sniffed volume that nonetheless landed in full (a
                    // cancel that caught nothing, or a fully-restored
                    // resume volume) is already on disk and refetching it
                    // buys nothing.
                    let deferred_vols: Vec<usize> = sniff
                        .deferred_slots()
                        .into_iter()
                        .filter(|&s| slots[s].deferred.load(Ordering::Relaxed) > 0)
                        .map(|s| slot_file[s])
                        .collect();
                    if !deferred_vols.is_empty() {
                        println!(
                            "fetching {} deferred recovery volume(s) for disk repair…",
                            deferred_vols.len()
                        );
                        if let Err(e) =
                            fetch_volumes(&servers, &nzb, out_dir, &buf_pool, &deferred_vols).await
                        {
                            println!("  ⚠ deferred volume fetch failed: {e}");
                        }
                    }
                }
                if dir_has_par2(out_dir).unwrap_or(false) {
                    use nzbkit::par2repair::{
                        RepairStatus, covered_names, repair_present_or_renamed_sets,
                        sniffed_packet_files,
                    };
                    let t0 = Instant::now();
                    note_activity("repairing");
                    println!(
                        "no PAR2 set came from the NZB, but the downloaded files \
                         include one - repairing from disk…"
                    );
                    // Every set whose data files are on disk, not just the
                    // first in packet-sorted order (`repair_dir`'s rule).
                    // A season pack posted with a set per episode had one
                    // arbitrary set decide the whole job: that set
                    // verifying clean reported success while the damaged
                    // episode's set was never looked at.
                    // The `or_renamed` entry point: on a wholly renamed
                    // post no FileDesc name is on disk, and the plain
                    // presence gate would skip a complete recovery set
                    // sitting right there. Safe HERE because this arm
                    // owns a directory where every downloaded byte has
                    // already landed; the nested post-pass keeps the
                    // name-only gate for the opposite reason.
                    let results = match repair_present_or_renamed_sets(out_dir) {
                        Ok(r) => r,
                        Err(e) => {
                            println!("PAR2: repair error - {e}");
                            Vec::new()
                        }
                    };
                    // Vacuous truth is not success: no set qualifying (no
                    // packets, or no set whose files are here) means no
                    // repair happened at all.
                    let mut every_set_ok = !results.is_empty();
                    // Obfuscated copies the adoption scan read the payload
                    // out of, gathered across every set and acted on only
                    // once ALL of them have verified: with a set per
                    // episode, one repaired set is no licence to delete
                    // anything another set may still need.
                    let mut consumed: Vec<PathBuf> = Vec::new();
                    // Names a set actually VERIFIED. A set with no data
                    // file on disk is skipped and reports nothing, so
                    // its declared names are not evidence about
                    // anything - see the hole scan below.
                    let mut healed: Vec<String> = Vec::new();
                    for r in results {
                        match r.status {
                            Ok(RepairStatus::NoDamage) => {
                                println!("PAR2: no damage, set verifies on disk ✔");
                                healed.extend(r.names);
                            }
                            Ok(RepairStatus::Repaired(rep)) => {
                                println!(
                                    "PAR2: repaired ✔ ({} block(s) rebuilt across {} file(s))",
                                    rep.blocks_rebuilt,
                                    rep.files_patched.len(),
                                );
                                consumed.extend(rep.consumed_sources);
                                healed.extend(r.names);
                            }
                            Ok(RepairStatus::Unrepairable { needed, have }) => {
                                println!(
                                    "PAR2: UNREPAIRABLE - need {needed} recovery block(s), have {have}"
                                );
                                repair_shortfall = Some((needed, have));
                                every_set_ok = false;
                            }
                            Err(e) => {
                                println!("PAR2: repair error - {e}");
                                every_set_ok = false;
                            }
                        }
                    }
                    if every_set_ok {
                        // A repair proves the files in its own recovery
                        // set and says nothing whatever about the rest -
                        // the invariant the in-stream arm above spells out
                        // and tests for. NoDamage is the sharper case: it
                        // means the fallback healed NOTHING, on a path only
                        // reached because something was already bad.
                        // Two different questions, two different sets.
                        //
                        // `named` is every name ANY set in the directory
                        // speaks for - the right answer to "is this file
                        // somebody's payload", which is what the
                        // recovery-volume sweep below asks before it
                        // deletes anything.
                        //
                        // `covered` is only what a set that actually
                        // REPORTED verified. A set whose data files are
                        // all absent is skipped and never runs, so
                        // counting its declared names as healed let a
                        // wholly missing file - one file of a season
                        // pack taken down, every article 430 - read as
                        // covered in the hole scan. The job reached
                        // Completed, and deleted the journal that was
                        // the only record of what was still missing.
                        let named: std::collections::HashSet<String> = covered_names(out_dir)
                            .unwrap_or_default()
                            .iter()
                            .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
                            .collect();
                        let covered: std::collections::HashSet<String> = healed
                            .iter()
                            .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
                            .collect();
                        // Issue #9, second half. The payload now exists
                        // under the name the PAR2 set gives it, so the
                        // obfuscated file its bytes were read out of is a
                        // byte-for-byte duplicate - 8.2 GB of one on the
                        // report that raised this, beside the 8.2 GB that
                        // was wanted. The engine will not remove a source
                        // (it does not own this directory) and the job
                        // tail's sweep goes by extension, which a hash
                        // name has none of, so the duplicate outlived
                        // every existing cleanup.
                        //
                        // BEFORE the uncovered-hole scan below, and that
                        // ordering is load-bearing in both directions.
                        // `covered` is already computed, so the packets
                        // have been read. And the scan asks whether each
                        // damaged slot's file is a hole: a consumed source
                        // still sitting there under a hash name matches no
                        // covered name and is not par2 magic, so it reads
                        // as an uncovered hole and fails the whole job.
                        // Deleted, it takes the `!had_writer` branch -
                        // "the extractor opened a file and it is gone,
                        // adopted or renamed under its FileDesc name" -
                        // which is exactly what happened.
                        //
                        // Only files that provably served as adoption
                        // sources, and only once every set verified. Never
                        // a sweep by shape: "extensionless in a finished
                        // directory" describes real payload too.
                        let mut freed: u64 = 0;
                        let mut gone: usize = 0;
                        // Trash-aware: a consumed adoption source is the
                        // obfuscated post's own downloaded volume - the
                        // set a user might want to keep or re-share -
                        // and the sniffed recovery files go "under the
                        // setting that governs named .par2", which since
                        // §64 has meant a recoverable delete. Parked for
                        // the deferred worker like every other sweep in
                        // a job's tail, and the flag read once here at
                        // the sweep's entry (remove_user_file's
                        // contract).
                        let recoverable = crate::smart::delete_to_trash();
                        let staging = crate::smart::trash_staging_dir(out_dir);
                        let mut remove = |p: &std::path::Path| {
                            let len = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                            match crate::smart::remove_swept_file(
                                p,
                                recoverable,
                                staging.as_deref(),
                            ) {
                                Ok(_) => {
                                    freed += len;
                                    gone += 1;
                                }
                                Err(e) => {
                                    // warn!, not println: the log ring is
                                    // where "why is this file still
                                    // here" gets answered.
                                    warn!(
                                        target: "cleanup",
                                        "could not remove {} - {e}",
                                        p.display()
                                    )
                                }
                            }
                        };
                        consumed.sort();
                        consumed.dedup();
                        for p in &consumed {
                            remove(p);
                        }
                        // The spent recovery volumes go the same way, under
                        // the setting that governs named `.par2` - these are
                        // simply the ones no extension rule can match. The
                        // sniff is directory-wide and says nothing about
                        // which set a volume served, which is the other
                        // reason this waits for every set to have verified.
                        //
                        // A sniffed file that is ITSELF recovery-set payload
                        // (a post whose content is par2 files) is excluded
                        // by name: `named` is exactly the set of names the
                        // packets speak for, skipped sets included - a
                        // set that never ran still owns its files.
                        if par_cleanup {
                            for p in sniffed_packet_files(out_dir).unwrap_or_default() {
                                let is_payload = p
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_lowercase())
                                    .is_some_and(|n| named.contains(&n));
                                if !is_payload {
                                    remove(&p);
                                }
                            }
                        }
                        if gone > 0 {
                            // "freed" only when the bytes actually left
                            // the disk - a recoverable delete parks them
                            // in the Trash on the same volume.
                            println!(
                                "  cleaned up {gone} obfuscated leftover(s), {:.1} MB {}",
                                freed as f64 / 1e6,
                                if recoverable { "to the Trash" } else { "freed" }
                            );
                        }
                        uncovered_after_par2 = slots
                            .iter()
                            .enumerate()
                            .filter(|(_, s)| {
                                // is_par2(): a sniffed volume's deferred
                                // (or 430'd) articles are not payload holes.
                                !s.is_par2()
                                    && (s.missing.load(Ordering::Relaxed) > 0
                                        || s.remaining.load(Ordering::Relaxed) > 0
                                        || s.errors.load(Ordering::Relaxed) > 0)
                            })
                            // A mapped or chased slot has no standalone
                            // file by design (its bytes went straight
                            // into extracted output), so the name test
                            // below cannot speak for it either way.
                            .filter(|(i, _)| {
                                !extractor.is_mapped(*i)
                                    && !extractor.is_chased(*i)
                                    && !extractor.is_rar_chased(*i)
                            })
                            .filter(|(i, s)| {
                                slot_is_uncovered_hole(
                                    out_dir,
                                    extractor.slot_path(*i),
                                    &s.hint,
                                    &covered,
                                )
                            })
                            .map(|(_, s)| s.hint.clone())
                            .collect();
                        // The census's own out-of-set findings belong
                        // here too (Codex sweep 2, 3 Aug M2). A slot
                        // whose articles ALL arrived and still does not
                        // cover its declared range has every counter at
                        // zero, so the scan above cannot see it - and
                        // it was exempted from the set by construction,
                        // so the repair that just succeeded says
                        // nothing about it.
                        for hint in &sparse_slots {
                            if !uncovered_after_par2.contains(hint) {
                                uncovered_after_par2.push(hint.clone());
                            }
                        }
                        if uncovered_after_par2.is_empty() {
                            println!("repair complete in {:.2?} ✔", t0.elapsed());
                            all_good = true;
                        } else {
                            println!(
                                "  ✘ repair succeeded, but {} file(s) outside the PAR2 set \
                                 are still incomplete: {}",
                                uncovered_after_par2.len(),
                                uncovered_after_par2.join(", ")
                            );
                        }
                    }
                }
            }
            if !all_good {
                // Missing articles left zero-filled holes and no PAR2
                // filled them - embedded RAR recovery records can.
                all_good = try_rar_rr_repair(out_dir, password.as_deref());
                // Recovery records heal the RAR set they live in. A file
                // the PAR2 pass already found outside every recovery set
                // is still a hole, whatever the volumes did.
                if all_good && !uncovered_after_par2.is_empty() {
                    all_good = false;
                    println!(
                        "  ✘ RAR recovery records cannot speak for {} file(s) outside \
                         the PAR2 set: {}",
                        uncovered_after_par2.len(),
                        uncovered_after_par2.join(", ")
                    );
                }
            }
        }
    }

    // --- extraction summary ---
    let ex_report = extractor.finish()?;
    // Now that no writer holds the partial file, a chased slot that
    // demoted can take the deobfuscated name after all. A slot whose
    // chase SUCCEEDED has no file left to rename (sevenz_finish deletes
    // the partial - the payload came out the other way), so slot_path is
    // None and this skips it.
    for (sidx, pname) in &deferred_renames {
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

    // Second late-attach read (C1): the settle/repair phase between the
    // network drain and this ladder runs for minutes on a big damaged
    // set, and a password typed during it must not miss this job too.
    let password: Option<String> = hub
        .as_ref()
        .and_then(|h| h.late_password_for(stream_owner))
        .or(password);
    // Everything from here to the end of the run is unpack work (the
    // disk-side ladders below, or the nested second pass) - close
    // enough for the queue row even on jobs that skip them all, since
    // those reach the finish within moments.
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
        let shape = final_shape
            .as_ref()
            .map(|s| s.display())
            .unwrap_or_default();
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
        all_good = reextract_dir(out_dir, password.as_deref())?;
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
        match try_unrar_spent(out_dir, password.as_deref()) {
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
        match try_unrar_spent(out_dir, password.as_deref()) {
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
    } else if nested_archive_beside_leftovers(out_dir, &outer_vol_stems) {
        match OuterHold::park(out_dir, &outer_vol_stems) {
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
        let nested_res = extract_nested(out_dir, password.as_deref(), 1);
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
    // M15 memory summary - the line benchmarks quote and budgets tune.
    let (pp_peak, pp_spilled) = verifier.partials_stats();
    println!(
        "mem: peak RSS {:.2} GB · holds peak {:.0} MB · verify partials peak {:.0} MB ({pp_spilled} blocks to read-back) · budget {:.2} GB",
        nzbkit::mem::peak_rss().unwrap_or(0) as f64 / 1e9,
        extractor.holds_peak() as f64 / 1e6,
        pp_peak as f64 / 1e6,
        budget.total as f64 / 1e9,
    );

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
        let recoverable = crate::smart::delete_to_trash();
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

    // Download complete and verified (or repaired): the journal's job is
    // done. Anything less is a FAILED job - the daemon parks it in history
    // (an *arr must see Failed, never import an incomplete dir) and the
    // journal stays on disk so a retry fetches only what's still missing.
    if all_good {
        if let Ok(j) = Arc::try_unwrap(journal) {
            j.remove();
        }
        return Ok(());
    }
    // Failing: print the block a bug report can carry whole. The daemon
    // mirrors stdout into the dashboard log ring, so this is what a user
    // pastes when they say "every file failed".
    print_failure_diagnostics(&servers, &stats);
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
            dead_servers: &dead_servers,
            // Sniffed slots count: "this post carries no PAR2 recovery
            // data" must not be claimed about a post whose recovery set
            // was identified in-stream (issue #14).
            par2_slots: slots.iter().filter(|s| s.is_par2()).count(),
            stalled: stalled.load(Ordering::Relaxed),
            missing_segments,
            total_segments,
            bytes_arrived: total,
            backbones: &backbones,
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

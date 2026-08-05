//! The download pipeline: get_with_progress, the whole one-pass fetch/decode/verify/extract drive shared by the get command and the daemon.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use nzbkit::pool::fetch_all_multi_ctl;
use std::path::Path;

mod vrig;
use vrig::{Rig, build_rig, install_seek};
mod fleet;
use fleet::{Fleet, build_fleet};
mod plan;
use plan::{FetchPlan, Intake, build_fetch_plan, build_intake, clamp_concurrency};
mod census;
use census::{Census, take_census};
mod tail;
use tail::{UnpackVerdict, finish_job, report_extraction, sweep_sniffed_leftovers, unpack_tail};
mod settle;
use settle::{SettleVerdict, fetch_matched_deferred, settle_verify_repair};
mod rig;
mod workers;
use workers::{
    Counters, build_counters, drain_network, spawn_deadlock_watchdog, spawn_decode_consumers,
    spawn_par_race, spawn_rate_ticker, spawn_spec_prefetch,
};

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
    // B4 small-RAM clamp + rotational decoder pick: see clamp_concurrency.
    let (connections, window, decoders) = clamp_concurrency(connections, window, decoders, out_dir);

    // Queue-row activity token, advanced at section transitions only
    // (never per article): the daemon's queue payload reads it to say
    // what the pipeline is doing right now. No hub (CLI) means no one
    // is listening; a sidecar's hub is never read by the queue payload.
    let note_activity = |tok: &'static str| {
        if let Some(h) = &hub {
            h.activity.lock_ok().insert(stream_owner.to_string(), tok);
        }
    };
    // Job intake - config, NZB parse, oracle routing, the archive
    // password, the crash-resume journal: see build_intake in
    // get/plan.rs. The destructure keeps downstream reads on the
    // inline names.
    let Intake {
        cfg_all,
        nzb,
        job_family,
        job_posted,
        password,
        journal,
        restored,
        completed,
        resuming,
        has_main,
        bootstrap_vol,
        resume_vols,
    } = build_intake(config, nzb_path, out_dir, password, &hub)?;
    // The slot + article fetch plan: see build_fetch_plan. The
    // destructure keeps every downstream read on the inline names.
    let FetchPlan {
        resume_sniffed_slots,
        resume_deferred_arts,
        resume_deferred_bytes,
        resume_have_bytes,
        slots,
        id_to_slot,
        slot_file,
        mut slot_arts,
        ids,
        fetch_done,
    } = build_fetch_plan(
        &nzb,
        &hub,
        &completed,
        resuming,
        bootstrap_vol,
        &resume_vols,
    );

    // The verification rig - verifier, sniff control, the configured
    // extractor: see build_rig. The destructure keeps every downstream
    // read on the inline names.
    let Rig {
        verifier,
        fast_verify,
        par2_outstanding,
        sniff,
        shape_said,
        resume_map,
        extractor,
    } = build_rig(
        &nzb,
        &slots,
        &slot_file,
        &hub,
        stream_owner,
        out_dir,
        &journal,
        &restored,
        &resume_sniffed_slots,
        resume_deferred_arts,
        resume_deferred_bytes,
        &fetch_done,
        &password,
        fast_verify,
        verify_lean,
        no_extract,
        resuming,
        &budget,
    );
    // M11: seek re-prioritization handle. QueueControl attaches to the
    // pool's pending queue when the fetch starts; SeekCtl turns player
    // read positions into promotions through it.
    let queue_ctl = Arc::new(nzbkit::pool::QueueControl::default());
    let abort_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The seek/promote ladder and the hub publish: see install_seek in
    // get/vrig.rs. slot_arts is taken - the SeekCtl owns it from here.
    let seek_names = install_seek(
        &slots,
        &mut slot_arts,
        &queue_ctl,
        &abort_flag,
        &extractor,
        &verifier,
        &hub,
        stream_owner,
    );
    let eager_bytes = nzb.eager_bytes();
    println!(
        "{}: {} files ({:.1} MB eager of {:.1} MB total) → {}",
        nzb_path.display(),
        slots.len(),
        eager_bytes as f64 / 1e6,
        nzb.total_bytes() as f64 / 1e6,
        out_dir.display()
    );

    // The buffer pools and the per-server fleet (race knobs, conntune
    // caps, warm-pool reconcile, live gauges, oracle sink): see
    // build_fleet. The destructure keeps downstream reads on the
    // inline names.
    let Fleet {
        buf_pool,
        out_pool,
        servers,
    } = build_fleet(
        &cfg_all,
        config,
        connections,
        window,
        &hub,
        job_posted,
        &job_family,
        &budget,
    )
    .await;

    // The outcome channel, the shared counters and samples, the
    // consumer throttle, the backfill cell: see build_counters in
    // get/workers.rs.
    let Counters {
        tx,
        rx,
        decoded_bytes,
        decode_errors,
        retention_excluded,
        missing_430,
        transport_failed,
        transport_sample,
        decode_error_sample,
        throttle_mbps,
        throttle_t0,
        backfill,
        rt,
    } = build_counters(&budget, progress, &hub, resume_have_bytes);
    // The decode-consumer fleet: see spawn_decode_consumers.
    let (consumers, pending_d) = spawn_decode_consumers(
        decoders,
        &rx,
        &buf_pool,
        &out_pool,
        &slots,
        &id_to_slot,
        &seek_names,
        &decoded_bytes,
        &fetch_done,
        &decode_errors,
        &retention_excluded,
        &missing_430,
        &transport_failed,
        &transport_sample,
        &decode_error_sample,
        &verifier,
        &extractor,
        &shape_said,
        &par2_outstanding,
        &journal,
        &backfill,
        &sniff,
        &queue_ctl,
        &rt,
        throttle_mbps,
        throttle_t0,
    );

    // Live rate ticker: see spawn_rate_ticker.
    let ticker = spawn_rate_ticker(decoded_bytes.clone(), slots.clone());

    // Deadlock watchdog: see spawn_deadlock_watchdog.
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = spawn_deadlock_watchdog(
        decoded_bytes.clone(),
        slots.clone(),
        queue_ctl.clone(),
        abort_flag.clone(),
        stalled.clone(),
    );

    let t0 = Instant::now();
    // M2c.5 speculative recovery prefetch: see spawn_spec_prefetch.
    let prefetched: Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let prefetch_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spec_prefetch_task: Option<tokio::task::JoinHandle<()>> = {
        let allowed = match &hub {
            Some(h) => h.spec_prefetch.load(Ordering::Relaxed),
            None => std::env::var_os("NZBFAST_NO_SPEC_PREFETCH").is_none(),
        };
        spawn_spec_prefetch(
            allowed,
            has_main,
            &nzb,
            &servers,
            &slots,
            out_dir,
            &buf_pool,
            &prefetched,
            &prefetch_stop,
        )
    };
    // PAR2-race experiment (dark): see spawn_par_race.
    let par_race_task = spawn_par_race(
        &slots,
        &verifier,
        &queue_ctl,
        &prefetch_stop,
        &prefetched,
        &fetch_done,
        &decoded_bytes,
        &slot_file,
        &nzb,
    );
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
    // Network phase over: stop the side tasks, join the decode
    // consumers, flush the last D records, honor abort/pause, signal
    // net_done and re-read the late password: see drain_network in
    // get/workers.rs. Bailing inside drops net_done, which the daemon
    // reads as network-drained - same as the inline code did.
    let (elapsed, password) = drain_network(
        &prefetch_stop,
        spec_prefetch_task,
        par_race_task,
        consumers,
        &pending_d,
        &extractor,
        &journal,
        t0,
        ticker,
        watchdog,
        &stalled,
        &abort_flag,
        &queue_ctl,
        &note_activity,
        net_done,
        &hub,
        stream_owner,
        password,
        &backfill,
    )
    .await?;

    // Issue #14 drain fallback - deferred slots the active set covers
    // fetch on the side machinery: see fetch_matched_deferred in
    // get/settle.rs.
    fetch_matched_deferred(
        &verifier, &sniff, &slots, &slot_file, &servers, &nzb, out_dir, &buf_pool, &extractor,
    )
    .await;

    // Post-drain accounting: see take_census. The destructure keeps every
    // downstream read on the same names the inline code used.
    let Census {
        total,
        dead_servers,
        backbones,
        post_age_days,
        sniff_bootstrap,
        incomplete,
        incomplete_spared,
        missing_segments,
        total_segments,
        sparse_slots,
        recovery_errs,
        derrs,
        retention_skipped,
        recovery_missing,
    } = take_census(
        &servers,
        &stats,
        &nzb,
        &slots,
        &sniff,
        &verifier,
        &extractor,
        &decode_errors,
        &retention_excluded,
        &decoded_bytes,
        elapsed,
    );

    // Phase marker: the network phase is over, the checks begin. On the
    // chart this is where throughput sits at zero on purpose - without
    // the marker a long repair reads as a download that died. The ring
    // lives on the fleet's shared LiveStats (build_fleet gave every
    // server's cfg the same Arc), so borrow it from the first server.
    if let Some(live) = servers.iter().find_map(|(_, c)| c.live.clone()) {
        live.note_run(
            "settle",
            "download finished - checking the files and repairing if needed",
        );
    }

    // Settle verification and the repair ladder: see get/settle.rs. The
    // destructure keeps every downstream read on the inline names.
    let SettleVerdict {
        all_good,
        reextract_failed,
        repair_shortfall,
        deferred_renames,
        sniff_covered,
    } = settle_verify_repair(
        &verifier,
        &extractor,
        &journal,
        &slots,
        &slot_file,
        &servers,
        &nzb,
        out_dir,
        &buf_pool,
        &sniff,
        sniff_bootstrap,
        bootstrap_vol,
        &resume_vols,
        &prefetched,
        fast_verify,
        par_cleanup,
        password.as_deref(),
        incomplete,
        derrs,
        &sparse_slots,
        recovery_errs,
        recovery_missing,
        &note_activity,
    )
    .await?;

    // Extraction summary: see report_extraction in get/tail.rs.
    let (ex_report, outer_vol_stems, final_shape) =
        report_extraction(&extractor, &deferred_renames, out_dir)?;

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
    // The disk-unpack tail (eat-arm, unrar ladder, nested pass): see
    // get/tail.rs.
    let UnpackVerdict {
        all_good,
        reextract_failed,
    } = unpack_tail(
        &extractor,
        &slots,
        &restored,
        &ex_report,
        &final_shape,
        &outer_vol_stems,
        out_dir,
        password.as_deref(),
        resuming,
        no_extract,
        resume_map,
        eat_consent,
        &note_activity,
        all_good,
        reextract_failed,
    )?;
    // M15 memory summary - the line benchmarks quote and budgets tune.
    let (pp_peak, pp_spilled) = verifier.partials_stats();
    println!(
        "mem: peak RSS {:.2} GB · holds peak {:.0} MB · verify partials peak {:.0} MB ({pp_spilled} blocks to read-back) · budget {:.2} GB",
        nzbkit::mem::peak_rss().unwrap_or(0) as f64 / 1e9,
        extractor.holds_peak() as f64 / 1e6,
        pp_peak as f64 / 1e6,
        budget.total as f64 / 1e9,
    );

    // Issue #14 tail - the sniffed-leftover sweep: see get/tail.rs.
    sweep_sniffed_leftovers(all_good, par_cleanup, &sniff, sniff_covered, out_dir);

    // Retire the journal on a good finish; otherwise print the
    // diagnostics block and fail with the closest cause: see
    // finish_job in get/tail.rs.
    finish_job(
        all_good,
        out_dir,
        &incomplete_spared,
        journal,
        &servers,
        &stats,
        reextract_failed,
        incomplete,
        derrs,
        &missing_430,
        retention_skipped,
        &transport_failed,
        &transport_sample,
        &decode_error_sample,
        &dead_servers,
        &slots,
        &stalled,
        missing_segments,
        total_segments,
        total,
        &backbones,
        post_age_days,
        repair_shortfall,
    )
}

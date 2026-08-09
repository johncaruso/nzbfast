//! The buffer pools and the server fleet (TODO 106 phase 2.1, cut 9):
//! race-stragglers knobs, connection auto-tune caps, the warm-pool
//! reconcile, per-server PoolConfigs with live gauges, and the M29
//! oracle sink. Body is a verbatim move from the orchestrator.

use crate::*;
use nzbkit::pool::{BufPool, PoolConfig};
use std::path::Path;

/// The wired fleet. Field names match the local bindings the inline
/// code used.
pub(super) struct Fleet {
    pub(super) buf_pool: Arc<BufPool>,
    pub(super) out_pool: Arc<BufPool>,
    pub(super) servers: Vec<(ServerConfig, PoolConfig)>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn build_fleet(
    cfg_all: &Config,
    config: &Path,
    connections: usize,
    window: usize,
    hub: &Option<Arc<StreamHub>>,
    job_posted: Option<i64>,
    job_family: &str,
    budget: &nzbkit::mem::MemBudget,
) -> Fleet {
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
    // Both tail knobs read the one settings.json the dashboard writes
    // (same loader as conntune::enabled, so the daemon and the CLI
    // agree); the env vars override PER KNOB in either direction - the
    // bench suite A/Bs single knobs against a live setting ("1"/"2"
    // arms, anything else disarms).
    let saved = crate::persist::load_json_with_backup(&config.with_file_name("settings.json"));
    // "Adaptive connection timeouts" (setting adaptive_timeouts, ON by
    // default): two-phase adaptive read bounds in place of the flat
    // whole-response timeout. Fault rigs (research/SPECULATION-
    // EXPERIMENTS-2026-08-04.md rounds 5/5b/5c): 4x on dead-air
    // stalls, stacks on brownout, zero false kills on jitter.
    let adaptive = saved
        .as_ref()
        .and_then(|v| v.get("adaptive_timeouts").and_then(|v| v.as_bool()))
        .unwrap_or(true);
    let adaptive_timeout = std::env::var("NZBFAST_ADAPTIVE_TIMEOUT")
        .ok()
        .map_or(adaptive, |v| v == "1");
    // "Race slow articles" (setting race_stragglers, ON by default).
    // Covers the three speculation knobs with measured payouts: early
    // tail fan-out (farm: tail 1.66 s -> 0.60 s), adaptive hedging
    // (rig: 12-13 s -> 6-8 s on a stalled article), and slope recycle
    // (rig: 45 s -> 25 s on one degraded session).
    let race = saved
        .as_ref()
        .and_then(|v| v.get("race_stragglers").and_then(|v| v.as_bool()))
        .unwrap_or(true);
    let tf = std::env::var("NZBFAST_TAIL_FANOUT").ok();
    let tail_fanout = tf.as_deref().map_or(race, |v| v == "1" || v == "2");
    let tail_fanout_early = tf.as_deref().map_or(race, |v| v == "2");
    let hedge = std::env::var("NZBFAST_HEDGE")
        .ok()
        .map_or(race, |v| v == "1");
    // TODO 115 (dark, env-only): dup-race an article after ~1 s of
    // pre-byte silence instead of waiting out the adaptive TTFB budget
    // (its floor is 2 s, paid serially per stall - the deadair matrix
    // residual). Rides the adaptive read path, so it is inert with
    // adaptive_timeouts off. Graduates the race_stragglers way only
    // with the jitter safety leg and the greet-delay rigs green.
    let ttfb_hedge = std::env::var("NZBFAST_TTFB_HEDGE").is_ok_and(|v| v == "1");
    let recycle_slope = std::env::var("NZBFAST_RECYCLE_SLOPE")
        .ok()
        .map_or(race, |v| v == "1");
    // Still dark (env-only): the race-loss recycle (subsumed by the
    // slope recycle in practice) and the hot spare (needs cap-aware
    // gating first - at an exact provider cap the spare would steal a
    // worker slot). NZBFAST_KEEPALIVE is read directly in the nntp dial
    // path (NZBFAST_DIAL_RACE was too, until §129 3c priced it out).
    let recycle_slow = std::env::var("NZBFAST_RECYCLE_SLOW").is_ok_and(|v| v == "1");
    let hot_spare = std::env::var("NZBFAST_HOT_SPARE").is_ok_and(|v| v == "1");
    // M7b.2 depth steering (dark, env-only): a server whose windowed
    // per-conn rate falls under 1/4 of the best other live server's
    // runs shallow pipelines (depth 1) instead of parking `window`
    // articles behind each slow session. Graduates the race_stragglers
    // way only with the steering rig's A/B and the real-line legs green
    // (research/DESIGN-PROVIDER-STEERING-RACING-2026-08-08.md §7).
    let steer_depth = std::env::var("NZBFAST_STEER_DEPTH").is_ok_and(|v| v == "1");
    // M7b.2 envelope racing (dark, env-only): per-owner hedge bounds,
    // the idle-picker envelope race, and the fleet-wide dup-spend
    // hygiene cap; the whole-run 2x slow-owner rule retires while
    // armed. Same graduation route as steer_depth. The per-server
    // block_account setting (design 5.7) is LANDED and wired into
    // PoolConfig::block_account below, so the economics no longer rest
    // on the level > 0 inference alone.
    let race_envelope = std::env::var("NZBFAST_RACE_ENVELOPE").is_ok_and(|v| v == "1");
    // TODO 115, graduated 5 Aug: cap-aware flap keepers - a
    // flap-clamped server whose accept cap was OBSERVED (dials bounced
    // off a capacity refusal) holds min(cap, budget) keepers instead of
    // one, so a provider willing to serve two sessions is not clamped
    // to half of that. Redials stay death-driven and bounce-paced, so
    // dials remain in the single-keeper's order - not the 217-dial
    // hammering the fault matrix measured from NZBGet on this shape.
    // Priced on the standalone chaos flap leg (one box, one corpus):
    // 43/43 s at 24 dials off, 40/40 s at 36 dials on - ties the best
    // competitor's wall at a sixth of its dials. Env overrides either
    // way.
    let flap_cap_keepers = std::env::var("NZBFAST_FLAP_CAP_KEEPERS")
        .ok()
        .is_none_or(|v| v == "1");
    // TODO 111/114 CRC retry-elsewhere, graduated to the consumer seam
    // 6 Aug: on a yEnc CRC failure (or a wrong-article body) the
    // article is refetched from a DIFFERENT server once, instead of
    // letting the damage ride to PAR2 repair - the corrupt-storm
    // matrix leg goes DNF -> byte-perfect, and every competitor
    // already does this. Detection is the decode consumer's EXISTING
    // pass (QueueControl::note_decoded), so the old pool-side second
    // decode - ~25% CPU at the loopback ceiling, the reason slow-CPU
    // boxes were priced out - is gone: the m1 full-rate A/B has the
    // steer at off-parity user CPU (9.3 vs the pool decode's 14.3
    // cpu-s per 8 GB) with equal walls, and the only remaining cost
    // is the forced per-article CRC where M32 delegation would have
    // skipped it (+4.5% user on a PAR2 full-MD5 job, wall parity).
    //
    // Default ON where an elsewhere exists. "2+ enabled servers" is
    // necessary but not sufficient: the steer marks tried_fail, and a
    // fill server's pickup gate demands the primary's 430 bit - so a
    // primary + fill pair can never steer, and a same-host (or same
    // explicit group) sibling serves the same wrong copy. Pay the
    // forced CRC only where a same-LEVEL peer on a different
    // host/backbone exists; the delivery-time other_can_take check
    // enforces the same rule live. Single-server configs pay nothing
    // at all. NZBFAST_CRC_STEER overrides both ways (the chaos rig's
    // same-host twins depend on =1); NZBFAST_CRC_RETRY is honored as
    // an alias - it named the same feature while the detection lived
    // in the pool, and the rig drivers still set it.
    let on: Vec<_> = cfg_all.servers.iter().filter(|s| s.enabled).collect();
    let multi_server = on.iter().enumerate().any(|(i, a)| {
        on.iter().enumerate().any(|(j, b)| {
            i != j
                && a.level == b.level
                && a.host != b.host
                && (a.group.is_none() || b.group.is_none() || a.group != b.group)
        })
    });
    let crc_steer = std::env::var("NZBFAST_CRC_STEER")
        .or_else(|_| std::env::var("NZBFAST_CRC_RETRY"))
        .map_or(multi_server, |v| v == "1");
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
    // Whether the live epoch controller is in charge for this run (the
    // `live_tune` setting mirrored on the hub, or the dev override).
    // Computed here because the cap note below must not print when the
    // knee is not capping.
    let live_tune = hub.as_ref().is_some_and(|h| {
        h.live_tune.load(std::sync::atomic::Ordering::Relaxed) || crate::conntune::live_tune_on()
    });
    let tuned_note: Vec<String> = cfg_all
        .servers
        .iter()
        .filter_map(|s| {
            let t = tuned.get(&s.host)?;
            let asked = crate::conntune::effective_limit(connections, s.connections);
            // A pinned server is not capped, so it must not be announced
            // as capped - this line is the ONLY explanation a user gets
            // for a number they did not choose, and printing it for a
            // number they DID choose is worse than printing nothing.
            (!s.pin_connections && !t.suspect && t.connections > 0 && t.connections < asked)
                .then(|| format!("{} capped at {} of {asked}", s.host, t.connections))
        })
        .collect();
    // With the live controller on, the knee SEEDS instead of capping -
    // announcing a cap that is not being applied is the same lie the
    // pinned-server exclusion exists to avoid.
    if !live_tune && !tuned_note.is_empty() {
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
    // TODO 112: with live tuning on (the `live_tune` setting, or
    // NZBFAST_LIVE_TUNE=1 as the dev override), the fleet is SPAWNED at
    // the ceiling and run at a live target the epoch controller moves.
    // The target starts at the SEED - the current time-of-day bucket
    // when it carries evidence, else the trusted knee, else the
    // configured count (conn-tuning design §5.1) - and the stored knee
    // does not cap the job: with the controller in charge, measurements
    // seed and only typed numbers cap. A pinned server keeps the old
    // shape: its number is a statement, not a state.
    //
    // Seeding reads the store directly rather than through `tuned`:
    // that map is emptied when auto_connections is off, but that toggle
    // governs the OFFLINE prober and its knee caps - a live-tune seed
    // is not a cap, and bucket evidence stays useful either way.
    let seed_store = if live_tune {
        crate::conntune::load(config)
    } else {
        Default::default()
    };
    let seed_bucket = crate::conntune::bucket_of(crate::conntune::local_hour());
    let seed_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut servers: Vec<_> = cfg_all
        .servers
        .iter()
        .map(|s| {
            let mut base = connections.min(s.connections.max(1) as usize);
            if let Some(cap) = host_caps.get(&s.host) {
                base = base.min((*cap).max(1));
            }
            let applied =
                crate::conntune::applied_connections(base, s.pin_connections, tuned.get(&s.host));
            let (conns, live_target) = match (live_tune && !s.pin_connections && base > 1, hub) {
                (true, Some(h)) => {
                    let seed = crate::conntune::seed_connections(
                        seed_store.get(&s.host),
                        seed_bucket,
                        seed_now,
                        base,
                    );
                    let t = h
                        .live_targets
                        .lock_ok()
                        .entry(s.host.clone())
                        .or_insert_with(|| nzbkit::pool::ConnTarget::new(seed))
                        .clone();
                    // A ceiling that moved between jobs clamps the
                    // surviving belief; a belief the controller earned
                    // above the prior survives the job boundary.
                    if t.get() > base {
                        t.set(base);
                    }
                    (base, Some(t))
                }
                _ => (applied, None),
            };
            let cfg = PoolConfig {
                connections: conns,
                live_target,
                window,
                buf_pool: Some(buf_pool.clone()),
                read_timeout,
                adaptive_timeout,
                tail_fanout,
                tail_fanout_early,
                steer_depth,
                race_envelope,
                // §5.7, and the one place the setting meets the pool:
                // per-server, never OR-folded across the fleet, because
                // the whole point of the flag is that one account's
                // billing says nothing about another's.
                block_account: s.block_account,
                hedge,
                ttfb_hedge,
                recycle_slow,
                recycle_slope,
                hot_spare,
                flap_cap_keepers,
                crc_steer,
                // TODO 121.4: the decode consumers ack every Done id
                // (note_settled / note_decoded), so the pool holds
                // each article's liveness entry until its bytes are
                // written - the dead-span verdict sees the whole pipe.
                arrival_ack: true,
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
            job_family.to_string(),
        );
        for (_, cfg) in servers.iter_mut() {
            cfg.oracle = Some(sink.clone());
        }
    }
    Fleet {
        buf_pool,
        out_pool,
        servers,
    }
}

#[cfg(test)]
mod block_account_wiring {
    use super::*;

    /// §5.7: the setting reaches the pool, PER SERVER.
    ///
    /// This one line is the whole join between a checkbox in the server
    /// editor and the racing gates in pool.rs, and neither side's own
    /// tests can see it: nzbkit pins that a flagged PoolConfig never
    /// races, and nzbkit::config pins that the field parses, but nothing
    /// else would notice if the wire between them were dropped in a
    /// refactor of this builder.
    ///
    /// Per-server and never OR-folded: one account's billing says
    /// nothing about another's, so a mixed fleet must come out mixed.
    #[tokio::test]
    async fn the_setting_reaches_the_pool_per_server() {
        let cfg: Config = serde_json::from_str(
            r#"{"servers":[
                 {"host":"flat.example"},
                 {"host":"metered.example","block_account":true}
               ]}"#,
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("nzbfast-ba-wire-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let fleet = build_fleet(
            &cfg,
            &dir.join("config.local.json"),
            4,
            4,
            &None,
            None,
            "",
            &nzbkit::mem::MemBudget::with_total(1 << 30),
        )
        .await;
        let flags: Vec<(String, bool)> = fleet
            .servers
            .iter()
            .map(|(s, p)| (s.host.clone(), p.block_account))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("flat.example".to_string(), false),
                ("metered.example".to_string(), true),
            ],
            "the flag must ride each server's own PoolConfig, not the fleet's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

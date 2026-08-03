//! M7b.1 - per-provider connection auto-tuning state.
//!
//! Measured 21 Jul 2026 (BENCHMARKS/PLAN §M7b): asking a provider for
//! more sockets than it wants to grant is 3-4× SLOWER than asking for
//! the knee (connect-flood defense) - connection count is the sharpest
//! single knob in the product, and it punishes the intuitive "more is
//! faster" direction. The daemon probes each provider's ladder while
//! idle (serve.rs) and stores the knee here; every job build then caps
//! each server's connections at min(configured, knee).
//!
//! State lives in `conntune.json` NEXT TO the config file (like
//! settings.json), so plain CLI `nzbfast get` runs benefit from the
//! daemon's probes too. The stored knee is the RAW recommendation; the
//! configured per-server `connections` (the account limit) stays the
//! hard cap at application time - a knee above it is surfaced as a
//! suggestion, never applied silently.

use crate::MutexExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Re-probe a provider after this long (knees move with provider policy).
pub const STALE_SECS: u64 = 7 * 86_400;

/// Re-probe a SUSPECT knee after this long instead - soon enough to
/// confirm or clear it within a day, far enough that the second sample
/// sees a different hour (a one-time provider or link issue at probe
/// time shouldn't survive corroboration).
pub const SUSPECT_STALE_SECS: u64 = 6 * 3600;

/// Stamped on every entry this build writes.
///
/// v0 = written before the `suspect` guard existed, so a low knee in a
/// v0 entry has never been corroborated by anything - it is one 5 s
/// ladder's opinion, which is exactly the sample that capped James at 6
/// of 18 and held him there. Guards that only run at RECORD time cannot
/// help an install whose bad knee is already on disk: nothing re-reads
/// it until the 7-day stale clock expires. The version lets
/// [`reopen_low_knees`] tell "measured under the old rules" from
/// "measured and corroborated under the new ones" exactly once.
pub const SCHEMA: u32 = 1;

/// Whether auto connection tuning is enabled in the dashboard settings
/// (settings.json next to the config; absent key = the default, ON).
/// The toggle gates APPLICATION as well as probing: switching it off
/// must lift a stored knee from the very next job, not keep capping
/// with stale state the user has disowned.
///
/// Through the same backup-aware loader every other settings read uses
/// (Codex sweep 2, 3 Aug ML3). A bare `read` + parse treats a torn or
/// half-written settings.json as "no setting", which for this key means
/// the default - ON. The daemon meanwhile loads the .bak and correctly
/// knows the user turned it OFF, so the two authorities disagreed and
/// every new job re-applied stored knees the user had disowned. One
/// loader, one answer.
pub fn enabled(config: &Path) -> bool {
    crate::persist::load_json_with_backup(&config.with_file_name("settings.json"))
        .and_then(|v| v.get("auto_connections").and_then(|v| v.as_bool()))
        .unwrap_or(true)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tuned {
    /// Recommended connection count (smallest reaching ≥90% of the
    /// ladder's peak rate).
    pub connections: usize,
    /// Most sockets the provider actually granted during the probe.
    pub granted: usize,
    /// Peak rate observed on the ladder (Gbps).
    pub gbps: f64,
    /// Unix time of the probe.
    pub checked: u64,
    /// "auto" (idle probe) or "manual" (dashboard ladder run).
    #[serde(default)]
    pub source: String,
    /// The knee would cut the configured connection count substantially
    /// and no earlier probe agrees yet - a single 5 s-per-rung ladder on
    /// a jittery link can fake a knee far below the true one (James: 6
    /// of 18). A suspect knee is NOT applied to jobs and is re-probed on
    /// the short clock; a second probe landing in the same place clears
    /// the flag (and, hours apart, samples a different time of day).
    #[serde(default)]
    pub suspect: bool,
    /// The ceiling in force when this knee was measured: the smaller of
    /// the global connections setting and the server's own configured
    /// count. Stored because the ceiling is an INPUT to the ladder (it
    /// sets how far the rungs climb), so raising it invalidates the
    /// measurement - see [`reopen_low_knees`]. 0 on a v0 entry.
    #[serde(default)]
    pub limit: usize,
    /// Schema version of this entry; see [`SCHEMA`].
    #[serde(default)]
    pub v: u32,
}

/// The connection ceiling a job would actually hand this server: the
/// global setting and the server's own configured count are both caps,
/// and the tuner has to reason about the smaller one. Judging a knee
/// against the server's number alone called 6 "suspiciously low" on an
/// install whose global setting was 6 - it was simply the ceiling.
pub fn effective_limit(global: usize, server_connections: u32) -> usize {
    global.max(1).min((server_connections.max(1)) as usize)
}

pub fn path_for(config: &Path) -> PathBuf {
    config.with_file_name("conntune.json")
}

pub fn load(config: &Path) -> HashMap<String, Tuned> {
    std::fs::read(path_for(config))
        .ok()
        .and_then(|b| serde_json::from_slice::<HashMap<String, Tuned>>(&b).ok())
        .unwrap_or_default()
}

/// Serializes every read-modify-write of conntune.json. The daemon's
/// probe loop, a manual ladder run and a settings edit all live in THIS
/// process: without the lock, two concurrent writers each load the old
/// map and the second write drops the first host's update - and both
/// used the same `.conntune.<pid>.tmp` path, tearing the file. The lock
/// removes the lost update; write_atomic (process-wide temp counter)
/// removes the torn write.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn save(config: &Path, map: &HashMap<String, Tuned>) {
    if let Ok(bytes) = serde_json::to_vec_pretty(map) {
        let _ = crate::persist::write_atomic(&path_for(config), &bytes);
    }
}

/// Merge one host's probe result in and persist.
pub fn record(config: &Path, host: &str, t: Tuned) {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    map.insert(host.to_string(), t);
    save(config, &map);
}

/// Put low knees back up for corroboration, and report which hosts moved.
///
/// A stored knee is a measurement taken under a ceiling - the ladder
/// only climbs as far as the configured count allows - so when the user
/// raises that ceiling the old measurement no longer answers the
/// question they are now asking. Until now nothing re-read the file on
/// that event, and the field report is unambiguous: James set 22, then
/// 24, restarted the app, tried a fresh NZB, and every job still ran at
/// the stored knee of 6 with the dashboard showing a flat `6/6`. The
/// number he typed had no effect and no way to have one.
///
/// So: for each host the user has configured, if the ceiling is now
/// higher than the one the knee was measured under AND the knee is less
/// than half of it, mark the entry `suspect` (jobs stop applying it, so
/// the user's number takes effect from the very next download) and zero
/// `checked` (the idle prober re-measures at its next opportunity, and
/// the corroboration rule decides). A knee that was right comes back
/// within one probe; a knee that was one bad 5 s sample does not.
///
/// v0 entries carry `limit: 0`, so this also sweeps the pre-guard files
/// already sitting on testers' disks the first time a new build runs -
/// which is the only thing that unsticks an install like James's.
/// Every entry seen is stamped to the current [`SCHEMA`], so the sweep
/// is once per entry, not once per call.
pub fn reopen_low_knees(
    config: &Path,
    limit_for: impl Fn(&str) -> Option<usize>,
) -> Vec<(String, usize, usize)> {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    let mut moved = Vec::new();
    let mut dirty = false;
    for (host, t) in map.iter_mut() {
        let Some(limit) = limit_for(host) else {
            continue; // not a server this install has configured
        };
        if limit > t.limit && t.connections * 2 <= limit && !t.suspect {
            t.suspect = true;
            t.checked = 0;
            moved.push((host.clone(), t.connections, limit));
            dirty = true;
        }
        // Record the ceiling this entry has now been judged against,
        // so the same raise never reopens it twice.
        if t.limit != limit || t.v != SCHEMA {
            t.limit = limit;
            t.v = SCHEMA;
            dirty = true;
        }
    }
    if dirty {
        save(config, &map);
    }
    moved
}

/// [`reopen_low_knees`] for a whole install: reads the server list off
/// disk and judges every stored knee against that server's effective
/// ceiling. Logs what it reopened, because a connection count silently
/// changing under the user is precisely the thing that took a support
/// round-trip to explain last time.
pub fn reopen_for_install(config: &Path, global: usize) {
    let Ok(cfg) = nzbkit::config::Config::load(config) else {
        return;
    };
    let limits: HashMap<&str, usize> = cfg
        .servers
        .iter()
        .map(|s| (s.host.as_str(), effective_limit(global, s.connections)))
        .collect();
    for (host, knee, limit) in reopen_low_knees(config, |h| limits.get(h).copied()) {
        println!(
            "[tune] {host}: your connection setting is now {limit}, well above the \
             measured {knee} - jobs will use {limit} while that measurement is \
             re-taken"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("nzbfast-conntune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        assert!(load(&cfg).is_empty());
        record(
            &cfg,
            "news.example.com",
            Tuned {
                connections: 12,
                granted: 12,
                gbps: 4.9,
                checked: 1,
                source: "auto".into(),
                suspect: false,
                limit: 20,
                v: SCHEMA,
            },
        );
        record(
            &cfg,
            "fill.example.com",
            Tuned {
                connections: 4,
                granted: 4,
                gbps: 0.8,
                checked: 2,
                source: "manual".into(),
                suspect: true,
                limit: 8,
                v: SCHEMA,
            },
        );
        let m = load(&cfg);
        assert_eq!(m.len(), 2);
        assert_eq!(m["news.example.com"].connections, 12);
        assert!(!m["news.example.com"].suspect);
        assert_eq!(m["fill.example.com"].source, "manual");
        assert!(m["fill.example.com"].suspect);
        // No settings.json in the dir: the toggle defaults ON.
        assert!(enabled(&cfg));
        std::fs::write(
            cfg.with_file_name("settings.json"),
            br#"{"auto_connections":false}"#,
        )
        .unwrap();
        assert!(!enabled(&cfg));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The v1.0.14 field case, end to end on the file.
    ///
    /// A pre-guard entry (v0, no `suspect`, no `limit`) holding a knee
    /// of 6 must stop capping the moment the install's ceiling is read
    /// as 24, and must be queued for a re-probe rather than deleted -
    /// if 6 really is this provider's knee, one probe puts it back.
    #[test]
    fn a_raised_ceiling_reopens_a_low_pre_guard_knee() {
        let dir = std::env::temp_dir().join(format!("nzbfast-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        // Exactly the shape v1.0.14 wrote: no `suspect`, no `limit`, no `v`.
        std::fs::write(
            path_for(&cfg),
            br#"{"news.newsdemon.com":{"connections":6,"granted":6,"gbps":0.24,
                 "checked":1754000000,"source":"auto"}}"#,
        )
        .unwrap();
        let before = load(&cfg);
        assert!(!before["news.newsdemon.com"].suspect, "v0 entry applies");
        assert_eq!(before["news.newsdemon.com"].v, 0);

        let moved = reopen_low_knees(&cfg, |_| Some(24));
        assert_eq!(moved, vec![("news.newsdemon.com".into(), 6, 24)]);
        let after = load(&cfg);
        let t = &after["news.newsdemon.com"];
        assert!(t.suspect, "a reopened knee must stop capping jobs");
        assert_eq!(t.checked, 0, "and must be eligible for an immediate probe");
        assert_eq!(t.limit, 24, "judged against the ceiling now in force");
        assert_eq!(t.v, SCHEMA);
        // The knee itself survives, so the re-probe has something to
        // corroborate against - deleting it would throw that away.
        assert_eq!(t.connections, 6);

        // Idempotent: the same ceiling must not reopen it a second time
        // (a settings save, or every daemon restart, would otherwise
        // re-arm a knee the probe loop had just cleared).
        assert!(reopen_low_knees(&cfg, |_| Some(24)).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Knees the user's ceiling has NOT outgrown are left alone: a knee
    /// at or near the ceiling is the tuner agreeing with the user, and a
    /// host that isn't a configured server is none of this code's
    /// business.
    #[test]
    fn reopen_leaves_settled_knees_alone() {
        let dir = std::env::temp_dir().join(format!("nzbfast-reopen2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let mk = |c: usize, limit: usize| Tuned {
            connections: c,
            granted: c,
            gbps: 1.0,
            checked: 9,
            source: "auto".into(),
            suspect: false,
            limit,
            v: SCHEMA,
        };
        record(&cfg, "near.example.com", mk(20, 24)); // 20 of 24: agrees
        record(&cfg, "low.example.com", mk(6, 24)); // already judged at 24
        record(&cfg, "gone.example.com", mk(2, 24)); // no longer configured
        let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(24));
        assert!(moved.is_empty(), "nothing should have moved: {moved:?}");
        let m = load(&cfg);
        assert!(m.values().all(|t| !t.suspect));
        assert_eq!(m["gone.example.com"].checked, 9);

        // But raise the ceiling past the one they were judged at and the
        // low knee - and only the low knee - reopens: 20 of 26 is still
        // the tuner agreeing with the user, 6 of 26 is not.
        let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(26));
        assert_eq!(moved, vec![("low.example.com".into(), 6, 26)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

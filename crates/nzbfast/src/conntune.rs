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

/// Merge one host's probe result in and persist. The daemon's probe loop
/// and a manual ladder run both live in THIS process, so serialize the whole
/// read-modify-write: without the lock, two concurrent records each load the
/// old map and the second write drops the first host's update - and both
/// used the same `.conntune.<pid>.tmp` path, tearing the file. The lock
/// removes the lost update; write_atomic (process-wide temp counter) removes
/// the torn write.
pub fn record(config: &Path, host: &str, t: Tuned) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    map.insert(host.to_string(), t);
    let path = path_for(config);
    if let Ok(bytes) = serde_json::to_vec_pretty(&map) {
        let _ = crate::persist::write_atomic(&path, &bytes);
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
}

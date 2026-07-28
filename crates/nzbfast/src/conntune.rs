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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Re-probe a provider after this long (knees move with provider policy).
pub const STALE_SECS: u64 = 7 * 86_400;

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
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
            Tuned { connections: 12, granted: 12, gbps: 4.9, checked: 1, source: "auto".into() },
        );
        record(
            &cfg,
            "fill.example.com",
            Tuned { connections: 4, granted: 4, gbps: 0.8, checked: 2, source: "manual".into() },
        );
        let m = load(&cfg);
        assert_eq!(m.len(), 2);
        assert_eq!(m["news.example.com"].connections, 12);
        assert_eq!(m["fill.example.com"].source, "manual");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

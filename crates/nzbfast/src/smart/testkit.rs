//! Helpers shared by both of `smart`'s test children. They live here
//! rather than in either one because the filing cases and the rename
//! cases both build scratch trees and both hold emitted names to the
//! portability rules - and a module cannot borrow a sibling's fn.

use super::*;

pub(super) fn scratch(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("nzbfast-smart-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A single emitted path component, held to the rules a Windows box
/// or an SMB share applies - which is every finished tree's fate, so
/// the host that wrote the name is beside the point.
pub(super) fn assert_portable(name: &str) {
    assert!(!name.is_empty(), "empty component");
    assert!(!name.starts_with('.'), "hidden: {name:?}");
    assert!(
        !name.ends_with('.') && !name.ends_with(' '),
        "Windows truncates: {name:?}"
    );
    assert!(!name.starts_with(' '), "leading space: {name:?}");
    assert!(!name.contains(':'), "drive/ADS meaning: {name:?}");
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    assert!(
        !matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "LPT1"
        ),
        "reserved device: {name:?}"
    );
}

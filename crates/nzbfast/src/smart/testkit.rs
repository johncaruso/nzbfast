//! Helpers shared by both of `smart`'s test children. They live here
//! rather than in either one because the filing cases and the rename
//! cases both build scratch trees and both hold emitted names to the
//! portability rules - and a module cannot borrow a sibling's fn.

use super::*;

// The integration suites' scratch guard, included as source so both
// halves of the tree hold the SAME type (a `tests/` module cannot be
// imported by the lib's unit tests any other way). TODO 149: scratch()
// used to remove only the PREVIOUS run's dir and leak its own, which is
// what gave the §142 oversized fixture a run-long blast radius on NTFS.
#[path = "../../tests/scratch/mod.rs"]
mod scratch_guard;
pub(super) use scratch_guard::ScratchDir;

pub(super) fn scratch(tag: &str) -> ScratchDir {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("nzbfast-smart-{}-{tag}-{n}", std::process::id()));
    ScratchDir::attach(&d)
}

/// The §149 contract itself: a passing test's tree is gone when the
/// guard drops.
#[test]
fn scratch_removes_its_tree_on_drop() {
    let d = scratch("dropclean");
    let kept = d.to_path_buf();
    std::fs::write(d.join("f"), b"x").unwrap();
    drop(d);
    assert!(!kept.exists(), "scratch tree must be removed on drop");
}

/// The other half of the contract: a FAILING test keeps its tree, so
/// the evidence of the failure survives for whoever is debugging it.
#[test]
fn scratch_keeps_its_tree_when_the_test_panics() {
    let kept = std::sync::Arc::new(std::sync::Mutex::new(None::<PathBuf>));
    let seen = kept.clone();
    let r = std::panic::catch_unwind(move || {
        let d = scratch("panickeep");
        *seen.lock().unwrap() = Some(d.to_path_buf());
        std::fs::write(d.join("evidence"), b"x").unwrap();
        panic!("the failing test");
    });
    assert!(r.is_err(), "the closure must have panicked");
    let path = kept.lock().unwrap().take().unwrap();
    assert!(
        path.join("evidence").exists(),
        "a panicking test's tree must survive its guard"
    );
    let _ = std::fs::remove_dir_all(&path);
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

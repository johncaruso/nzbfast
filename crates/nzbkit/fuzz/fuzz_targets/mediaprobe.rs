#![no_main]
//! Fuzz the container probe behind the preview-and-verify panel.
//!
//! These bytes are the least trusted in the tree: the probe runs over a
//! file that is still arriving off Usenet, before PAR2 has verified
//! anything, and it walks attacker-declared lengths in three container
//! formats. Two properties are asserted beyond "does not crash":
//!
//! 1. **Determinism.** The same bytes must probe to the same answer.
//!    That is what makes a wall-clock budget inadmissible in the parser
//!    (an element budget bounds the same thing without it), and it is
//!    what lets a polling panel trust that a field stopped changing
//!    because the file settled, not because a deadline fired.
//! 2. **Bounded output.** A track list, chapter list or warning list
//!    that grows with a declared length rather than with real elements
//!    is the shape of an allocation attack.
//!
//! Run with the rss limit - it is what actually enforces the
//! "never allocate from an untrusted length" rule:
//!
//!     cargo +nightly fuzz run mediaprobe -- -max_total_time=300 -rss_limit_mb=512
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hint = || nzbkit::mediaprobe::ProbeHint {
        filename: None,
        known_size: Some(data.len() as u64),
    };
    let first = nzbkit::mediaprobe::probe(&mut std::io::Cursor::new(data), hint());
    let second = nzbkit::mediaprobe::probe(&mut std::io::Cursor::new(data), hint());
    match (first, second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "probe disagreed with itself");
            assert!(a.video.len() + a.audio.len() + a.subtitles.len() <= 64);
            assert!(a.chapters.len() <= 512);
            // Warnings are deduplicated by message, so a file cannot
            // grow the list by repeating the same broken element.
            assert!(a.warnings.len() <= 128, "warning list is unbounded");
        }
        (Err(_), Err(_)) => {}
        _ => panic!("probe was non-deterministic"),
    }
    // The same bytes with no size hint, which is how a finished file on
    // disk arrives: the walk then resolves the end by seeking.
    let _ = nzbkit::mediaprobe::probe(
        &mut std::io::Cursor::new(data),
        nzbkit::mediaprobe::ProbeHint {
            filename: Some("fuzz.mkv".to_string()),
            known_size: None,
        },
    );
});

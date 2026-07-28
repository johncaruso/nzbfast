#![no_main]
//! Fuzz the streaming recovery scanners on arbitrary bytes.
//!
//! Both entry points here parse ATTACKER-CONTROLLED headers and size their
//! own work from fields inside them: the `{RB}` inline-recovery scanner
//! derives a shard plan (data shards x group count) from a chunk header, and
//! the REV reader derives a slot table from a `.rev` header. Those are the
//! two places a downloaded file gets to choose an allocation, which is
//! exactly what the 64 GiB-from-1.8 MiB REV bomb was.
//!
//! The scanners are also the paths reached AUTOMATICALLY once extraction
//! fails, so anything that panics or hangs here is reachable by downloading
//! a file. We are hunting panics, OOB and non-termination - the budgets
//! passed in are deliberately small so a run that respects them is fast and
//! one that does not shows up as a timeout.
use libfuzzer_sys::fuzz_target;

use rars::recovery::stream::{scan_inline_recovery_chunks, MemorySource};

fuzz_target!(|data: &[u8]| {
    // Cap the corpus: these scanners are linear in the input and the point
    // is malformed structure, not size.
    if data.len() > 1 << 20 {
        return;
    }
    let source = MemorySource(data.to_vec());

    // Inline `{RB}` recovery records: plan arithmetic, chunk framing, the
    // anti-quadratic hash budget, and the window-sliding marker search.
    if let Ok(scan) = scan_inline_recovery_chunks(&source, 1 << 20) {
        // Ranges the scan reports must stay inside the source it scanned;
        // a caller reads parity straight from them.
        for chunk in &scan.chunks {
            assert!(chunk.parity.start <= chunk.parity.end);
            assert!(chunk.parity.end <= data.len() as u64);
        }
        // One state table per group, each indexed by data shard. A group with
        // no surviving record has an empty table, which callers must skip
        // rather than index - so empty is the only other legal width.
        if let Some(plan) = scan.plan() {
            for states in &scan.group_states {
                assert!(states.is_empty() || states.len() == plan.data_shards as usize);
            }
            // Every chunk the scan kept must land in a group, and that
            // group's table must be usable: a chunk pointing at an empty
            // group would be parity nothing can be checked against.
            let by_group = scan.chunks_by_group().expect("grouping a scan it produced");
            assert_eq!(by_group.len(), scan.group_states.len());
            assert_eq!(
                by_group.iter().map(Vec::len).sum::<usize>(),
                scan.chunks.len()
            );
            for (slots, states) in by_group.iter().zip(&scan.group_states) {
                assert!(slots.is_empty() || !states.is_empty());
            }
        }
    }

    // REV headers: the slot table is the declared-count allocation.
    if let Ok(volume) = rars::rar50::read_rev5_meta(&source) {
        assert!(volume.payload.start <= volume.payload.end);
        assert!(volume.payload.end <= data.len() as u64);
        assert_eq!(
            volume.meta.data_volumes.len(),
            volume.meta.data_count as usize
        );
        let _ = rars::rar50::verify_rev5_payload(&source, &volume);
        let _ = volume.row();
    }
});

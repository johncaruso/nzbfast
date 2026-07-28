//! BLAKE2sp-256 as used by RAR 5 file-hash records.
//!
//! Built from eight independent BLAKE2s leaf states (tree mode, per RFC
//! 7693) over `blake2s_simd`. The eight leaves receive the input round-robin
//! in 64-byte blocks and are completely independent, so large updates gather
//! each leaf's blocks and hash the leaves on a small thread team —
//! `blake2s_simd` has no NEON many-way kernel, which otherwise leaves the
//! whole hash on one scalar lane on aarch64.

const OUT_BYTES: usize = 32;
const BLOCK_BYTES: usize = 64;
const PARALLELISM: usize = 8;
const GROUP_BYTES: usize = BLOCK_BYTES * PARALLELISM;
// Below this many buffered bytes, feeding leaves serially beats spawning.
const PARALLEL_MIN_BYTES: usize = 512 * 1024;
const HASH_THREADS: usize = 4;

fn leaf_params(index: usize) -> blake2s_simd::Params {
    let mut params = blake2s_simd::Params::new();
    params
        .hash_length(OUT_BYTES)
        .fanout(PARALLELISM as u8)
        .max_depth(2)
        .max_leaf_length(0)
        .node_offset(index as u64)
        .node_depth(0)
        .inner_hash_length(OUT_BYTES);
    if index == PARALLELISM - 1 {
        params.last_node(true);
    }
    params
}

fn root_params() -> blake2s_simd::Params {
    let mut params = blake2s_simd::Params::new();
    params
        .hash_length(OUT_BYTES)
        .fanout(PARALLELISM as u8)
        .max_depth(2)
        .max_leaf_length(0)
        .node_offset(0)
        .node_depth(1)
        .inner_hash_length(OUT_BYTES)
        .last_node(true);
    params
}

#[derive(Clone)]
pub(crate) struct Hasher {
    leaves: Vec<blake2s_simd::State>,
    /// Input buffered until a parallel batch is worthwhile. Always drained
    /// in whole 512-byte groups except at finalization.
    buffer: Vec<u8>,
}

impl Hasher {
    pub(crate) fn new() -> Self {
        Self {
            leaves: (0..PARALLELISM)
                .map(|index| leaf_params(index).to_state())
                .collect(),
            buffer: Vec::new(),
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        // Steady state (whole-group-aligned batches from the extract
        // pipelines, empty buffer): hash straight from the caller's slice —
        // no copy of the stream.
        if self.buffer.is_empty() && input.len() >= PARALLEL_MIN_BYTES {
            let whole = input.len() / GROUP_BYTES * GROUP_BYTES;
            hash_groups_parallel(&mut self.leaves, &input[..whole]);
            self.buffer.extend_from_slice(&input[whole..]);
            return;
        }
        self.buffer.extend_from_slice(input);
        if self.buffer.len() >= PARALLEL_MIN_BYTES {
            let whole = self.buffer.len() / GROUP_BYTES * GROUP_BYTES;
            let (groups, remainder) = self.buffer.split_at(whole);
            hash_groups_parallel(&mut self.leaves, groups);
            self.buffer = remainder.to_vec();
        }
    }

    pub(crate) fn finalize(mut self) -> [u8; OUT_BYTES] {
        // Drain the remainder serially: whole groups first, then the
        // partial group's per-leaf slots.
        let buffer = std::mem::take(&mut self.buffer);
        let mut offset = 0;
        while offset < buffer.len() {
            let leaf = (offset / BLOCK_BYTES) % PARALLELISM;
            let end = (offset + BLOCK_BYTES).min(buffer.len());
            self.leaves[leaf].update(&buffer[offset..end]);
            offset = end;
        }

        let mut root = root_params().to_state();
        for leaf in &mut self.leaves {
            root.update(leaf.finalize().as_bytes());
        }
        let hash = root.finalize();
        let mut out = [0u8; OUT_BYTES];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

/// Hash whole 512-byte groups into the leaves, splitting the leaf set
/// across a small scoped thread team. Each worker gathers its leaves'
/// 64-byte blocks into a contiguous scratch buffer and hashes it in one
/// update call.
fn hash_groups_parallel(leaves: &mut [blake2s_simd::State], groups: &[u8]) {
    debug_assert_eq!(groups.len() % GROUP_BYTES, 0);
    let group_count = groups.len() / GROUP_BYTES;
    if groups.is_empty() {
        return;
    }
    let leaves_per_thread = PARALLELISM / HASH_THREADS;
    let mut chunks: Vec<&mut [blake2s_simd::State]> = leaves.chunks_mut(leaves_per_thread).collect();
    std::thread::scope(|scope| {
        for (thread_index, thread_leaves) in chunks.iter_mut().enumerate() {
            let first_leaf = thread_index * leaves_per_thread;
            scope.spawn(move || {
                let mut scratch = vec![0u8; group_count * BLOCK_BYTES];
                for (offset, leaf) in thread_leaves.iter_mut().enumerate() {
                    let leaf_index = first_leaf + offset;
                    let slot = leaf_index * BLOCK_BYTES;
                    for group in 0..group_count {
                        let src = group * GROUP_BYTES + slot;
                        scratch[group * BLOCK_BYTES..(group + 1) * BLOCK_BYTES]
                            .copy_from_slice(&groups[src..src + BLOCK_BYTES]);
                    }
                    leaf.update(&scratch);
                }
            });
        }
    });
}

pub(crate) fn hash(input: &[u8]) -> [u8; OUT_BYTES] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{hash, Hasher};

    #[test]
    fn matches_public_blake2sp_vectors() {
        assert_eq!(
            hex(&hash(b"")),
            "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
        );
        assert_eq!(
            hex(&hash(b"abc")),
            "70f75b58f1fecab821db43c88ad84edde5a52600616cd22517b7bb14d440a7d5"
        );
    }

    #[test]
    fn streaming_hasher_matches_one_shot_hash() {
        let input: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
        let mut hasher = Hasher::new();
        for chunk in input.chunks(37) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), hash(&input));
    }

    #[test]
    fn parallel_batches_match_crate_blake2sp() {
        // Large enough to cross the parallel threshold multiple times, with
        // a ragged tail; reference is blake2s_simd's own blake2sp.
        let input: Vec<u8> = (0..3 * 1024 * 1024 + 517)
            .map(|i| (i % 253) as u8)
            .collect();
        let mut hasher = Hasher::new();
        for chunk in input.chunks(96 * 1024 + 13) {
            hasher.update(chunk);
        }
        let parallel = hasher.finalize();

        let reference = blake2s_simd::blake2sp::Params::new()
            .hash_length(32)
            .to_state()
            .update(&input)
            .finalize();
        assert_eq!(parallel.as_slice(), reference.as_bytes());
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

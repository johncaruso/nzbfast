//! In-process PAR2 Reed-Solomon repair over GF(2^16) - M2's "open
//! research" item, now real. `par2.rs` stays parsing/verification-only;
//! this module reconstructs missing or corrupt input blocks from
//! recovery slices and patches the damaged files IN PLACE (no whole-file
//! rewrite, no external par2cmdline).
//!
//! ## The math (PAR2 spec, recovery-slice section)
//!
//! Input slice `i` (files in Main-packet order, slices in file order) is
//! assigned the constant g_i = 2^{k_i}, where k_i is the i-th natural
//! number coprime to 65535 (not divisible by 3, 5, 17 or 257; 32768
//! exist, which is the spec's input-slice cap). A recovery slice with
//! exponent `e` holds, over GF(2^16) with slices read as little-endian
//! u16 words (odd tail byte = low half of a zero-padded final word):
//!
//! ```text
//!     R_e = Σ_i g_i^e · D_i
//! ```
//!
//! With missing-slice set M and present set P this rearranges to
//!
//! ```text
//!     Σ_{j∈M} g_j^e · D_j  =  R_e ⊕ Σ_{i∈P} g_i^e · D_i  =:  S_e
//! ```
//!
//! - |M| unknowns solved from |M| recovery slices by inverting the
//! matrix A[r][c] = g_{j_c}^{e_r} (every entry a power of two:
//! 2^{k_{j_c}·e_r mod 65535}). [`Reconstructor`] streams the present
//! slices through the syndrome accumulation so the whole data set is
//! never in memory: peak RAM is |M| syndromes + |M| recovery slices +
//! one small batch of input blocks.
//!
//! Correctness is self-proving: after patching, every touched file must
//! match its FileDesc whole-file MD5, or [`repair_dir`] fails and the
//! caller falls back to par2cmdline.
//!
//! Obfuscated and shifted sets are covered by the extra-file adoption
//! scan (par2cmdline's "sliding scan", natively): when a file fails
//! identification outright - missing, renamed, or byte-shifted - the
//! IFSC block checksums (rolling CRC32 prefilter, MD5 confirm) are slid
//! over every candidate file in the directory to locate block content
//! living under other names or offsets, and those blocks are adopted as
//! data sources. The scan reads whole files, so it is gated: it only
//! runs when some file failed identification or the damage exceeds the
//! recovery slices on disk - never on the everyday a-few-blocks-bad
//! repair, whose verified files already pin every block in place. Two
//! extensions go past par2cmdline: recovery volumes hidden under junk
//! names are found by packet-magic sniffing (par2cmdline only loads
//! packets from files with ".par2" in the name), and when damage still
//! exceeds recovery after the extras scan, identified-but-damaged
//! targets are scanned too (mid-file insertions leave a half-verified
//! file whose remaining content is byte-shifted inside itself).

use crate::gf16::{self, MulTable};
use crate::par2::{self, BlockCheck, Par2File};
use md5::{Digest, Md5};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// PAR2 hard limit: number of naturals below 65535 coprime to it.
const MAX_INPUT_SLICES: usize = 32768;
/// Present-slice bytes buffered between threaded syndrome flushes.
const BATCH_BYTES: usize = 64 << 20;

#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("no valid PAR2 Main packet found in the .par2 files")]
    NoMainPacket,
    #[error("recovery set malformed: {0}")]
    Malformed(String),
    #[error("recovery matrix is singular for this slice combination")]
    SingularMatrix,
    #[error("repaired file failed MD5 verification: {0}")]
    VerifyFailed(String),
}

/// The log₂ of the RS constant for each of the first `n` input slices:
/// the n smallest naturals coprime to 65535. (Sequence of constants:
/// 2, 4, 16, 128, 256, 2048, …)
pub fn input_base_logs(n: usize) -> Result<Vec<u32>, RepairError> {
    if n > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{n} input slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}"
        )));
    }
    let mut logs = Vec::with_capacity(n);
    let mut k = 0u32;
    while logs.len() < n {
        k += 1;
        if k % 3 != 0 && k % 5 != 0 && k % 17 != 0 && k % 257 != 0 {
            logs.push(k);
        }
    }
    Ok(logs)
}

/// Locate every valid recovery slice for `set_id` in a buffer of PAR2
/// packets: (exponent, offset of slice data, data length). Packets
/// failing their MD5 are already dropped by the scanner; duplicates are
/// NOT deduped here - callers dedupe by exponent across files.
pub fn recovery_slice_locators(bytes: &[u8], set_id: &[u8; 16]) -> Vec<(u32, usize, usize)> {
    let mut out = Vec::new();
    par2::scan_packets(bytes, |pkt| {
        if &pkt.ptype == par2::TYPE_RECVSLIC && &pkt.set_id == set_id && pkt.body.len() >= 4 {
            let e = u32::from_le_bytes(pkt.body[0..4].try_into().unwrap());
            out.push((e, pkt.body_offset + 4, pkt.body.len() - 4));
        }
    });
    out
}

/// Streaming Reed-Solomon reconstruction. Build with the missing input
/// slice indices and exactly as many recovery slices, [`feed`] every
/// present input slice exactly once (any order, short tail data fine),
/// then [`finish`] returns the reconstructed slices in `missing` order.
///
/// [`feed`]: Reconstructor::feed
/// [`finish`]: Reconstructor::finish
pub struct Reconstructor {
    block_size: usize,
    /// k_i per global input index (shared with [`Feeder`] handles).
    base_logs: std::sync::Arc<Vec<u32>>,
    missing: Vec<usize>,
    /// A⁻¹, row-major: missing[c] = Σ_r inverse[c][r] · S_r.
    inverse: Vec<Vec<u16>>,
    /// Batches travel to a worker thread that owns the syndrome rows, so
    /// the caller's disk reads overlap the GF math (bounded channel:
    /// one batch queued while one folds).
    tx: Option<std::sync::mpsc::SyncSender<FeedBatch>>,
    worker: Option<std::thread::JoinHandle<Vec<Vec<u16>>>>,
    /// Pending present slices, packed into the next batch's arena.
    batch: FeedBatch,
    batch_capacity: usize,
}

/// One thread's share of a multi-accumulate: `dsts[j] ^= Σ_i
/// coeff(j, i) · srcs[i]` over GF(2^16), column-tiled for cache reuse.
///
/// The naive loop (rows outer, sources inner) streams every source
/// past every row: with a 32 MiB batch and ~100 syndrome rows that is
/// ~100x the batch in RAM reads, which is exactly where the repair leg
/// falls behind on parts with laptop-class caches (an L3 smaller than
/// the batch re-reads it from memory each sweep; Apple-class bandwidth
/// hides the same traffic). Tiling columns keeps this thread's slice
/// of every destination row L2-resident across one pass over the
/// sources, so each source tile is read once per thread and the
/// destination tiles never leave cache.
///
/// Sources may be shorter than the rows (zero-padded tails) and the
/// split tables are built once per (row, source-group) - `group` caps
/// their memory, degrading toward the untiled loop only when a single
/// group's tables would not fit the budget.
fn fold_chunk_tiled(
    dsts: &mut [&mut [u16]],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    row_base: usize,
    tile_words: usize,
    table_budget: usize,
) {
    if dsts.is_empty() || srcs.is_empty() {
        return;
    }
    if gf16::multi_fold_width() > 0 {
        return fold_chunk_multi(dsts, srcs, coeff, row_base, tile_words);
    }
    let words = dsts[0].len();
    debug_assert!(dsts.iter().all(|d| d.len() == words));
    let per_src = std::mem::size_of::<MulTable>() * dsts.len();
    let group = (table_budget / per_src.max(1)).clamp(1, srcs.len());
    // One column tile is walked across EVERY row this thread owns before
    // moving on, so the resident set is tile x rows, not tile. A fixed
    // tile therefore only stays L2-resident while the row count is small;
    // scale it down as rows grow so the intent holds either way.
    // The caller's tile is the ceiling, so the floor must never exceed
    // it (callers - and the tests - may ask for a deliberately tiny
    // tile). A zero tile would not advance the loop below.
    let ceiling = tile_words.max(1);
    let tile_words = (L2_TARGET_WORDS / dsts.len()).clamp(MIN_TILE_WORDS.min(ceiling), ceiling);
    let mut tables: Vec<MulTable> = Vec::with_capacity(group * dsts.len());
    // Coefficients hoisted out of the tile loop: the zero test used to
    // recompute one per (tile, source, row), and for the syndrome fold
    // that is a u64 multiply plus a `% 65535` division.
    let mut coeffs: Vec<u16> = Vec::with_capacity(group * dsts.len());
    let mut g0 = 0usize;
    while g0 < srcs.len() {
        let g1 = (g0 + group).min(srcs.len());
        tables.clear();
        coeffs.clear();
        for j in 0..dsts.len() {
            for i in g0..g1 {
                let c = coeff(row_base + j, i);
                coeffs.push(c);
                tables.push(MulTable::new(c));
            }
        }
        let mut w0 = 0usize;
        while w0 < words {
            let w1 = (w0 + tile_words).min(words);
            for (gi, src) in srcs[g0..g1].iter().enumerate() {
                let sb = (w0 * 2).min(src.len());
                let eb = (w1 * 2).min(src.len());
                if sb == eb {
                    continue;
                }
                for (j, d) in dsts.iter_mut().enumerate() {
                    let t = j * (g1 - g0) + gi;
                    if coeffs[t] == 0 {
                        continue;
                    }
                    tables[t].xor_mul_into(&mut d[w0..w1], &src[sb..eb]);
                }
            }
            w0 = w1;
        }
        g0 = g1;
    }
}

/// The multi-source twin of [`fold_chunk_tiled`], used when the
/// platform has a fused kernel ([`gf16::multi_fold_width`] > 0): per
/// destination tile, per row, sources are folded in fused groups - each
/// dst chunk is loaded/stored once per GROUP instead of once per source,
/// and no split tables are built at all (the old path built one 1.2 KB
/// table per (row, source): 23M of them on a heavy repair, all fighting
/// the destination tiles for L2). Sources that don't cover a full tile
/// (zero-padded tails) and sub-chunk tile remainders take the scalar
/// single-source path; both are rare edges of a fold that is otherwise
/// whole blocks.
fn fold_chunk_multi(
    dsts: &mut [&mut [u16]],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    row_base: usize,
    tile_words: usize,
) {
    let width = gf16::multi_fold_width().min(16);
    let words = dsts[0].len();
    debug_assert!(dsts.iter().all(|d| d.len() == words));
    // Same residency math as the table path (a tile is walked across
    // every row this thread owns), with one extra constraint: a multiple
    // of 16 words, so the fused kernel covers whole tiles and the
    // per-source remainder path stays out of the steady state.
    let ceiling = tile_words.max(16);
    let tile_words = ((L2_TARGET_WORDS / dsts.len())
        .clamp(MIN_TILE_WORDS.min(ceiling), ceiling))
        & !15;
    let tile_words = tile_words.max(16);
    // Coefficients hoisted per (row, group) sweep, exactly as the table
    // path hoists them. Zero coefficients ride along (a pmull by zero
    // contributes nothing and they are far too rare to branch on).
    let mut coeffs: Vec<u16> = Vec::with_capacity(dsts.len() * width);
    let mut g0 = 0usize;
    while g0 < srcs.len() {
        let g1 = (g0 + width).min(srcs.len());
        coeffs.clear();
        for j in 0..dsts.len() {
            for i in g0..g1 {
                coeffs.push(coeff(row_base + j, i));
            }
        }
        let mut w0 = 0usize;
        while w0 < words {
            let w1 = (w0 + tile_words).min(words);
            let tile_bytes = (w1 - w0) * 2;
            // Window this group's sources to the tile. Full-coverage
            // sources take the fused kernel; short ones (zero-padded
            // tails) are folded singly afterwards.
            let mut full: [&[u8]; 16] = [&[]; 16];
            let mut full_idx: [usize; 16] = [0; 16];
            let mut n = 0usize;
            let mut partial: [(usize, &[u8]); 16] = [(0, &[]); 16];
            let mut np = 0usize;
            for (gi, src) in srcs[g0..g1].iter().enumerate() {
                let sb = (w0 * 2).min(src.len());
                let eb = (w1 * 2).min(src.len());
                if sb == eb {
                    continue;
                }
                if eb - sb == tile_bytes {
                    full[n] = &src[sb..eb];
                    full_idx[n] = gi;
                    n += 1;
                } else {
                    partial[np] = (gi, &src[sb..eb]);
                    np += 1;
                }
            }
            for (j, d) in dsts.iter_mut().enumerate() {
                let dtile = &mut d[w0..w1];
                if n > 0 {
                    let mut gc: [u16; 16] = [0; 16];
                    for (k, &gi) in full_idx[..n].iter().enumerate() {
                        gc[k] = coeffs[j * (g1 - g0) + gi];
                    }
                    let done = gf16::xor_mul_multi_into(dtile, &full[..n], &gc[..n]);
                    if done < dtile.len() {
                        // Only a non-32-byte-aligned FINAL tile lands here.
                        for (s, c) in full[..n].iter().zip(&gc[..n]) {
                            if *c != 0 {
                                MulTable::new(*c)
                                    .xor_mul_into(&mut dtile[done..], &s[done * 2..]);
                            }
                        }
                    }
                }
                for &(gi, s) in &partial[..np] {
                    let c = coeffs[j * (g1 - g0) + gi];
                    if c != 0 {
                        MulTable::new(c).xor_mul_into(&mut dtile[..s.len().div_ceil(2)], s);
                    }
                }
            }
            w0 = w1;
        }
        g0 = g1;
    }
}

/// Destination tile size for [`fold_chunk_tiled`]: the ceiling, used
/// when a thread owns few enough rows that 64 KiB each still fits.
const TILE_WORDS: usize = 32 << 10;
/// Destination-cache target a thread aims to stay inside across all the
/// rows it owns. 512 KiB is a conservative L2 share (leaving room for
/// the source tile and the split tables beside it).
const L2_TARGET_WORDS: usize = (512 << 10) / 2;
/// Never tile finer than this - past here the per-call overheads and the
/// source re-reads cost more than the residency buys.
const MIN_TILE_WORDS: usize = 2 << 10;
/// Per-thread split-table memory cap for [`fold_chunk_tiled`].
const TABLE_BUDGET: usize = 2 << 20;
/// Do not split a column range finer than this: below it the thread and
/// table-build overheads dominate the fold itself.
const MIN_COL_WORDS: usize = 2 << 10;

/// Run `dsts[j] ^= Σ_i coeff(j, i) · srcs[i]` across the whole machine.
///
/// Splitting by rows alone caps parallelism at the ROW COUNT, which for
/// both callers is the number of missing blocks. Light damage is the
/// common case (a few failed articles), so that repeatedly left a
/// many-core machine folding on one or two threads: measured, fold
/// throughput scaled linearly with missing-block count and only
/// saturated once it reached the core count.
///
/// Rows stay the outer split (they need no sub-slicing and keep whole
/// rows on one thread), and whatever parallelism they leave unused goes
/// to the column range: the grid is rows x columns. Column slices of a
/// row are disjoint, so each thread still owns its destination bytes
/// outright and nothing is shared but the read-only sources.
/// Bench hook: the fold in isolation, so a harness can time the GF work
/// without the surrounding allocation and batching. Not part of the
/// supported API.
#[doc(hidden)]
pub fn bench_fold(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
) {
    fold_parallel(dsts, srcs, coeff);
}

fn fold_parallel(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
) {
    let rows = dsts.len();
    if rows == 0 || srcs.is_empty() {
        return;
    }
    let words = dsts[0].len();
    debug_assert!(dsts.iter().all(|d| d.len() == words));
    if words == 0 {
        return;
    }
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get()).max(1);
    let row_threads = cores.min(rows);
    let row_chunk = rows.div_ceil(row_threads);
    // Columns split past the leftover-core count on purpose: units are
    // WORK-STOLEN, not statically owned. A static grid handed each
    // thread one fixed cell, so on hybrid parts every fold waited for
    // the slowest E-core to finish a P-core-sized share (measured: the
    // straggler set the wall on both the i7 and the M3 at high m).
    // Oversplitting columns a few times per thread gives fast cores
    // more units and the tail shrinks to one small unit's length.
    let col_splits = if rows >= cores {
        (8usize).min(words.div_ceil(MIN_COL_WORDS).max(1))
    } else {
        // Few rows: columns are the only parallelism, so they carry
        // both the fan-out AND the oversplit.
        (cores / row_threads * 4)
            .max(1)
            .min(words.div_ceil(MIN_COL_WORDS).max(1))
    };
    let col_chunk = words.div_ceil(col_splits);

    // A view of every row restricted to each column range, built by
    // repeated split_at_mut so the borrows are provably disjoint.
    let mut cols: Vec<Vec<&mut [u16]>> =
        (0..col_splits).map(|_| Vec::with_capacity(rows)).collect();
    for row in dsts.iter_mut() {
        let mut rest: &mut [u16] = row.as_mut_slice();
        for col in cols.iter_mut() {
            let take = rest.len().min(col_chunk);
            let (head, tail) = rest.split_at_mut(take);
            col.push(head);
            rest = tail;
        }
    }

    // The unit grid: (row range x column range) cells, each owning its
    // destination region outright, pulled off one atomic counter.
    struct Unit<'a> {
        rows: Vec<&'a mut [u16]>,
        row_base: usize,
        col_off: usize,
    }
    let mut units: Vec<Unit> = Vec::with_capacity(col_splits * row_threads);
    for (ci, col) in cols.into_iter().enumerate() {
        let mut row_base = 0usize;
        let mut col = col;
        while !col.is_empty() {
            let take = col.len().min(row_chunk);
            let rest = col.split_off(take);
            units.push(Unit {
                rows: col,
                row_base,
                col_off: ci * col_chunk,
            });
            row_base += take;
            col = rest;
        }
    }
    let units = std::sync::Mutex::new(units);
    let workers = cores.min(row_threads * col_splits);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let unit = units.lock().unwrap().pop();
                    let Some(unit) = unit else { return };
                    // Each unit sees only its own bytes of every source;
                    // a source that ends before this range contributes
                    // nothing (PAR2 tail slices are zero-padded).
                    let sub: Vec<&[u8]> = srcs
                        .iter()
                        .map(|src| {
                            let b0 = (unit.col_off * 2).min(src.len());
                            let b1 = ((unit.col_off + col_chunk) * 2).min(src.len());
                            &src[b0..b1]
                        })
                        .collect();
                    let mut rows = unit.rows;
                    fold_chunk_tiled(
                        &mut rows,
                        &sub,
                        coeff,
                        unit.row_base,
                        TILE_WORDS,
                        TABLE_BUDGET,
                    );
                }
            });
        }
    });
}

/// One feeder's assembled batch: slices PACKED into a single arena
/// instead of one heap allocation each. The per-slice `Vec<u8>` design
/// allocated and freed tens of thousands of block-sized buffers across
/// threads per heavy repair; on Windows every 64 KiB+ allocation is a
/// direct VirtualAlloc, and the cross-thread VirtualFree storm (TLB
/// shootdowns interrupt every core) collapsed the fold from 105 GB/s to
/// 13 GB/s a few seconds into the run (measured, i7-1280P, m=1500). An
/// arena per batch is ~two allocations per 32 MiB instead of ~512.
struct FeedBatch {
    arena: Vec<u8>,
    /// (base log k, arena offset, len) per slice.
    slices: Vec<(u32, usize, usize)>,
}

impl FeedBatch {
    fn with_capacity(bytes: usize) -> FeedBatch {
        FeedBatch {
            arena: Vec::with_capacity(bytes),
            slices: Vec::new(),
        }
    }

    fn push(&mut self, k: u32, data: &[u8]) {
        let off = self.arena.len();
        self.arena.extend_from_slice(data);
        self.slices.push((k, off, data.len()));
    }
}

/// Fold queued batches of present slices into every syndrome row - one
/// row sweep for the whole set, however many feeder batches it arrived
/// as.
fn fold_batches(exponents: &[u32], syndromes: &mut [Vec<u16>], batches: &[FeedBatch]) {
    if syndromes.is_empty() {
        return;
    }
    let mut srcs: Vec<&[u8]> = Vec::new();
    let mut logs: Vec<u32> = Vec::new();
    for b in batches {
        for &(k, off, len) in &b.slices {
            srcs.push(&b.arena[off..off + len]);
            logs.push(k);
        }
    }
    if srcs.is_empty() {
        return;
    }
    fold_parallel(syndromes, &srcs, &|j, i| {
        gf16::pow2(logs[i] as u64 * exponents[j] as u64)
    });
}

impl Reconstructor {
    pub fn new(
        block_size: usize,
        n_inputs: usize,
        missing: &[usize],
        recovery: &[(u32, Vec<u8>)],
    ) -> Result<Reconstructor, RepairError> {
        if block_size == 0 || block_size % 2 != 0 {
            return Err(RepairError::Malformed(format!(
                "block size {block_size} not a positive multiple of 2"
            )));
        }
        if recovery.len() != missing.len() {
            return Err(RepairError::Malformed(format!(
                "{} recovery slices for {} missing blocks - caller must pass exactly one per",
                recovery.len(),
                missing.len()
            )));
        }
        // A dense missing x missing GF(2^16) inverse costs ~4*m^2 bytes (the
        // matrix plus its inverse) and O(m^3) single-threaded field ops. The
        // PAR2 spec slice cap (32768) is far too loose a bound for that: a
        // crafted set declaring tens of thousands of missing blocks would pin
        // multiple GB and run for hours (a repair-time DoS). Refuse a matrix
        // larger than a real recovery set ever is; 8192 caps peak matrix memory
        // near 256 MB. An extreme legitimate repair can still use par2cmdline.
        const MAX_REPAIR_DIM: usize = 8192;
        if missing.len() > MAX_REPAIR_DIM {
            return Err(RepairError::Malformed(format!(
                "{} missing blocks exceeds the repair-matrix cap ({MAX_REPAIR_DIM})",
                missing.len()
            )));
        }
        let base_logs = input_base_logs(n_inputs)?;
        if let Some(&j) = missing.iter().find(|&&j| j >= n_inputs) {
            return Err(RepairError::Malformed(format!(
                "missing index {j} out of range ({n_inputs} inputs)"
            )));
        }
        let t_inv = std::time::Instant::now();
        // Consecutive exponents (both repair paths pick the SMALLEST
        // available, so this is the norm - gaps mean recovery packets
        // were themselves lost) make A a Vandermonde in the bases times
        // a diagonal, whose explicit inverse costs O(m²) instead of
        // Gauss-Jordan's O(m³).
        let consecutive =
            !recovery.is_empty() && recovery.windows(2).all(|w| w[1].0 == w[0].0 + 1);
        let structured = if consecutive {
            let ks: Vec<u32> = missing.iter().map(|&j| base_logs[j]).collect();
            invert_vandermonde(&ks, recovery[0].0)
        } else {
            None
        };
        let (label, inverse) = match structured {
            Some(inv) => ("vandermonde", inv),
            None => {
                // A[r][c] = g_{missing[c]}^{e_r} = 2^{k·e mod 65535}
                let a: Vec<Vec<u16>> = recovery
                    .iter()
                    .map(|&(e, _)| {
                        missing
                            .iter()
                            .map(|&j| gf16::pow2(base_logs[j] as u64 * e as u64))
                            .collect()
                    })
                    .collect();
                ("gauss-jordan", invert(a)?)
            }
        };
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            eprintln!(
                "[repair-timing] matrix invert ({}x{0}, {label}): {:.2?}",
                missing.len(),
                t_inv.elapsed()
            );
        }
        let words = block_size / 2;
        let mut exponents = Vec::with_capacity(recovery.len());
        let mut syndromes = Vec::with_capacity(recovery.len());
        for (e, data) in recovery {
            if data.len() != block_size {
                return Err(RepairError::Malformed(format!(
                    "recovery slice (exponent {e}) is {} bytes, block size is {block_size}",
                    data.len()
                )));
            }
            let mut w = vec![0u16; words];
            for (dw, s) in w.iter_mut().zip(data.chunks_exact(2)) {
                *dw = u16::from_le_bytes([s[0], s[1]]);
            }
            exponents.push(*e);
            syndromes.push(w);
        }
        // Capacity 4 (was 1): with M2c.2's parallel readers each sender
        // carries a BATCH_BYTES/N-sized batch, so a slightly deeper
        // queue keeps disks busy while a batch folds without growing
        // worst-case in-flight memory beyond the old single-feeder cap.
        let (tx, rx) = std::sync::mpsc::sync_channel::<FeedBatch>(8);
        let fold_trace = std::env::var_os("NZBFAST_FOLD_TRACE").is_some();
        let worker = std::thread::spawn(move || {
            let mut syndromes = syndromes;
            let mut waited = std::time::Duration::ZERO;
            let mut folded = std::time::Duration::ZERO;
            let mut calls = 0usize;
            let mut bytes = 0usize;
            loop {
                let t_w = std::time::Instant::now();
                let Ok(first) = rx.recv() else { break };
                waited += t_w.elapsed();
                let mut merged = vec![first];
                // Coalesce whatever the feeders have already queued: the
                // tiled fold walks EVERY syndrome row once per call, so N
                // small batches cost N row sweeps where one merged batch
                // costs one. Parallel feeders split BATCH_BYTES across
                // handles for memory control (M2c.2), which shrank fold
                // units 8x - measured as a repair regression on
                // small-L3 parts.
                //
                // The bound is channel capacity PLUS live senders, not
                // capacity alone: each try_recv that frees a buffered slot
                // immediately unblocks a sender, whose message lands in the
                // buffer and is drained on the next iteration. With
                // sync_channel(4) and up to 8 feeders that is up to 12
                // batches merged, not 5. Harmless at typical block sizes
                // (~48 MB vs the 32 MB BATCH_BYTES design cap), but a feeder
                // batch is one whole block when block_size is large - a set
                // with 16 MB blocks holds ~192 MB in the merged batch. The
                // fold is XOR accumulation, so merging and reordering are
                // exact; this is a memory bound, not a correctness one.
                while let Ok(more) = rx.try_recv() {
                    merged.push(more);
                }
                let t_f = std::time::Instant::now();
                fold_batches(&exponents, &mut syndromes, &merged);
                folded += t_f.elapsed();
                calls += 1;
                let mb: usize = merged.iter().map(|b| b.arena.len()).sum();
                bytes += mb;
                if fold_trace {
                    eprintln!(
                        "[fold-trace] call {calls}: {} srcs, {:.1} MB, {:.2?}",
                        merged.iter().map(|b| b.slices.len()).sum::<usize>(),
                        mb as f64 / 1e6,
                        t_f.elapsed()
                    );
                }
            }
            if fold_trace {
                eprintln!(
                    "[fold-trace] total: {calls} calls, {:.1} MB, fold {:.2?}, recv-wait {:.2?}",
                    bytes as f64 / 1e6,
                    folded,
                    waited
                );
            }
            syndromes
        });
        Ok(Reconstructor {
            block_size,
            base_logs: std::sync::Arc::new(base_logs),
            missing: missing.to_vec(),
            inverse,
            tx: Some(tx),
            worker: Some(worker),
            batch: FeedBatch::with_capacity(BATCH_BYTES),
            batch_capacity: BATCH_BYTES,
        })
    }

    /// Accumulate one present input slice (borrowed - it is packed into
    /// the batch arena, so callers can reuse one read buffer instead of
    /// allocating per slice). `data` may be shorter than the block size
    /// (file tail) - the zero padding contributes nothing.
    pub fn feed(&mut self, input_index: usize, data: &[u8]) {
        debug_assert!(
            !self.missing.contains(&input_index),
            "fed a slice declared missing"
        );
        debug_assert!(data.len() <= self.block_size);
        if self.batch.arena.len() + data.len() > self.batch_capacity {
            self.flush();
        }
        self.batch.push(self.base_logs[input_index], data);
        if self.batch.arena.len() >= self.batch_capacity {
            self.flush();
        }
    }

    /// Hand the pending batch to the fold worker. Blocks only when a
    /// batch is already queued behind the one being folded.
    fn flush(&mut self) {
        if self.batch.slices.is_empty() {
            return;
        }
        let batch = std::mem::replace(
            &mut self.batch,
            FeedBatch::with_capacity(self.batch_capacity),
        );
        // The worker outlives every sender; send can't fail.
        let _ = self.tx.as_ref().expect("finish() not yet called").send(batch);
    }

    /// A shareable feed handle for parallel producers (M2c.2). Each
    /// reader thread takes its own Feeder; batches from every handle
    /// funnel into the same fold worker, so slices may arrive in any
    /// interleaving (the syndrome fold is order-free XOR accumulation).
    /// `max_batch` bounds the handle's assembly buffer - callers split
    /// [`BATCH_BYTES`] across handles so total in-flight memory stays
    /// what the single-feeder design used. Drop every Feeder (they
    /// flush on drop) BEFORE calling [`finish`], or finish blocks on
    /// the channel.
    pub fn feeder(&self, max_batch: usize) -> Feeder {
        let max_batch = max_batch.max(1 << 20);
        Feeder {
            tx: self.tx.as_ref().expect("finish() not yet called").clone(),
            base_logs: self.base_logs.clone(),
            batch: FeedBatch::with_capacity(max_batch),
            max_batch,
        }
    }

    /// Solve: returns the reconstructed slices (full `block_size` bytes
    /// each, zero-padded past any file tail) in `missing` order.
    pub fn finish(mut self) -> Vec<Vec<u8>> {
        self.flush();
        drop(self.tx.take());
        let syndromes = self
            .worker
            .take()
            .expect("finish() called once")
            .join()
            .expect("syndrome fold worker panicked");
        let m = self.missing.len();
        let words = self.block_size / 2;
        let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
        if m > 0 {
            // Same tiled multi-accumulate as the syndrome fold: the
            // m x m back-substitution re-reads every syndrome row per
            // output row, so untiled it costs m x the syndrome set in
            // RAM sweeps (and used to run scalar on top). Shares the
            // row x column scheduler too - with one missing block this
            // solve is a single row, so rows alone would run it on one
            // thread.
            let syn_bytes: Vec<&[u8]> =
                syndromes.iter().map(|s| gf16::words_as_bytes(s)).collect();
            let inverse = &self.inverse;
            let t_bs = std::time::Instant::now();
            fold_parallel(&mut out, &syn_bytes, &|j, i| inverse[j][i]);
            if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                eprintln!("[repair-timing] back-substitution: {:.2?}", t_bs.elapsed());
            }
        }
        // On little-endian a word slice already IS its PAR2 byte view,
        // so this is a memcpy per block rather than a per-byte iterator
        // chain over the whole repaired payload.
        out.into_iter()
            .map(|w| gf16::words_as_bytes(&w).to_vec())
            .collect()
    }
}

/// One producer's handle into a [`Reconstructor`]'s fold worker (M2c.2
/// parallel feed reads). Same batching as the built-in feed path, but
/// clonable across reader threads; flushes its tail batch on drop.
pub struct Feeder {
    tx: std::sync::mpsc::SyncSender<FeedBatch>,
    base_logs: std::sync::Arc<Vec<u32>>,
    batch: FeedBatch,
    max_batch: usize,
}

impl Feeder {
    /// Same contract as [`Reconstructor::feed`].
    pub fn feed(&mut self, input_index: usize, data: &[u8]) {
        if self.batch.arena.len() + data.len() > self.max_batch {
            self.flush();
        }
        self.batch.push(self.base_logs[input_index], data);
        if self.batch.arena.len() >= self.max_batch {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.batch.slices.is_empty() {
            return;
        }
        let batch = std::mem::replace(&mut self.batch, FeedBatch::with_capacity(self.max_batch));
        // The worker outlives every sender; send can't fail.
        let _ = self.tx.send(batch);
    }
}

impl Drop for Feeder {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Explicit inverse of the CONSECUTIVE-exponent repair matrix in O(m²),
/// via Lagrange basis polynomials - Gauss-Jordan is O(m³) and was the
/// true ceiling at extreme damage (0.55 s at m = 1400 even fanned out;
/// ~two minutes extrapolated at the m = 8192 repair cap).
///
/// With exponents e0..e0+m-1 the matrix factors: A[r][c] = g_c^{e0+r} =
/// g_c^{e0} · g_c^r, so A = V · diag(g_c^{e0}) with V[r][c] = g_c^r a
/// classic Vandermonde in the bases g_c = 2^{k_c}. V is the transpose of
/// the evaluation matrix whose inverse rows are the Lagrange basis
/// polynomials of the nodes, so
///
/// ```text
///     A⁻¹[c][r] = g_c^{-e0} · [z^r] L_c(z),
///     L_c(z) = Π_{k≠c}(z + g_k) / Π_{k≠c}(g_c + g_k)
/// ```
///
/// (char 2: subtraction is XOR). Build the master polynomial P(z) =
/// Π(z + g_c) once in O(m²); each column is then one synthetic division
/// P/(z + g_c), one Horner evaluation for the denominator, and one
/// scalar-vector scale - O(m) each, columns independent, so the whole
/// inverse is O(m²), which is optimal (it HAS m² entries). Everything is
/// exact field arithmetic: no conditioning concerns. `ks` are the base
/// logs k_c; distinct ks (guaranteed - they are distinct naturals
/// coprime to 65535) make V nonsingular ALWAYS, so this path cannot
/// fail; `None` is returned only on the theoretically-impossible
/// duplicate base, and the caller falls back to Gauss-Jordan.
fn invert_vandermonde(ks: &[u32], e0: u32) -> Option<Vec<Vec<u16>>> {
    let m = ks.len();
    let bases: Vec<u16> = ks.iter().map(|&k| gf16::pow2(k as u64)).collect();
    // P(z) = Π (z + g_c), degree m: p[i] is the z^i coefficient.
    let mut p = vec![0u16; m + 1];
    p[0] = 1;
    for (deg, &g) in bases.iter().enumerate() {
        // p ← p·(z + g): new[i] = old[i-1] + g·old[i], walked downward
        // so it runs in place.
        let t = MulTable::new(g);
        p[deg + 1] = p[deg];
        for i in (1..=deg).rev() {
            p[i] = p[i - 1] ^ t.mul(p[i]);
        }
        p[0] = t.mul(p[0]);
    }
    // Columns are independent - fan out for the big heavy-damage case.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(m / 64)
        .max(1);
    let mut rows: Vec<Option<Vec<u16>>> = vec![None; m];
    let build_row = |c: usize| -> Option<Vec<u16>> {
        let g = bases[c];
        let t = MulTable::new(g);
        // Synthetic division: Q_c = P / (z + g), degree m-1.
        let mut q = vec![0u16; m];
        q[m - 1] = p[m];
        for i in (1..m).rev() {
            q[i - 1] = p[i] ^ t.mul(q[i]);
        }
        // Denominator d_c = Q_c(g) = Π_{k≠c}(g + g_k), by Horner.
        let mut d = 0u16;
        for &coef in q.iter().rev() {
            d = t.mul(d) ^ coef;
        }
        if d == 0 {
            return None; // duplicate base - cannot happen for valid ks
        }
        // Row c of A⁻¹: (g^{-e0} / d_c) · Q_c, one SIMD scalar-vector
        // product (xor into zeros = plain multiply).
        let neg_e0 = gf16::ORDER as u64 - (ks[c] as u64 * e0 as u64) % gf16::ORDER as u64;
        let scale = gf16::mul(gf16::inv(d), gf16::pow2(neg_e0));
        let mut row = vec![0u16; m];
        MulTable::new(scale).xor_mul_words(&mut row, &q);
        Some(row)
    };
    if threads < 2 {
        for (c, slot) in rows.iter_mut().enumerate() {
            *slot = build_row(c);
        }
    } else {
        let chunk = m.div_ceil(threads);
        std::thread::scope(|s| {
            for (w, slice) in rows.chunks_mut(chunk).enumerate() {
                let build_row = &build_row;
                s.spawn(move || {
                    for (i, slot) in slice.iter_mut().enumerate() {
                        *slot = build_row(w * chunk + i);
                    }
                });
            }
        });
    }
    rows.into_iter().collect()
}

/// Gauss-Jordan inversion over GF(2^16) (addition = XOR, so no sign
/// bookkeeping). Distinct bases and exponents make singularity
/// essentially theoretical, but a generalized Vandermonde over a finite
/// field carries no guarantee - the caller treats it as unrepairable
/// with this slice set.
///
/// Past [`PAR_INVERT_MIN`] rows the elimination fans out: the serial
/// loop is O(m²) split-table builds plus O(m³) field work on ONE thread,
/// and at heavy damage that was the single largest piece of the solve
/// (measured 1.9 s of a 6.3 s repair at m = 1400).
fn invert(a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
    let m = a.len();
    // Each worker should own enough rows that a column's elimination
    // outweighs its two barrier crossings.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(m / 32)
        .max(1);
    if m < PAR_INVERT_MIN || threads < 2 {
        return invert_serial(a);
    }
    invert_parallel(a, threads)
}

/// Below this the barrier choreography costs more than the elimination.
const PAR_INVERT_MIN: usize = 128;

/// The fan-out behind [`invert`]. Rows are dealt to workers round-robin
/// and NEVER move - pivoting is tracked as a permutation instead of the
/// serial path's row swaps, so every worker keeps `&mut` to its own rows
/// for the whole solve. Each column runs two barrier-separated phases:
/// scan (every worker offers its lowest eligible pivot row; atomic min
/// picks the winner), publish (the owner normalizes the pivot row and
/// copies it into a shared buffer), then every worker eliminates its own
/// rows against the copy. The published inverse is reassembled through
/// the pivot permutation at the end.
fn invert_parallel(mut a: Vec<Vec<u16>>, threads: usize) -> Result<Vec<Vec<u16>>, RepairError> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let m = a.len();
    let mut inv: Vec<Vec<u16>> = (0..m)
        .map(|i| {
            let mut row = vec![0u16; m];
            row[i] = 1;
            row
        })
        .collect();
    // piv[col] = row index chosen as that column's pivot (usize::MAX =
    // none found = singular).
    let piv: Vec<AtomicUsize> = (0..m).map(|_| AtomicUsize::new(usize::MAX)).collect();
    let used: Vec<AtomicBool> = (0..m).map(|_| AtomicBool::new(false)).collect();
    let singular = AtomicBool::new(false);
    let pivot_rows = std::sync::RwLock::new((vec![0u16; m], vec![0u16; m]));
    let barrier = std::sync::Barrier::new(threads);
    let mut shards: Vec<Vec<(usize, &mut [u16], &mut [u16])>> =
        (0..threads).map(|_| Vec::new()).collect();
    for (r, (ar, ir)) in a.iter_mut().zip(inv.iter_mut()).enumerate() {
        shards[r % threads].push((r, ar.as_mut_slice(), ir.as_mut_slice()));
    }
    std::thread::scope(|s| {
        for shard in shards {
            let (piv, used, singular, pivot_rows, barrier) =
                (&piv, &used, &singular, &pivot_rows, &barrier);
            s.spawn(move || {
                let mut shard = shard;
                for col in 0..m {
                    // Scan: offer this shard's lowest unused row with a
                    // nonzero in the pivot column. Rows were dealt in
                    // ascending order, so the first hit is the lowest.
                    for (r, ar, _) in shard.iter() {
                        if !used[*r].load(Ordering::Relaxed) && ar[col] != 0 {
                            piv[col].fetch_min(*r, Ordering::AcqRel);
                            break;
                        }
                    }
                    barrier.wait();
                    let p = piv[col].load(Ordering::Acquire);
                    if p == usize::MAX {
                        // Every worker reads the same verdict right
                        // after the same barrier, so all of them leave
                        // on this column together.
                        singular.store(true, Ordering::Relaxed);
                        return;
                    }
                    if p % threads == shard[0].0 % threads {
                        // This shard owns the pivot row: normalize it
                        // and publish a copy for everyone to fold with.
                        used[p].store(true, Ordering::Relaxed);
                        let (_, ar, ir) = shard
                            .iter_mut()
                            .find(|(r, _, _)| *r == p)
                            .expect("owner shard holds the pivot row");
                        let f = gf16::inv(ar[col]);
                        if f != 1 {
                            for x in ar.iter_mut().chain(ir.iter_mut()) {
                                *x = gf16::mul(*x, f);
                            }
                        }
                        let mut g = pivot_rows.write().unwrap();
                        g.0.copy_from_slice(ar);
                        g.1.copy_from_slice(ir);
                    }
                    barrier.wait();
                    let g = pivot_rows.read().unwrap();
                    for (r, ar, ir) in shard.iter_mut() {
                        if *r == p {
                            continue;
                        }
                        let f = ar[col];
                        if f == 0 {
                            continue;
                        }
                        let t = MulTable::new(f);
                        t.xor_mul_words(ar, &g.0);
                        t.xor_mul_words(ir, &g.1);
                    }
                    // No third barrier: the next scan touches only this
                    // shard's rows and a fresh piv slot, and the next
                    // publisher's write lock can't be granted until every
                    // reader has dropped `g` at its next barrier.
                }
            });
        }
    });
    if singular.load(Ordering::Relaxed) {
        return Err(RepairError::SingularMatrix);
    }
    // inv[piv[col]] is column `col`'s row of A⁻¹.
    Ok(piv
        .into_iter()
        .map(|p| std::mem::take(&mut inv[p.into_inner()]))
        .collect())
}

fn invert_serial(mut a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
    let m = a.len();
    let mut inv: Vec<Vec<u16>> = (0..m)
        .map(|i| {
            let mut row = vec![0u16; m];
            row[i] = 1;
            row
        })
        .collect();
    for col in 0..m {
        let piv = (col..m)
            .find(|&r| a[r][col] != 0)
            .ok_or(RepairError::SingularMatrix)?;
        a.swap(col, piv);
        inv.swap(col, piv);
        let f = gf16::inv(a[col][col]);
        if f != 1 {
            for x in a[col].iter_mut().chain(inv[col].iter_mut()) {
                *x = gf16::mul(*x, f);
            }
        }
        for r in 0..m {
            if r == col || a[r][col] == 0 {
                continue;
            }
            let f = a[r][col];
            let t = MulTable::new(f);
            let (arow, acol) = two_rows(&mut a, r, col);
            t.xor_mul_words(arow, acol);
            let (irow, icol) = two_rows(&mut inv, r, col);
            t.xor_mul_words(irow, icol);
        }
    }
    Ok(inv)
}

/// Disjoint (&mut rows[r], &rows[c]) - r ≠ c.
fn two_rows(rows: &mut [Vec<u16>], r: usize, c: usize) -> (&mut [u16], &[u16]) {
    debug_assert_ne!(r, c);
    if r < c {
        let (lo, hi) = rows.split_at_mut(c);
        (&mut lo[r], &hi[0])
    } else {
        let (lo, hi) = rows.split_at_mut(r);
        (&mut hi[0], &lo[c])
    }
}

// ---------------------------------------------------------------------------
// Mapped-target repair driver (M2c.1) - repair INTO the extracted file
// ---------------------------------------------------------------------------

/// Byte access to the recovery-set files by their Main-packet index,
/// however they are actually stored - the daemon implements this over
/// the extractor's volume view (header stash + block→payload mapping
/// into the extracted output), so damaged store-mode sets repair with
/// no materialized volume files at all.
pub trait VolumeIo: Sync {
    fn read(&self, file: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()>;
    fn write(&self, file: usize, off: u64, data: &[u8]) -> std::io::Result<()>;
}

/// Reed-Solomon repair over [`VolumeIo`]: `files` must be EVERY file of
/// the recovery set in Main-packet order (the global slice numbering
/// assigns the RS constants - a reordered or partial list computes
/// garbage), each with a caller-supplied per-block present vector (the
/// daemon's in-stream + read-back verification ledger). `recovery`
/// holds candidate recovery slices (exponent, exactly block_size
/// bytes); duplicates by exponent are fine, the smallest exponents win.
///
/// Present slices are streamed through the syndromes via `io.read`,
/// missing ones are reconstructed and written back via `io.write`
/// (tails trimmed to the file length), and then - the self-proving
/// contract - the set is re-read via `io.read` and must check out, or
/// the whole call fails with [`RepairError::VerifyFailed`] and the
/// caller falls back to the materialize + `repair_dir` path. Returns the
/// number of blocks rebuilt. No adoption here: misnamed/shifted sets
/// take the directory path.
///
/// EVERY file is re-read, not only the ones that received a rebuilt
/// block. The blocks this function trusts were verified as they ARRIVED,
/// off the wire, never off disk, so a covered file whose bytes went bad
/// after they were written - a failed pwrite, a bad sector, anything
/// between - passed straight through a "successful" repair and out into
/// a Completed job. The directory path never had this hole, because
/// par2 verifies the whole set from disk before and after.
///
/// The digest differs by what the file has been through, which is what
/// keeps the added cost near a plain read:
///
/// - a file that received rebuilt blocks is re-hashed WHOLE against its
///   PAR2 MD5, exactly as before: those bytes are new, and MD5 is what
///   proves them;
/// - an untouched file is checked per block against the IFSC CRC32s,
///   ~5-10x cheaper than MD5 and the same answer for the corruption this
///   is looking for. `full_verify` (the operator asking for full rather
///   than fast verification) puts it on MD5 too, as does a set that
///   carries no per-block checksums to use.
pub fn repair_mapped(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    full_verify: bool,
) -> Result<usize, RepairError> {
    if block_size == 0 || block_size % 2 != 0 {
        return Err(RepairError::Malformed(format!(
            "block size {block_size} not a positive multiple of 2"
        )));
    }
    let bs = block_size as u64;
    // Lay files onto the global slice index space; collect the missing.
    let mut first_slice = Vec::with_capacity(files.len());
    // owner[g] = file index of global slice g (zero-length files make
    // first_slice non-unique, so a binary search can't be trusted).
    let mut owner: Vec<usize> = Vec::new();
    let mut missing: Vec<usize> = Vec::new();
    let mut next = 0usize;
    for (fi, (f, present)) in files.iter().enumerate() {
        let n = f.length.div_ceil(bs) as usize;
        if present.len() != n {
            return Err(RepairError::Malformed(format!(
                "{}: present vector has {} entries, length implies {n}",
                f.name,
                present.len()
            )));
        }
        first_slice.push(next);
        owner.extend(std::iter::repeat_n(fi, n));
        for (i, &p) in present.iter().enumerate() {
            if !p {
                missing.push(next + i);
            }
        }
        next += n;
    }
    let n_inputs = next;
    if n_inputs > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{n_inputs} input slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}"
        )));
    }
    if missing.is_empty() {
        return Ok(0);
    }

    // Smallest exponents win, deduped; exactly one per missing slice.
    let mut by_exp: HashMap<u32, &Vec<u8>> = HashMap::new();
    for (e, data) in recovery {
        if data.len() == block_size {
            by_exp.entry(*e).or_insert(data);
        }
    }
    if by_exp.len() < missing.len() {
        return Err(RepairError::Malformed(format!(
            "{} recovery slice(s) for {} missing block(s)",
            by_exp.len(),
            missing.len()
        )));
    }
    let mut exps: Vec<u32> = by_exp.keys().copied().collect();
    exps.sort_unstable();
    exps.truncate(missing.len());
    let chosen: Vec<(u32, Vec<u8>)> =
        exps.iter().map(|e| (*e, by_exp[e].clone())).collect();

    // Syndrome pass: stream every present slice once via io.read.
    // M2c.2: the reads were the measured hot spot (4.0 s of a 4.96 s
    // repair, single-threaded 1 MB reads) - fan them out. The flattened
    // present-slice list is split into CONTIGUOUS chunks (sequential
    // read patterns per thread), each reader owns a Feeder into the one
    // fold worker; XOR accumulation makes arrival order irrelevant.
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let rec = Reconstructor::new(block_size, n_inputs, &missing, &chosen)?;
    let work: Vec<(usize, usize, u64, usize)> = files
        .iter()
        .enumerate()
        .flat_map(|(fi, (f, present))| {
            let base = first_slice[fi];
            present.iter().enumerate().filter(|&(_, &p)| p).map(move |(i, _)| {
                let off = i as u64 * bs;
                (base + i, fi, off, (f.length - off).min(bs) as usize)
            })
        })
        .collect();
    if work.is_empty() {
        // Every block of every file is missing: there is nothing to
        // stream into the syndrome pass, and `work.chunks(0)` below
        // would panic. The all-missing rebuild belongs to the disk
        // path - decline so the caller falls back gracefully.
        return Err(RepairError::Malformed(
            "no present blocks to stream - declining mapped repair".into(),
        ));
    }
    let readers = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(8)
        .min(work.len())
        .max(1);
    // Split the shared batch budget across handles so total in-flight
    // memory matches the old single-feeder design.
    let per_reader_batch = (BATCH_BYTES / readers).max(1 << 20);
    let chunk = work.len().div_ceil(readers);
    let mut read_results: Vec<Result<(), RepairError>> =
        (0..readers).map(|_| Ok(())).collect();
    std::thread::scope(|s| {
        for (wchunk, res) in work.chunks(chunk).zip(read_results.iter_mut()) {
            let mut feeder = rec.feeder(per_reader_batch);
            s.spawn(move || {
                *res = (|| {
                    // One reusable read buffer per reader: slices are
                    // packed into the feeder's arena, so per-slice
                    // allocations are gone (see FeedBatch).
                    let mut buf = vec![0u8; block_size];
                    for &(g, fi, off, take) in wchunk {
                        io.read(fi, off, &mut buf[..take])?;
                        feeder.feed(g, &buf[..take]);
                    }
                    Ok(())
                })();
                // feeder drops here → tail batch flushes.
            });
        }
    });
    for r in read_results {
        r?;
    }
    if timing {
        eprintln!("[repair-timing] feed reads queued in {:.2?}", t0.elapsed());
    }
    let rebuilt = rec.finish();
    if timing {
        eprintln!("[repair-timing] fold+solve done at {:.2?}", t0.elapsed());
    }

    // Write rebuilt blocks back, tails trimmed.
    for (mi, &g) in missing.iter().enumerate() {
        let fi = owner[g];
        let (f, _) = &files[fi];
        let off = (g - first_slice[fi]) as u64 * bs;
        let take = (f.length - off).min(bs) as usize;
        io.write(fi, off, &rebuilt[mi][..take])?;
    }

    // Self-prove: re-read the WHOLE SET via io.read - files are
    // independent, so verify across threads.
    let rebuilt_files: HashSet<usize> = missing.iter().map(|&g| owner[g]).collect();
    // Sorted, because the results below are collected in this order and
    // `for r in results { r?; }` reports the FIRST error: HashSet order
    // meant a repair leaving two files failing their MD5 named a
    // different one on each run from identical inputs. repair_dir_set
    // sorts for the same reason. Also makes the chunk split
    // size-independent of hash order.
    let touched: Vec<usize> = (0..files.len()).collect();
    let threads = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(touched.len())
        .max(1);
    let chunk = touched.len().div_ceil(threads);
    let mut results: Vec<Option<Result<(), RepairError>>> =
        (0..touched.len()).map(|_| None).collect();
    std::thread::scope(|s| {
        for (tchunk, rchunk) in touched.chunks(chunk).zip(results.chunks_mut(chunk)) {
            let rebuilt_files = &rebuilt_files;
            s.spawn(move || {
                let mut buf = vec![0u8; 1 << 20];
                for (&fi, r) in tchunk.iter().zip(rchunk) {
                    let (f, _) = &files[fi];
                    // MD5 for the bytes this call just wrote, and for a set
                    // with no IFSC to check against; CRC32 per block for the
                    // rest. See the function docs.
                    let md5_this = full_verify
                        || rebuilt_files.contains(&fi)
                        || f.blocks.len() as u64 != f.length.div_ceil(bs);
                    let one = (|| {
                        let mut hasher = Md5::new();
                        let mut crc = crc32fast::Hasher::new();
                        let mut filled = 0usize; // bytes of the current block
                        let mut bidx = 0usize;
                        let mut off = 0u64;
                        while off < f.length {
                            let take = (f.length - off).min(buf.len() as u64) as usize;
                            io.read(fi, off, &mut buf[..take])?;
                            if md5_this {
                                hasher.update(&buf[..take]);
                            } else {
                                // Blocks straddle reads freely; the CRC
                                // accumulates across them and closes at each
                                // boundary. The tail block is zero-padded to
                                // the block size per spec, which
                                // `crc32_zeros` does without allocating.
                                let mut p = 0usize;
                                while p < take {
                                    let seg = (block_size - filled).min(take - p);
                                    crc.update(&buf[p..p + seg]);
                                    filled += seg;
                                    p += seg;
                                    if filled == block_size {
                                        let done = std::mem::replace(
                                            &mut crc,
                                            crc32fast::Hasher::new(),
                                        );
                                        if f.blocks.get(bidx).map(|b| b.crc32)
                                            != Some(done.finalize())
                                        {
                                            return Err(RepairError::VerifyFailed(
                                                f.name.clone(),
                                            ));
                                        }
                                        filled = 0;
                                        bidx += 1;
                                    }
                                }
                            }
                            off += take as u64;
                        }
                        if md5_this {
                            let md5: [u8; 16] = hasher.finalize().into();
                            if md5 != f.md5 {
                                return Err(RepairError::VerifyFailed(f.name.clone()));
                            }
                            return Ok(());
                        }
                        if filled > 0 {
                            let padded = crate::yenc_simd::crc32_zeros(
                                crc.finalize(),
                                (block_size - filled) as u64,
                            );
                            if f.blocks.get(bidx).map(|b| b.crc32) != Some(padded) {
                                return Err(RepairError::VerifyFailed(f.name.clone()));
                            }
                        }
                        Ok(())
                    })();
                    *r = Some(one);
                }
            });
        }
    });
    for r in results {
        r.expect("verify worker filled every slot")?;
    }
    if timing {
        eprintln!("[repair-timing] patch+verify done at {:.2?}", t0.elapsed());
    }
    Ok(missing.len())
}

// ---------------------------------------------------------------------------
// Extra-file block adoption - par2cmdline's "sliding scan", natively
// ---------------------------------------------------------------------------

/// Where an adopted block's bytes live: candidate index + byte offset.
/// Bytes past the candidate's end are zeros (a tail block matched at
/// end-of-file - its checksum covers the zero padding).
#[derive(Debug, Clone, Copy)]
struct AdoptSrc {
    cand: usize,
    offset: u64,
}

/// 32×32 GF(2) matrix over u32 columns: column `j` is the image of bit
/// `1 << j`.
type Mat32 = [u32; 32];

fn mat_apply(m: &Mat32, mut x: u32) -> u32 {
    let mut r = 0u32;
    let mut i = 0usize;
    while x != 0 {
        if x & 1 != 0 {
            r ^= m[i];
        }
        x >>= 1;
        i += 1;
    }
    r
}

fn mat_mul(a: &Mat32, b: &Mat32) -> Mat32 {
    std::array::from_fn(|j| mat_apply(a, b[j]))
}

/// CRC32 (IEEE-reflected, the IFSC flavor) over a fixed-length window
/// that slides one byte in O(1). The CRC register update is GF(2)-linear
/// in (register, byte), so the difference between "window shifted by
/// one" and "window plus one byte" is a linear function of the expiring
/// byte pushed through `window` zero-byte updates - precomputed here as
/// `expire`, built in O(log window) by matrix exponentiation (windows
/// are PAR2 block sizes, up to 256 MB).
struct RollingCrc {
    table: [u32; 256],
    /// expire[c]: contribution to remove when byte value `c` leaves.
    expire: [u32; 256],
}

impl RollingCrc {
    fn new(window: usize) -> RollingCrc {
        let mut table = [0u32; 256];
        for (i, e) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            }
            *e = c;
        }
        // One-zero-byte register operator, raised to the window length.
        let one: Mat32 = std::array::from_fn(|j| {
            let r = 1u32 << j;
            (r >> 8) ^ table[(r & 0xFF) as usize]
        });
        let mut zn: Mat32 = std::array::from_fn(|j| 1u32 << j);
        let mut base = one;
        let mut e = window;
        while e != 0 {
            if e & 1 != 0 {
                zn = mat_mul(&base, &zn);
            }
            e >>= 1;
            if e != 0 {
                base = mat_mul(&base, &base);
            }
        }
        const INIT: u32 = 0xFFFF_FFFF;
        let expire = std::array::from_fn(|c| {
            let after_first = (INIT >> 8) ^ table[((INIT ^ c as u32) & 0xFF) as usize];
            mat_apply(&zn, after_first ^ INIT)
        });
        RollingCrc { table, expire }
    }

    /// Register update for one appended byte.
    #[inline]
    fn push(&self, reg: u32, byte: u8) -> u32 {
        (reg >> 8) ^ self.table[((reg ^ byte as u32) & 0xFF) as usize]
    }

    /// Slide a full window one byte: append `new`, expire `old` (the
    /// byte that entered `window` updates ago).
    #[inline]
    fn roll(&self, reg: u32, old: u8, new: u8) -> u32 {
        self.push(reg, new) ^ self.expire[old as usize]
    }
}

/// Identity key for a destination path. On a case-insensitive volume
/// `README.txt` and `readme.txt` name ONE object, so comparing raw paths
/// counts two aliases of the same file as two distinct destinations -
/// which is how a "distinct" target ends up sharing (and destroying)
/// another's bytes. `fold` comes from probing the output volume
/// (`disk::case_insensitive_dir`), not from the build target: the answer
/// belongs to the destination filesystem, not to the binary.
fn path_identity_key(fold: bool, p: &Path) -> PathBuf {
    if fold {
        PathBuf::from(p.to_string_lossy().to_lowercase())
    } else {
        p.to_path_buf()
    }
}

/// Files eligible as adoption sources: every regular non-.par2 file in
/// `dir` that is not an identified target (identified files' bytes are
/// already pinned block-by-block - scanning them again is the perf trap
/// this gate exists to avoid).
fn adoption_candidates(
    dir: &Path,
    targets: &[Target],
    exclude: &HashSet<PathBuf>,
) -> Result<Vec<(PathBuf, u64)>, RepairError> {
    // Keyed by filesystem identity, not by spelling: the PAR2-declared name
    // and the on-disk name routinely differ in case, and on a case-insensitive
    // volume an exact compare would hand an identified target's OWN file to
    // the sliding scan as an adoption source.
    let fold = crate::disk::case_insensitive_dir(dir);
    let identified: HashSet<PathBuf> = targets
        .iter()
        .filter(|t| t.exists && (t.intact || t.present.iter().any(|&p| p)))
        .map(|t| path_identity_key(fold, &t.path))
        .collect();
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if !e.file_type()?.is_file()
            || p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
            || identified.contains(&path_identity_key(fold, &p))
            || exclude.contains(&p)
        {
            continue;
        }
        let len = e.metadata()?.len();
        if len > 0 {
            out.push((p, len));
        }
    }
    out.sort();
    Ok(out)
}

fn md5_of_file(path: &Path, limit: Option<u64>) -> Result<[u8; 16], RepairError> {
    let mut f = File::open(path)?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut left = limit.unwrap_or(u64::MAX);
    while left > 0 {
        let want = buf.len().min(left.min(usize::MAX as u64) as usize);
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hasher.finalize().into())
}

/// Locate missing blocks' content in the candidate files. Fast path
/// first: a candidate that is a missing file whole (same length + MD5,
/// prefiltered on md5_16k) adopts every slice at aligned offsets - the
/// common renamed-file case, no per-byte scan. Whatever is still missing
/// then goes through the sliding scan: roll the block-size CRC32 window
/// over each candidate (continuing with virtual zeros past end-of-file,
/// matching the spec's zero-padded tail checksums), confirm CRC hits by
/// block MD5, and record the first source found per slice.
fn adopt_blocks(
    dir: &Path,
    targets: &[Target],
    missing: &[usize],
    bs: usize,
    exclude: &HashSet<PathBuf>,
) -> Result<(Vec<(PathBuf, u64)>, HashMap<usize, AdoptSrc>), RepairError> {
    let cands = adoption_candidates(dir, targets, exclude)?;
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    if cands.is_empty() {
        return Ok((cands, adopted));
    }
    let missing_set: HashSet<usize> = missing.iter().copied().collect();

    let mut consumed = vec![false; cands.len()];
    // Each candidate is hashed at most once, however many targets probe
    // it (renamed multi-volume sets pair N missing files with N
    // candidates - without the cache that's N² hashing passes).
    let mut head_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut md5_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    for t in targets {
        let unidentified =
            !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
        if t.n_slices == 0 || t.file.length == 0 || !unidentified {
            continue;
        }
        for (ci, (p, len)) in cands.iter().enumerate() {
            if consumed[ci] || *len != t.file.length {
                continue;
            }
            let head = match head_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, Some((*len).min(16384)))?;
                    head_cache[ci] = Some(h);
                    h
                }
            };
            if head != t.file.md5_16k {
                continue;
            }
            let whole = match md5_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, None)?;
                    md5_cache[ci] = Some(h);
                    h
                }
            };
            if whole != t.file.md5 {
                continue;
            }
            for i in 0..t.n_slices {
                let g = t.first_slice + i;
                if missing_set.contains(&g) {
                    adopted.entry(g).or_insert(AdoptSrc {
                        cand: ci,
                        offset: i as u64 * bs as u64,
                    });
                }
            }
            consumed[ci] = true;
            break;
        }
    }

    let indices: Vec<usize> = (0..cands.len()).filter(|&ci| !consumed[ci]).collect();
    sliding_scan(&cands, &indices, targets, &missing_set, bs, &mut adopted)?;
    Ok((cands, adopted))
}

/// Sliding-scan the candidate slots named by `indices` for the content
/// of every slice in `missing_set` not already adopted. Slices without
/// IFSC data can only be found by the whole-file fast path.
fn sliding_scan(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    targets: &[Target],
    missing_set: &HashSet<usize>,
    bs: usize,
    adopted: &mut HashMap<usize, AdoptSrc>,
) -> Result<(), RepairError> {
    let mut by_crc: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut md5s: HashMap<usize, [u8; 16]> = HashMap::new();
    for t in targets {
        for (i, c) in t.file.blocks.iter().enumerate() {
            let g = t.first_slice + i;
            if missing_set.contains(&g) && !adopted.contains_key(&g) {
                by_crc.entry(c.crc32).or_default().push(g);
                md5s.insert(g, c.md5);
            }
        }
    }
    if by_crc.is_empty() {
        return Ok(());
    }
    // 65536-bit prefilter on the CRC's low 16 bits: the per-byte hot
    // path is one table probe, not a HashMap lookup.
    let mut filter = vec![0u64; 1024];
    for &crc in by_crc.keys() {
        filter[(crc & 0xFFFF) as usize >> 6] |= 1 << (crc & 63);
    }
    let roll = RollingCrc::new(bs);
    let mut remaining = md5s.len();
    for &ci in indices {
        if remaining == 0 {
            break;
        }
        let (p, len) = &cands[ci];
        scan_candidate(
            p, *len, bs, &roll, &filter, &by_crc, &md5s, ci, adopted, &mut remaining,
        )?;
    }
    Ok(())
}

/// Slide the block-size window over one candidate file (plus `bs - 1`
/// virtual zero bytes so tail blocks match at end-of-file) and adopt
/// every still-missing slice whose CRC32 and MD5 both match.
#[allow(clippy::too_many_arguments)]
fn scan_candidate(
    path: &Path,
    len: u64,
    bs: usize,
    roll: &RollingCrc,
    filter: &[u64],
    by_crc: &HashMap<u32, Vec<usize>>,
    md5s: &HashMap<usize, [u8; 16]>,
    cand: usize,
    adopted: &mut HashMap<usize, AdoptSrc>,
    remaining: &mut usize,
) -> Result<(), RepairError> {
    let mut f = File::open(path)?;
    let mut ring = vec![0u8; bs];
    let mut pos = 0usize; // ring slot of the window's oldest byte
    let mut reg = 0xFFFF_FFFFu32;
    let mut buf = vec![0u8; 1 << 18];
    let mut i: u64 = 0; // stream index: file bytes, then virtual zeros
    let total = len + bs as u64 - 1;
    'stream: while i < total {
        let n = if i < len {
            let want = buf.len().min((len - i) as usize);
            let got = f.read(&mut buf[..want])?;
            if got == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "candidate file shrank mid-scan",
                )
                .into());
            }
            got
        } else {
            let want = buf.len().min((total - i) as usize);
            buf[..want].fill(0);
            want
        };
        for &b in &buf[..n] {
            let old = ring[pos];
            reg = if i < bs as u64 {
                roll.push(reg, b)
            } else {
                roll.roll(reg, old, b)
            };
            ring[pos] = b;
            pos += 1;
            if pos == bs {
                pos = 0;
            }
            i += 1;
            if i < bs as u64 {
                continue;
            }
            let crc = reg ^ 0xFFFF_FFFF;
            if filter[(crc & 0xFFFF) as usize >> 6] & (1 << (crc & 63)) == 0 {
                continue;
            }
            let Some(slices) = by_crc.get(&crc) else {
                continue;
            };
            if slices.iter().all(|g| adopted.contains_key(g)) {
                continue;
            }
            let mut h = Md5::new();
            h.update(&ring[pos..]);
            h.update(&ring[..pos]);
            let md5: [u8; 16] = h.finalize().into();
            let offset = i - bs as u64;
            for &g in slices {
                if md5s[&g] == md5 && !adopted.contains_key(&g) {
                    adopted.insert(g, AdoptSrc { cand, offset });
                    *remaining -= 1;
                    if *remaining == 0 {
                        break 'stream;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Reads adopted block bytes from candidate files, keeping each source
/// open across calls. Bytes past a candidate's end are the zero padding
/// the block checksum was verified against.
struct CandReader<'a> {
    cands: &'a [(PathBuf, u64)],
    open: HashMap<usize, File>,
}

impl CandReader<'_> {
    fn read(&mut self, s: AdoptSrc, take: usize) -> Result<Vec<u8>, RepairError> {
        let (path, len) = &self.cands[s.cand];
        let f = match self.open.entry(s.cand) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => v.insert(File::open(path)?),
        };
        let avail = take.min(len.saturating_sub(s.offset) as usize);
        let mut v = vec![0u8; take];
        crate::disk::read_exact_at(f, &mut v[..avail], s.offset)?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Directory-level driver
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RepairReport {
    /// Input blocks reconstructed via Reed-Solomon.
    pub blocks_rebuilt: usize,
    /// Input blocks whose content was found intact under another name or
    /// offset by the extra-file adoption scan.
    pub blocks_adopted: usize,
    /// File names (as found on disk) that adopted blocks came from.
    pub adopted_from: Vec<String>,
    /// Files whose bytes were patched (includes created ones).
    pub files_patched: Vec<String>,
    /// Subset of `files_patched` that were missing entirely.
    pub files_created: Vec<String>,
}

#[derive(Debug)]
pub enum RepairStatus {
    /// Every recovery-set file already verifies - nothing written.
    NoDamage,
    /// Damage found and repaired; every patched file re-verified by MD5.
    Repaired(RepairReport),
    /// Not enough recovery slices on disk for the damage found.
    Unrepairable { needed: usize, have: usize },
}

/// One recovery-set file mapped onto the global slice index space.
struct Target {
    file: Par2File,
    path: PathBuf,
    first_slice: usize,
    n_slices: usize,
    /// Per-slice verification result (present ⇔ both IFSC hashes match).
    present: Vec<bool>,
    /// Whole-file MD5 over the first `length` bytes matched AND the disk
    /// length is exactly `length`.
    intact: bool,
    exists: bool,
}

/// Gather the PAR2 packet files in `dir`: `*.par2` by name, plus
/// magic-sniffed files (obfuscated posts rename recovery volumes too, and
/// par2cmdline - handed extra files - loads packets from them, so do we).
/// Sniffing costs one 8-byte read per file; oversized sniff hits are
/// skipped rather than slurped. Returns (sorted packet files, the subset
/// found by sniff rather than name).
fn collect_packet_files(dir: &Path) -> Result<(Vec<PathBuf>, HashSet<PathBuf>), RepairError> {
    const MAX_SNIFFED_PACKET_BYTES: u64 = 1 << 30;
    let mut packet_files: Vec<PathBuf> = Vec::new();
    let mut sniffed: HashSet<PathBuf> = HashSet::new();
    for e in std::fs::read_dir(dir)? {
        let Ok(e) = e else { continue };
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let p = e.path();
        if p
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
        {
            packet_files.push(p);
        } else if e
            .metadata()
            .is_ok_and(|m| m.len() >= 64 && m.len() <= MAX_SNIFFED_PACKET_BYTES)
        {
            let mut head = [0u8; 8];
            let ok = File::open(&p)
                .and_then(|mut f| f.read_exact(&mut head))
                .is_ok();
            if ok && &head == par2::MAGIC {
                sniffed.insert(p.clone());
                packet_files.push(p);
            }
        }
    }
    packet_files.sort();
    Ok((packet_files, sniffed))
}

/// Repair the PAR2 recovery set found in `dir`: parse every `*.par2`
/// file (packets only - data files are located by their FileDesc names),
/// verify each recovery-set file block-by-block from disk, reconstruct
/// missing/corrupt blocks from recovery slices, and patch them in place.
/// Files longer than declared are truncated; absent files are recreated.
/// Success requires every touched file to pass its whole-file MD5.
/// When the dir carries packets from more than one recovery set, the
/// first set seen (sorted packet-file order) is the one repaired.
pub fn repair_dir(dir: &Path) -> Result<RepairStatus, RepairError> {
    repair_dir_set(dir, None)
}

/// Repair every recovery set in `dir` whose data files are actually
/// there. A nested layer can land beside packets that describe files
/// which never touched this dir (the downloaded set's own index next to
/// an in-stream-extracted payload: its volumes exist only as the
/// extracted output) - repairing such a set would at best re-derive
/// "everything missing" noise and at worst resurrect volume files, so a
/// set only qualifies when at least one of its FileDesc names exists on
/// disk. Sets are repaired in first-seen (sorted packet-file) order;
/// per-set failures don't stop later sets. `Ok(vec![])` = nothing
/// relevant here at all.
pub fn repair_present_sets(
    dir: &Path,
) -> Result<Vec<Result<RepairStatus, RepairError>>, RepairError> {
    let (packet_files, _) = collect_packet_files(dir)?;
    if packet_files.is_empty() {
        return Ok(Vec::new());
    }
    let mut order: Vec<[u8; 16]> = Vec::new();
    let mut names: HashMap<[u8; 16], Vec<String>> = HashMap::new();
    for path in &packet_files {
        let bytes = std::fs::read(path)?;
        par2::scan_packets(&bytes, |pkt| {
            names.entry(pkt.set_id).or_insert_with(|| {
                order.push(pkt.set_id);
                Vec::new()
            });
            if pkt.ptype == *par2::TYPE_FILEDESC {
                if let Some((_, d)) = par2::parse_filedesc(pkt.body) {
                    names.get_mut(&pkt.set_id).unwrap().push(d.name);
                }
            }
        });
    }
    let mut out = Vec::new();
    for id in order {
        let present = names[&id]
            .iter()
            .any(|n| dir.join(crate::disk::sanitize_filename(n)).is_file());
        if present {
            out.push(repair_dir_set(dir, Some(id)));
        }
    }
    Ok(out)
}

/// The repair engine behind [`repair_dir`] / [`repair_present_sets`]:
/// `want` pins the recovery set to operate on (packets from other sets
/// are ignored, exactly as foreign-set packets always were); `None`
/// keeps the historical first-seen binding.
fn repair_dir_set(dir: &Path, want: Option<[u8; 16]>) -> Result<RepairStatus, RepairError> {
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let mut mark = {
        let mut last = t0;
        move |label: &str| {
            if timing {
                let now = std::time::Instant::now();
                eprintln!(
                    "[repair-timing] {label}: +{:.2?} (total {:.2?})",
                    now - last,
                    now - t0
                );
                last = now;
            }
        }
    };
    let (packet_files, mut sniffed) = collect_packet_files(dir)?;
    if packet_files.is_empty() {
        return Err(RepairError::NoMainPacket);
    }

    // --- incremental packet scan (one file's bytes in memory at a time) ---
    // Critical packets (Main + every FileDesc + IFSC) are duplicated in
    // every volume, so they normally all come out of the FIRST (index)
    // file. The loop stops as soon as the critical set is complete; the
    // remaining files - the recovery volumes, i.e. almost all the bytes -
    // carry only RecvSlic locations we still need, and that scan runs in
    // the background UNDER the target-verify pass below (disjoint files:
    // .par2 volumes here, data files there).
    let mut set_id: Option<[u8; 16]> = want;
    let mut main: Option<(u64, Vec<[u8; 16]>)> = None;
    let mut descs: HashMap<[u8; 16], par2::Desc> = HashMap::new();
    let mut ifscs: HashMap<[u8; 16], Vec<BlockCheck>> = HashMap::new();
    let mut seen: HashSet<[u8; 16]> = HashSet::new();
    // (packet file idx, data offset, exponent, data len)
    let mut rec_locs: Vec<(usize, usize, u32, usize)> = Vec::new();
    let mut scanned = 0usize;
    for (pfi, path) in packet_files.iter().enumerate() {
        let bytes = std::fs::read(path)?;
        par2::scan_packets(&bytes, |pkt| {
            if !seen.insert(pkt.md5) {
                return;
            }
            match set_id {
                None => set_id = Some(pkt.set_id),
                Some(id) if id != pkt.set_id => return,
                _ => {}
            }
            match &pkt.ptype {
                t if t == par2::TYPE_MAIN => {
                    if main.is_none() {
                        main = par2::parse_main(pkt.body);
                    }
                }
                t if t == par2::TYPE_FILEDESC => {
                    if let Some((fid, d)) = par2::parse_filedesc(pkt.body) {
                        descs.entry(fid).or_insert(d);
                    }
                }
                t if t == par2::TYPE_IFSC => {
                    if let Some((fid, blocks)) = par2::parse_ifsc(pkt.body) {
                        ifscs.entry(fid).or_insert(blocks);
                    }
                }
                t if t == par2::TYPE_RECVSLIC => {
                    if pkt.body.len() >= 4 {
                        let e = u32::from_le_bytes(pkt.body[0..4].try_into().unwrap());
                        rec_locs.push((pfi, pkt.body_offset + 4, e, pkt.body.len() - 4));
                    }
                }
                _ => {}
            }
        });
        scanned = pfi + 1;
        let critical_complete = main.as_ref().is_some_and(|(_, ids)| {
            ids.iter()
                .all(|fid| descs.contains_key(fid) && ifscs.contains_key(fid))
        });
        if critical_complete {
            break;
        }
        // Sets whose files carry no IFSC never look "complete", so they
        // scan everything here and skip the background leg - exactly the
        // historical behavior.
    }
    mark("packet scan (critical)");
    let (block_size, file_ids) = main.ok_or(RepairError::NoMainPacket)?;
    let bs = block_size as usize;
    // Whether two destination paths that differ only in case name ONE file is
    // a property of this volume, so probe it rather than guessing from the
    // build target (see `disk::case_insensitive_dir`).
    let fold = crate::disk::case_insensitive_dir(dir);

    // --- lay the recovery-set files onto the global slice index space ---
    let mut targets: Vec<Target> = Vec::with_capacity(file_ids.len());
    let mut next_slice = 0usize;
    for fid in &file_ids {
        let Some(d) = descs.remove(fid) else {
            // Without the FileDesc we know neither name nor length, and
            // the global constant assignment shifts - unrecoverable here.
            return Err(RepairError::Malformed(format!(
                "FileDesc missing for file id {fid:02x?}"
            )));
        };
        // d.length is attacker-controlled; a huge value makes n_slices
        // enormous. Reject per-file before it can (a) wrap the running
        // sum in `next_slice += n_slices` (release builds have no overflow
        // checks), slipping past the aggregate guard below, or (b) drive a
        // multi-exabyte `vec![false; n_slices]` in verify_target.
        let n_slices_u64 = d.length.div_ceil(block_size);
        if n_slices_u64 > MAX_INPUT_SLICES as u64 {
            return Err(RepairError::Malformed(format!(
                "{}: {n_slices_u64} slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}",
                d.name
            )));
        }
        let n_slices = n_slices_u64 as usize;
        // A disagreeing IFSC packet is DROPPED, not fatal - `par2.rs` handles
        // the identical case the same way, for the same reason: an empty
        // `blocks` routes the file to the whole-file MD5, which covers every
        // byte. Failing the call instead abandoned every other file in the
        // set (19 repairable files lost to one malformed packet) when the
        // recovery blocks to fix them were sitting right there.
        let blocks = ifscs
            .remove(fid)
            .filter(|b| b.len() == n_slices)
            .unwrap_or_default();
        // Wire-supplied names never touch the filesystem raw.
        let path = dir.join(crate::disk::sanitize_filename(&d.name));
        targets.push(Target {
            file: Par2File {
                file_id: *fid,
                name: d.name,
                length: d.length,
                md5: d.md5,
                md5_16k: d.md5_16k,
                blocks,
            },
            path,
            first_slice: next_slice,
            n_slices,
            present: Vec::new(),
            intact: false,
            exists: false,
        });
        next_slice = next_slice.saturating_add(n_slices);
    }
    let n_inputs = next_slice;
    if n_inputs > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{n_inputs} input slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}"
        )));
    }

    // Two distinct FileDescs can sanitize to the SAME path (e.g. "a/b.bin"
    // and "a_b.bin" both land at "a_b.bin"). Sharing a destination is silent
    // data loss: verifying, repairing, or landing the second removes the
    // first's (possibly intact) bytes and renames over them, yet the set can
    // still report `Repaired`. Give every colliding target a distinct path,
    // disambiguated by its unique file_id, so a destination is never shared
    // and each descriptor is verified/landed against its own file.
    {
        // Claims are keyed by filesystem identity: on macOS/Windows two
        // descriptors that differ only in case name ONE object, so an exact
        // path compare would leave both undisambiguated and let the second
        // land over the first - the very loss this block exists to prevent.
        let mut claimed: HashSet<PathBuf> = HashSet::new();
        for t in &mut targets {
            if claimed.insert(path_identity_key(fold, &t.path)) {
                continue;
            }
            let mut suffix = 0u32;
            loop {
                let fid: String =
                    t.file.file_id.iter().take(6).map(|b| format!("{b:02x}")).collect();
                let tag = if suffix == 0 {
                    format!(".dup-{fid}")
                } else {
                    format!(".dup-{fid}-{suffix}")
                };
                let mut alt = t.path.clone().into_os_string();
                alt.push(tag);
                let alt = PathBuf::from(alt);
                if claimed.insert(path_identity_key(fold, &alt)) {
                    t.path = alt;
                    break;
                }
                suffix += 1;
            }
        }
    }

    // A sniffed packet file that is also a recovery-set target is data
    // first - keep it eligible for the adoption scan. Compared through
    // `path_identity_key` like every other destination compare in this file:
    // on a case-insensitive volume `Movie.R00` and `movie.r00` name one
    // object, and an exact compare left the file in `exclude`, so the
    // adoption scan never looked at the one file holding the missing blocks
    // and the set reported Unrepairable when it was repairable.
    sniffed.retain(|p| {
        !targets
            .iter()
            .any(|t| path_identity_key(fold, &t.path) == path_identity_key(fold, p))
    });

    // --- verify every target from disk, overlapped with the recovery-
    //     volume scan (they touch disjoint files: data files here, .par2
    //     volumes there) ---
    let remaining = &packet_files[scanned..];
    if remaining.is_empty() {
        verify_all_targets(&mut targets, bs)?;
    } else {
        let seen_bg = std::mem::take(&mut seen);
        let sid = set_id;
        let mut verify_res: Result<(), RepairError> = Ok(());
        let mut bg_res: Result<Vec<(usize, usize, u32, usize)>, RepairError> = Ok(Vec::new());
        std::thread::scope(|s| {
            let h = s.spawn(move || {
                let mut seen = seen_bg;
                let mut locs = Vec::new();
                for (i, path) in remaining.iter().enumerate() {
                    let pfi = scanned + i;
                    let bytes = std::fs::read(path)?;
                    par2::scan_packets(&bytes, |pkt| {
                        if !seen.insert(pkt.md5) {
                            return;
                        }
                        // Criticals are already complete, so only the
                        // recovery-slice locations are still wanted here.
                        if Some(pkt.set_id) == sid
                            && pkt.ptype == *par2::TYPE_RECVSLIC
                            && pkt.body.len() >= 4
                        {
                            let e = u32::from_le_bytes(pkt.body[0..4].try_into().unwrap());
                            locs.push((pfi, pkt.body_offset + 4, e, pkt.body.len() - 4));
                        }
                    });
                }
                Ok(locs)
            });
            verify_res = verify_all_targets(&mut targets, bs);
            bg_res = h.join().expect("volume scan worker panicked");
        });
        verify_res?;
        rec_locs.extend(bg_res?);
    }
    mark("verify targets + volume scan");
    let mut missing: Vec<usize> = Vec::new();
    for t in &targets {
        for (i, ok) in t.present.iter().enumerate() {
            if !ok {
                missing.push(t.first_slice + i);
            }
        }
    }
    let needs_resize: Vec<usize> = targets
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.intact)
        .map(|(i, _)| i)
        .collect();
    if missing.is_empty() && needs_resize.is_empty() {
        return Ok(RepairStatus::NoDamage);
    }

    // --- pick recovery slices: smallest exponents, deduped ---
    let mut by_exp: HashMap<u32, (usize, usize)> = HashMap::new();
    for &(pfi, off, e, len) in &rec_locs {
        if len == bs {
            by_exp.entry(e).or_insert((pfi, off));
        }
    }

    // --- extra-file adoption ---
    // Only when a file failed identification outright (missing, renamed,
    // shifted - nothing on disk verifies) or the damage exceeds the
    // recovery slices on disk. The scan reads whole candidate files, so
    // it must never run on the everyday a-few-blocks-bad repair.
    let any_unidentified = targets.iter().any(|t| {
        t.n_slices > 0 && !(t.exists && (t.intact || t.present.iter().any(|&p| p)))
    });
    let (mut cands, mut adopted) =
        if !missing.is_empty() && (any_unidentified || missing.len() > by_exp.len()) {
            adopt_blocks(dir, &targets, &missing, bs, &sniffed)?
        } else {
            (Vec::new(), HashMap::new())
        };
    // Adopted slices are found, not missing - only the rest needs RS.
    let mut missing: Vec<usize> = missing
        .into_iter()
        .filter(|g| !adopted.contains_key(g))
        .collect();

    // Last-resort escalation: still more damage than recovery on disk -
    // scan identified damaged targets too, which the normal pass skips.
    // A mid-file insertion leaves a file half-verified with the rest of
    // its content byte-shifted inside itself; only a scan of that file
    // can find it. Any target whose bytes end up serving as an adoption
    // source is later rebuilt via temp+rename, never patched in place.
    if !missing.is_empty() && missing.len() > by_exp.len() {
        let start = cands.len();
        for t in &targets {
            let identified = t.exists && (t.intact || t.present.iter().any(|&p| p));
            if identified && t.present.iter().any(|&p| !p) {
                let len = std::fs::metadata(&t.path)?.len();
                if len > 0 {
                    cands.push((t.path.clone(), len));
                }
            }
        }
        if cands.len() > start {
            let missing_set: HashSet<usize> = missing.iter().copied().collect();
            let indices: Vec<usize> = (start..cands.len()).collect();
            sliding_scan(&cands, &indices, &targets, &missing_set, bs, &mut adopted)?;
            missing.retain(|g| !adopted.contains_key(g));
        }
    }
    mark("adoption");
    let cands = cands;
    let adopted = adopted;
    let missing = missing;
    let mut cand_reader = CandReader {
        cands: &cands,
        open: HashMap::new(),
    };

    let needed = missing.len();
    if by_exp.len() < needed {
        return Ok(RepairStatus::Unrepairable {
            needed,
            have: by_exp.len(),
        });
    }
    let recovery = if needed > 0 {
        let mut exps: Vec<u32> = by_exp.keys().copied().collect();
        exps.sort_unstable();
        exps.truncate(needed);
        let mut loaded: Vec<(u32, Vec<u8>)> = Vec::with_capacity(needed);
        let mut open: HashMap<usize, File> = HashMap::new();
        for e in exps {
            let (pfi, off) = by_exp[&e];
            let f = match open.entry(pfi) {
                std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(File::open(&packet_files[pfi])?)
                }
            };
            let mut data = vec![0u8; bs];
            crate::disk::read_exact_at(f, &mut data, off as u64)?;
            loaded.push((e, data));
        }
        loaded
    } else {
        Vec::new()
    };
    mark("load recovery");

    // --- syndrome pass: stream every present slice once ---
    let blocks_rebuilt = missing.len();
    let rebuilt: Vec<Vec<u8>> = if blocks_rebuilt > 0 {
        let mut rec = Reconstructor::new(bs, n_inputs, &missing, &recovery)?;
        // `Reconstructor::new` has copied every recovery slice into its own
        // u16 syndrome buffers, so this second payload-sized copy (missing x
        // block_size - 537 MB on a 128-block/4 MiB repair) is dead weight for
        // the rest of the solve. Peak RSS on that repair measured ~2 GB
        // against a 268 MB resolved budget; this is one of the four live
        // buffers and the only one that is redundant.
        drop(recovery);
        // Present-slice reads fan out exactly as in `repair_mapped`
        // (M2c.2): contiguous chunks of the flattened work list per
        // reader (sequential read patterns), each with its own Feeder
        // into the one fold worker. This loop used to run single-file,
        // single-threaded - the only serial data pass left in the
        // disk repair path.
        let work: Vec<(usize, usize, u64, usize)> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.exists)
            .flat_map(|(ti, t)| {
                t.present.iter().enumerate().filter(|&(_, &p)| p).map(move |(i, _)| {
                    let off = i as u64 * block_size;
                    (t.first_slice + i, ti, off, (t.file.length - off).min(block_size) as usize)
                })
            })
            .collect();
        if !work.is_empty() {
            let readers = std::thread::available_parallelism()
                .map_or(4, |n| n.get())
                .min(8)
                .min(work.len())
                .max(1);
            let per_reader_batch = (BATCH_BYTES / readers).max(1 << 20);
            let chunk = work.len().div_ceil(readers);
            let targets_ref = &targets;
            let mut read_results: Vec<Result<(), RepairError>> =
                (0..readers).map(|_| Ok(())).collect();
            std::thread::scope(|s| {
                for (wchunk, res) in work.chunks(chunk).zip(read_results.iter_mut()) {
                    let mut feeder = rec.feeder(per_reader_batch);
                    s.spawn(move || {
                        *res = (|| {
                            let mut open: Option<(usize, File)> = None;
                            // One reusable read buffer per reader (see
                            // FeedBatch - per-slice allocs are the trap).
                            let mut buf = vec![0u8; bs];
                            for &(g, ti, off, take) in wchunk {
                                if open.as_ref().is_none_or(|(oi, _)| *oi != ti) {
                                    open = Some((ti, File::open(&targets_ref[ti].path)?));
                                }
                                let f = &open.as_ref().expect("just opened").1;
                                crate::disk::read_exact_at(f, &mut buf[..take], off)?;
                                feeder.feed(g, &buf[..take]);
                            }
                            Ok(())
                        })();
                        // feeder drops here → tail batch flushes.
                    });
                }
            });
            for r in read_results {
                r?;
            }
        }
        // Adopted blocks are present data too - fed from their source.
        let mut by_cand: HashMap<usize, Vec<(usize, u64)>> = HashMap::new();
        for (&g, s) in &adopted {
            by_cand.entry(s.cand).or_default().push((g, s.offset));
        }
        for (ci, mut list) in by_cand {
            list.sort_unstable_by_key(|&(_, off)| off);
            for (g, off) in list {
                let take = bs.min(cands[ci].1.saturating_sub(off) as usize);
                let data = cand_reader.read(AdoptSrc { cand: ci, offset: off }, take)?;
                rec.feed(g, &data);
            }
        }
        let r = rec.finish();
        mark("feed+fold+solve");
        r
    } else {
        Vec::new()
    };

    // --- patch ---
    let mut adopted_from: Vec<String> = adopted
        .values()
        .map(|s| {
            cands[s.cand]
                .0
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    adopted_from.sort();
    let mut report = RepairReport {
        blocks_rebuilt,
        blocks_adopted: adopted.len(),
        adopted_from,
        files_patched: Vec::new(),
        files_created: Vec::new(),
    };
    let rebuilt_of: HashMap<usize, usize> =
        missing.iter().enumerate().map(|(mi, &g)| (g, mi)).collect();
    let mut damaged: Vec<usize> = needs_resize;
    for (ti, t) in targets.iter().enumerate() {
        if !t.present.iter().all(|&p| p) && !damaged.contains(&ti) {
            damaged.push(ti);
        }
    }
    damaged.sort_unstable();

    // Identified targets (≥1 verified block or an intact MD5) are patched
    // in place - unless their bytes serve as an adoption source. Those,
    // and unidentified targets, are rebuilt to a temp file and renamed in
    // LAST, so no source is overwritten until every adopted read and
    // every whole-file verify has happened.
    // Identity-keyed for the same reason as `adoption_candidates`: the source
    // was found by `read_dir` and the target names itself from the PAR2
    // packet, so a case difference between the two would defeat this check
    // and patch a file in place while it is still being read as a source.
    let used_sources: HashSet<PathBuf> = adopted
        .values()
        .map(|s| path_identity_key(fold, &cands[s.cand].0))
        .collect();
    let mut renames: Vec<(PathBuf, usize)> = Vec::new();
    let cleanup = |renames: &[(PathBuf, usize)], extra: Option<&PathBuf>| {
        for (tmp, _) in renames {
            let _ = std::fs::remove_file(tmp);
        }
        if let Some(tmp) = extra {
            let _ = std::fs::remove_file(tmp);
        }
    };
    // (path to verify, target index) - temps verify before their rename.
    let mut checks: Vec<(PathBuf, usize)> = Vec::new();
    for &ti in &damaged {
        let t = &targets[ti];
        let identified = t.exists && (t.intact || t.present.iter().any(|&p| p));
        let via_temp = !identified || used_sources.contains(&path_identity_key(fold, &t.path));
        // In temp mode verified blocks are copied over from the old
        // file; in place they're already where they belong.
        let write_blocks = |f: &File,
                           cand_reader: &mut CandReader,
                           copy_present: bool|
         -> Result<(), RepairError> {
            f.set_len(t.file.length)?;
            let src = if copy_present && t.exists && t.present.iter().any(|&p| p) {
                Some(File::open(&t.path)?)
            } else {
                None
            };
            for (i, &present) in t.present.iter().enumerate() {
                let g = t.first_slice + i;
                let off = i as u64 * block_size;
                let take = (t.file.length - off).min(block_size) as usize;
                if present {
                    if let Some(src) = &src {
                        let mut v = vec![0u8; take];
                        crate::disk::read_exact_at(src, &mut v, off)?;
                        crate::disk::write_all_at(f, &v, off)?;
                    }
                    continue;
                }
                if let Some(&mi) = rebuilt_of.get(&g) {
                    crate::disk::write_all_at(f, &rebuilt[mi][..take], off)?;
                } else if let Some(&s) = adopted.get(&g) {
                    let data = cand_reader.read(s, take)?;
                    crate::disk::write_all_at(f, &data, off)?;
                }
            }
            Ok(())
        };
        if !via_temp {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&t.path)?;
            let res = write_blocks(&f, &mut cand_reader, false);
            drop(f);
            if let Err(e) = res {
                cleanup(&renames, None);
                return Err(e);
            }
            checks.push((t.path.clone(), ti));
        } else {
            // A temp this call provably created. The name used to be fully
            // predictable and opened with `File::create`, which truncates and
            // follows symlinks: a pre-existing `.<name>.nzbfast-repair.tmp`
            // was clobbered and then removed by cleanup, and a symlink there
            // put the truncation on its target. `create_new` cannot do either.
            let base = t
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into());
            let mut made = None;
            for n in 0..1024 {
                let candidate =
                    t.path.with_file_name(format!(".{base}.nzbfast-repair.{n}.tmp"));
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&candidate)
                {
                    Ok(f) => {
                        made = Some((candidate, f));
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        cleanup(&renames, None);
                        return Err(e.into());
                    }
                }
            }
            let Some((tmp, tmp_file)) = made else {
                cleanup(&renames, None);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "no free repair temp name",
                )
                .into());
            };
            let res = write_blocks(&tmp_file, &mut cand_reader, true);
            if let Err(e) = res {
                cleanup(&renames, Some(&tmp));
                return Err(e);
            }
            checks.push((tmp.clone(), ti));
            renames.push((tmp, ti));
        }
    }
    mark("patch");
    // Whole-file MD5 for everything written - files are independent, so
    // verify across threads.
    if !checks.is_empty() {
        let threads = std::thread::available_parallelism()
            .map_or(4, |n| n.get())
            .min(checks.len())
            .max(1);
        let chunk = checks.len().div_ceil(threads);
        let mut results: Vec<Option<Result<bool, RepairError>>> =
            (0..checks.len()).map(|_| None).collect();
        let targets_ref = &targets;
        std::thread::scope(|s| {
            for (cchunk, rchunk) in checks.chunks(chunk).zip(results.chunks_mut(chunk)) {
                s.spawn(move || {
                    for ((path, ti), r) in cchunk.iter().zip(rchunk) {
                        *r = Some(md5_matches(path, &targets_ref[*ti].file));
                    }
                });
            }
        });
        for ((_, ti), r) in checks.iter().zip(results) {
            match r.expect("verify worker filled every slot") {
                Ok(true) => {}
                Ok(false) => {
                    cleanup(&renames, None);
                    return Err(RepairError::VerifyFailed(targets[*ti].file.name.clone()));
                }
                Err(e) => {
                    cleanup(&renames, None);
                    return Err(e);
                }
            }
        }
    }
    mark("final verify");
    // Every adopted read and every verify is done - land the rebuilds.
    let temp_set: HashSet<usize> = renames.iter().map(|&(_, ti)| ti).collect();
    for &ti in &damaged {
        if !temp_set.contains(&ti) {
            report.files_patched.push(targets[ti].file.name.clone());
        }
    }
    for (tmp, ti) in renames {
        let t = &targets[ti];
        // Rename straight over the target - no remove first.
        //
        // `fs::rename` replaces atomically on unix AND windows
        // (MOVEFILE_REPLACE_EXISTING), so the file is never absent. Removing
        // it first opened a window where a crash, or any rename failure, left
        // NO canonical file at all: the original had been deleted and the
        // rebuilt copy was still sitting under its temp name.
        std::fs::rename(&tmp, &t.path)?;
        report.files_patched.push(t.file.name.clone());
        if !t.exists {
            report.files_created.push(t.file.name.clone());
        }
    }
    Ok(RepairStatus::Repaired(report))
}

/// What the verify pass learned about one target file.
struct Pass1Out {
    exists: bool,
    intact: bool,
    /// Whole-file MD5 matched over the declared length: every block is
    /// present even if trailing junk keeps `intact` false.
    clean: bool,
    /// Per-block presence from the in-stream block CRC32s, for a
    /// damaged file with IFSC data (None when clean, absent, or the
    /// set has no IFSC packets - those fall back to all-false).
    present: Option<Vec<bool>>,
}

/// Target verification in ONE streaming pass: the whole-file MD5 and
/// the per-block IFSC CRC32s are computed from the same buffered read.
/// The old shape hashed every damaged file twice (whole-file MD5, then
/// a second full pass of per-block MD5+CRC); the CRC costs a few
/// percent on top of the MD5 and deletes that second pass outright.
///
/// Presence is decided by the block CRC32 ALONE. The block MD5s are
/// deliberately not consulted: a corrupt block that collides CRC32
/// (2⁻³² per damaged block, and damage is honest randomness) would
/// poison the syndromes and make the repair produce wrong bytes for
/// OTHER blocks - and that is exactly what the mandatory whole-file
/// self-prove after patching catches, so the failure mode is a FAILED
/// repair, never a wrong "Repaired". Same trade par2cmdline's own
/// scanning makes, with a stronger backstop.
fn verify_pass1(path: &Path, file: &Par2File, bs: usize) -> Result<Pass1Out, RepairError> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Pass1Out {
                exists: false,
                intact: false,
                clean: false,
                present: None,
            });
        }
        Err(e) => return Err(e.into()),
    };
    let disk_len = f.metadata()?.len();
    let n_slices = file.length.div_ceil(bs as u64) as usize;
    let track = !file.blocks.is_empty();
    let mut whole = Md5::new();
    let mut blocks_ok = track.then(|| vec![false; n_slices]);
    let mut crc = crc32fast::Hasher::new();
    let mut bfill = 0usize;
    let mut bidx = 0usize;
    // The buffer is bounded regardless of the slice size - `bs` is
    // wire-supplied up to MAX_BLOCK_SIZE (256 MiB), and this allocates
    // once per parallel worker. The in-stream block CRC accumulates
    // across reads (`bfill`), so blocks may straddle buffers freely.
    let mut buf = vec![0u8; bs.clamp(1 << 20, 8 << 20)];
    let limit = file.length.min(disk_len);
    let mut pos = 0u64;
    while pos < limit {
        let take = ((limit - pos) as usize).min(buf.len());
        read_full(&mut f, &mut buf[..take])?;
        whole.update(&buf[..take]);
        if let Some(ok) = blocks_ok.as_mut() {
            let mut p = 0usize;
            while p < take {
                let seg = (bs - bfill).min(take - p);
                crc.update(&buf[p..p + seg]);
                bfill += seg;
                p += seg;
                if bfill == bs {
                    let done = std::mem::replace(&mut crc, crc32fast::Hasher::new());
                    if let Some(check) = file.blocks.get(bidx) {
                        ok[bidx] = done.finalize() == check.crc32;
                    }
                    bfill = 0;
                    bidx += 1;
                }
            }
        }
        pos += take as u64;
    }
    if bfill > 0 {
        if let Some(ok) = blocks_ok.as_mut() {
            // Tail block, zero-padded to the block size per spec - but
            // only when the declared bytes were all on disk (a tail cut
            // short by a truncated file is damage by definition).
            let off = bidx as u64 * bs as u64;
            let expect = (file.length - off).min(bs as u64);
            if limit - off >= expect {
                // Extended through the padding in O(log n) rather than by
                // hashing a zero buffer: `bs` is wire-supplied up to 256 MiB,
                // and a set of many one-byte targets made every parallel
                // worker allocate one of those at its tail block - a
                // metadata-driven `targets x block_size` memory spike on a
                // file that could be a few KB. The read buffer above is
                // already clamped for exactly this reason.
                let padded = crate::yenc_simd::crc32_zeros(
                    crc.clone().finalize(),
                    (bs - bfill) as u64,
                );
                if let Some(check) = file.blocks.get(bidx) {
                    ok[bidx] = padded == check.crc32;
                }
            }
        }
    }
    let md5: [u8; 16] = whole.finalize().into();
    let md5_ok = disk_len >= file.length && md5 == file.md5;
    Ok(Pass1Out {
        exists: true,
        intact: md5_ok && disk_len == file.length,
        clean: md5_ok,
        present: if md5_ok { None } else { blocks_ok },
    })
}

/// Verify every target from a size-descending work queue (biggest file
/// first, so no fixed-chunk straggler). One streaming pass per file
/// does everything - see [`verify_pass1`].
fn verify_all_targets(targets: &mut [Target], bs: usize) -> Result<(), RepairError> {
    if targets.is_empty() {
        return Ok(());
    }
    let mut order: Vec<usize> = (0..targets.len()).collect();
    order.sort_by_key(|&ti| targets[ti].file.length); // pop() takes the largest
    let queue = std::sync::Mutex::new(order);
    let cores = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(targets.len());
    let targets_ref: &[Target] = targets;
    let mut results: Vec<Result<Vec<(usize, Pass1Out)>, RepairError>> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..cores)
            .map(|_| {
                s.spawn(|| {
                    let mut out: Vec<(usize, Pass1Out)> = Vec::new();
                    loop {
                        let Some(ti) = queue.lock().unwrap().pop() else {
                            return Ok(out);
                        };
                        let t = &targets_ref[ti];
                        out.push((ti, verify_pass1(&t.path, &t.file, bs)?));
                    }
                })
            })
            .collect();
        results = handles
            .into_iter()
            .map(|h| h.join().expect("verify worker panicked"))
            .collect();
    });
    let mut p1s: Vec<(usize, Pass1Out)> = Vec::with_capacity(targets.len());
    for r in results {
        p1s.extend(r?);
    }
    for (ti, out) in p1s {
        let t = &mut targets[ti];
        t.exists = out.exists;
        t.intact = out.intact;
        t.present = match out.present {
            Some(p) => p,
            None => vec![out.clean; t.n_slices],
        };
    }
    Ok(())
}

fn read_full(f: &mut File, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match f.read(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "file shorter than its metadata length",
                ));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn md5_matches(path: &Path, file: &Par2File) -> Result<bool, RepairError> {
    let mut f = File::open(path)?;
    if f.metadata()?.len() != file.length {
        return Ok(false);
    }
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let md5: [u8; 16] = hasher.finalize().into();
    Ok(md5 == file.md5)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Destination identity is a filesystem question, not a string question.
    /// The colliding-target guard, the adoption-source exclusion and the
    /// "never patch a file that is still being read" check all key on this,
    /// and on a case-insensitive volume an exact path compare silently treats
    /// two aliases of ONE file as two independent destinations - which is how
    /// a repair lands over an intact file and still reports success.
    #[test]
    fn path_identity_key_folds_only_when_told_to() {
        let a = Path::new("/out/README.txt");
        let b = Path::new("/out/readme.txt");
        // Folding: two aliases of ONE file on a case-insensitive volume.
        assert_eq!(path_identity_key(true, a), path_identity_key(true, b));
        // Not folding: genuinely distinct files on a case-sensitive volume.
        assert_ne!(path_identity_key(false, a), path_identity_key(false, b));
        // Genuinely different names must never collapse, either way.
        for fold in [true, false] {
            assert_ne!(
                path_identity_key(fold, Path::new("/out/a.bin")),
                path_identity_key(fold, Path::new("/out/b.bin"))
            );
        }
    }

    #[test]
    fn base_log_sequence_matches_the_spec() {
        let logs = input_base_logs(9).unwrap();
        assert_eq!(logs, vec![1, 2, 4, 7, 8, 11, 13, 14, 16]);
        // Constants themselves: 2, 4, 16, 128, 256, 2048, 8192, 16384, 0x100B.
        let bases: Vec<u16> = logs.iter().map(|&k| gf16::pow2(k as u64)).collect();
        assert_eq!(bases, vec![2, 4, 16, 128, 256, 2048, 8192, 16384, 0x100B]);
    }

    #[test]
    fn base_logs_cap_at_32768() {
        let logs = input_base_logs(MAX_INPUT_SLICES).unwrap();
        assert_eq!(logs.len(), MAX_INPUT_SLICES);
        assert!(*logs.last().unwrap() < 65535);
        assert!(input_base_logs(MAX_INPUT_SLICES + 1).is_err());
    }

    /// The tiled multi-accumulate must match the naive row x source
    /// double loop for every awkward shape: sources shorter than the
    /// rows, odd source lengths, tiles smaller/larger than rows, and a
    /// table budget small enough to force multiple source groups.
    #[test]
    fn fold_chunk_tiled_matches_naive() {
        let mut state = 0xB5297A4D3F84D5B5u64;
        let mut rng = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for (rows, nsrc, words, tile) in [
            (1usize, 1usize, 7usize, 4usize),
            (3, 5, 64, 16),
            (4, 7, 33, 8),
            (2, 3, 100, 1024), // tile bigger than the row: single tile
            (5, 9, 96, 32),
        ] {
            let coeffs: Vec<Vec<u16>> = (0..rows)
                .map(|_| (0..nsrc).map(|_| rng() as u16).collect())
                .collect();
            // Mix of full, short, odd, and empty sources.
            let srcs: Vec<Vec<u8>> = (0..nsrc)
                .map(|i| {
                    let len = match i % 4 {
                        0 => words * 2,
                        1 => words,     // short (and odd when words is odd)
                        2 => words * 2 - 1, // odd tail byte
                        _ => 0,         // empty
                    };
                    (0..len).map(|_| rng() as u8).collect()
                })
                .collect();
            let base: Vec<Vec<u16>> = (0..rows)
                .map(|_| (0..words).map(|_| rng() as u16).collect())
                .collect();

            let mut want = base.clone();
            for (j, row) in want.iter_mut().enumerate() {
                for (i, src) in srcs.iter().enumerate() {
                    MulTable::new(coeffs[j][i]).xor_mul_into(row, src);
                }
            }

            let src_refs: Vec<&[u8]> = srcs.iter().map(|s| s.as_slice()).collect();
            // A one-byte budget forces group size 1 (max grouping stress).
            for budget in [1usize, TABLE_BUDGET] {
                let mut got = base.clone();
                {
                    let mut views: Vec<&mut [u16]> =
                        got.iter_mut().map(|v| v.as_mut_slice()).collect();
                    fold_chunk_tiled(
                        &mut views,
                        &src_refs,
                        &|j, i| coeffs[j][i],
                        0,
                        tile,
                        budget,
                    );
                }
                assert_eq!(
                    got, want,
                    "rows={rows} nsrc={nsrc} words={words} tile={tile} budget={budget}"
                );
            }

            // The row x column scheduler must agree with the same
            // oracle. This is the path that splits each row's word
            // range across threads and re-windows every source to
            // match, so short/odd/empty sources are the interesting
            // part - a mis-windowed source silently corrupts a repair.
            let mut got = base.clone();
            fold_parallel(&mut got, &src_refs, &|j, i| coeffs[j][i]);
            assert_eq!(got, want, "fold_parallel rows={rows} nsrc={nsrc} words={words}");
        }
    }

    /// Reference recovery-slice generator: R_e = Σ_i g_i^e · D_i, the
    /// same formula par2cmdline uses to CREATE recovery data. Tests
    /// build sets with it and reconstruct after synthetic damage; the
    /// real-par2cmdline fixture test (tests/par2repair_reference.rs)
    /// pins the formula itself against reference-tool output.
    fn generate_recovery(slices: &[Vec<u8>], block_size: usize, e: u32) -> Vec<u8> {
        let logs = input_base_logs(slices.len()).unwrap();
        let mut acc = vec![0u16; block_size / 2];
        for (d, &k) in slices.iter().zip(&logs) {
            MulTable::new(gf16::pow2(k as u64 * e as u64)).xor_mul_into(&mut acc, d);
        }
        acc.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn demo_slices(n: usize, block_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                (0..block_size)
                    .map(|j| ((i * 7919 + j * 104729 + j / 3) % 251) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn round_trip_reconstructs_scattered_missing_slices() {
        let (n, bs) = (11, 64);
        let slices = demo_slices(n, bs);
        let missing = [0usize, 4, 5, 10];
        // Non-consecutive exponents on purpose.
        let recovery: Vec<(u32, Vec<u8>)> = [3u32, 0, 7, 5]
            .iter()
            .map(|&e| (e, generate_recovery(&slices, bs, e)))
            .collect();
        let mut rec = Reconstructor::new(bs, n, &missing, &recovery).unwrap();
        for (i, s) in slices.iter().enumerate() {
            if !missing.contains(&i) {
                rec.feed(i, s);
            }
        }
        let rebuilt = rec.finish();
        for (out, &j) in rebuilt.iter().zip(&missing) {
            assert_eq!(out, &slices[j], "slice {j} reconstructed byte-identical");
        }
    }

    #[test]
    fn round_trip_with_short_tail_slice() {
        let (n, bs) = (5, 32);
        let mut slices = demo_slices(n, bs);
        slices[4].truncate(13); // odd-length tail, like a real file tail
        let mut padded = slices.clone();
        padded[4].resize(bs, 0);
        let missing = [1usize, 4];
        let recovery: Vec<(u32, Vec<u8>)> = [0u32, 1]
            .iter()
            .map(|&e| (e, generate_recovery(&padded, bs, e)))
            .collect();
        let mut rec = Reconstructor::new(bs, n, &missing, &recovery).unwrap();
        for (i, s) in slices.iter().enumerate() {
            if !missing.contains(&i) {
                rec.feed(i, s); // short tails fed unpadded
            }
        }
        let rebuilt = rec.finish();
        assert_eq!(rebuilt[0], padded[1]);
        assert_eq!(
            &rebuilt[1][..13],
            &slices[4][..],
            "tail slice reconstructed"
        );
        assert!(rebuilt[1][13..].iter().all(|&b| b == 0), "padding is zeros");
    }

    #[test]
    fn wrong_recovery_count_is_rejected() {
        let (n, bs) = (4, 32);
        let slices = demo_slices(n, bs);
        let recovery = vec![(0u32, generate_recovery(&slices, bs, 0))];
        assert!(matches!(
            Reconstructor::new(bs, n, &[0, 1], &recovery),
            Err(RepairError::Malformed(_))
        ));
    }

    #[test]
    fn matrix_inversion_round_trips() {
        // A · A⁻¹ = I for a small PAR2-shaped matrix.
        let logs = input_base_logs(6).unwrap();
        let missing = [1usize, 3, 5];
        let exps = [0u32, 1, 2];
        let a: Vec<Vec<u16>> = exps
            .iter()
            .map(|&e| {
                missing
                    .iter()
                    .map(|&j| gf16::pow2(logs[j] as u64 * e as u64))
                    .collect()
            })
            .collect();
        let inv = invert(a.clone()).unwrap();
        for i in 0..3 {
            for j in 0..3 {
                let mut dot = 0u16;
                for k in 0..3 {
                    dot ^= gf16::mul(a[i][k], inv[k][j]);
                }
                assert_eq!(dot, u16::from(i == j), "({i},{j})");
            }
        }
    }

    /// Vec-backed VolumeIo for mapped-driver tests.
    struct MemIo {
        files: std::sync::Mutex<Vec<Vec<u8>>>,
        /// When set, writes to this (file, byte offset in the file's
        /// backing store) get flipped - simulates a broken write path,
        /// which the whole-file MD5 must catch.
        corrupt_write_at: Option<(usize, usize)>,
        /// When set, this (file, offset) is flipped on the FIRST write to
        /// any file - i.e. after every syndrome read has happened, so the
        /// rot cannot poison the reconstruction and the only thing that
        /// can catch it is the self-prove re-reading a file it did not
        /// rebuild.
        rot_on_first_write: Option<(usize, usize)>,
        rotted: std::sync::atomic::AtomicBool,
    }
    impl MemIo {
        fn new(files: Vec<Vec<u8>>, corrupt_write_at: Option<(usize, usize)>) -> MemIo {
            MemIo {
                files: std::sync::Mutex::new(files),
                corrupt_write_at,
                rot_on_first_write: None,
                rotted: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn rotting(files: Vec<Vec<u8>>, at: (usize, usize)) -> MemIo {
            MemIo {
                files: std::sync::Mutex::new(files),
                corrupt_write_at: None,
                rot_on_first_write: Some(at),
                rotted: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn snapshot(&self) -> Vec<Vec<u8>> {
            self.files.lock().unwrap().clone()
        }
    }
    impl VolumeIo for MemIo {
        fn read(&self, file: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
            let files = self.files.lock().unwrap();
            let off = off as usize;
            buf.copy_from_slice(&files[file][off..off + buf.len()]);
            Ok(())
        }
        fn write(&self, file: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
            let mut files = self.files.lock().unwrap();
            let off = off as usize;
            files[file][off..off + data.len()].copy_from_slice(data);
            if let Some((rf, ro)) = self.rot_on_first_write {
                if !self.rotted.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    files[rf][ro] ^= 0xFF;
                }
            }
            if let Some((cf, co)) = self.corrupt_write_at {
                if cf == file && (off..off + data.len()).contains(&co) {
                    files[file][co] ^= 0xFF;
                }
            }
            Ok(())
        }
    }

    /// Two files (one with an odd tail), slices + recovery generated
    /// with the reference formula. Returns (files-with-present, bs,
    /// recovery, pristine bytes).
    fn mapped_fixture(
        damage: &[(usize, usize)],
    ) -> (Vec<(Par2File, Vec<bool>)>, usize, Vec<(u32, Vec<u8>)>, Vec<Vec<u8>>) {
        let bs = 64usize;
        let lens = [200usize, 97]; // 4 slices (tail 8) + 2 slices (tail 33)
        let pristine: Vec<Vec<u8>> = lens
            .iter()
            .enumerate()
            .map(|(i, &l)| payload_bytes(l, i as u64 + 10))
            .collect();
        // Global padded slices in file order.
        let mut slices: Vec<Vec<u8>> = Vec::new();
        for d in &pristine {
            for c in d.chunks(bs) {
                let mut v = c.to_vec();
                v.resize(bs, 0);
                slices.push(v);
            }
        }
        let recovery: Vec<(u32, Vec<u8>)> = (0..4u32)
            .map(|e| (e, generate_recovery(&slices, bs, e)))
            .collect();
        let mut files: Vec<(Par2File, Vec<bool>)> = Vec::new();
        for (fi, d) in pristine.iter().enumerate() {
            let n = d.len().div_ceil(bs);
            let mut present = vec![true; n];
            for &(df, di) in damage {
                if df == fi {
                    present[di] = false;
                }
            }
            files.push((
                Par2File {
                    file_id: [fi as u8; 16],
                    name: format!("f{fi}.bin"),
                    length: d.len() as u64,
                    md5: Md5::digest(d).into(),
                    md5_16k: Md5::digest(d).into(),
                    blocks: Vec::new(),
                },
                present,
            ));
        }
        (files, bs, recovery, pristine)
    }

    fn payload_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    /// The self-prove covers the WHOLE SET, not just the files that
    /// received a rebuilt block.
    ///
    /// The present-block ledger comes from verification done as the bytes
    /// ARRIVED, off the wire - never off disk. So a covered file whose
    /// bytes went bad after they were written (a failed pwrite, a bad
    /// sector) is "present" as far as this driver knows, is never
    /// rebuilt, and used to sail through a successful repair into a
    /// Completed job. The directory path never had that hole because par2
    /// reads the whole set off disk.
    #[test]
    fn mapped_driver_rereads_files_it_did_not_rebuild() {
        // IFSC checksums present, so an untouched file takes the cheap
        // per-block CRC32 path rather than MD5.
        let with_ifsc = |files: &mut Vec<(Par2File, Vec<bool>)>, pristine: &[Vec<u8>], bs: usize| {
            for ((f, _), data) in files.iter_mut().zip(pristine) {
                f.blocks = data
                    .chunks(bs)
                    .map(|c| {
                        let mut padded = c.to_vec();
                        padded.resize(bs, 0);
                        BlockCheck {
                            md5: Md5::digest(&padded).into(),
                            crc32: crc32fast::hash(&padded),
                        }
                    })
                    .collect();
            }
        };

        for full_verify in [false, true] {
            let damage = [(0usize, 1usize)];
            let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
            with_ifsc(&mut files, &pristine, bs);

            // File 0 is damaged and will be rebuilt. File 1 is untouched by
            // the repair, and goes bad on disk once the syndrome reads are
            // done - so nothing but the self-prove can notice. (Rotting it
            // up front instead would poison the reconstruction itself,
            // which is a different, already-covered failure.)
            let mut on_disk = pristine.clone();
            on_disk[0][bs..2 * bs].fill(0);
            let io = MemIo::rotting(on_disk, (1, 3));

            let got = repair_mapped(&files, bs, &recovery, &io, full_verify);
            assert!(
                matches!(&got, Err(RepairError::VerifyFailed(n)) if n == "f1.bin"),
                "a repair that left a corrupt covered file did not fail on it \
                 (full_verify={full_verify}): {got:?}"
            );
        }

        // ...and the same set with an intact file 1 still repairs, so the
        // new read is a check and not a blocker.
        let damage = [(0usize, 1usize)];
        let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
        with_ifsc(&mut files, &pristine, bs);
        let mut on_disk = pristine.clone();
        on_disk[0][bs..2 * bs].fill(0);
        let io = MemIo::new(on_disk, None);
        assert_eq!(repair_mapped(&files, bs, &recovery, &io, false).expect("repairs"), 1);
        assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
    }

    #[test]
    fn mapped_driver_rebuilds_and_self_verifies() {
        let damage = [(0usize, 1usize), (0, 3), (1, 1)]; // incl. both tails
        let (files, bs, recovery, pristine) = mapped_fixture(&damage);
        let io = MemIo::new(
            pristine
                .iter()
                .enumerate()
                .map(|(fi, d)| {
                    let mut v = d.clone();
                    // Zero the damaged blocks' bytes so a bug that skips
                    // rebuilding can't accidentally verify.
                    for &(df, di) in &damage {
                        if df == fi {
                            let s = di * bs;
                            let e = (s + bs).min(v.len());
                            v[s..e].fill(0);
                        }
                    }
                    v
                })
                .collect(),
            None,
        );
        let n = repair_mapped(&files, bs, &recovery, &io, false).expect("repairs");
        assert_eq!(n, 3);
        assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
    }

    #[test]
    fn mapped_driver_parallel_readers_many_slices() {
        // M2c.2: enough slices that every reader thread gets a real
        // contiguous chunk (chunks straddle file boundaries), varied
        // file lengths incl. a zero-length file and odd tails. Damage
        // spread across files; result must be byte-identical.
        let bs = 64usize;
        let lens = [0usize, 64 * 37 + 9, 64 * 3, 97, 64 * 41, 64 * 20 + 33];
        let pristine: Vec<Vec<u8>> = lens
            .iter()
            .enumerate()
            .map(|(i, &l)| payload_bytes(l, i as u64 + 99))
            .collect();
        let mut slices: Vec<Vec<u8>> = Vec::new();
        for d in &pristine {
            for c in d.chunks(bs) {
                let mut v = c.to_vec();
                v.resize(bs, 0);
                slices.push(v);
            }
        }
        assert!(slices.len() > 100, "fixture must exceed one reader chunk each");
        let damage: &[(usize, usize)] =
            &[(1, 0), (1, 36), (2, 1), (3, 0), (4, 40), (5, 20)];
        let recovery: Vec<(u32, Vec<u8>)> = (0..damage.len() as u32)
            .map(|e| (e, generate_recovery(&slices, bs, e)))
            .collect();
        let mut files: Vec<(Par2File, Vec<bool>)> = Vec::new();
        for (fi, d) in pristine.iter().enumerate() {
            let n = d.len().div_ceil(bs);
            let mut present = vec![true; n];
            for &(df, di) in damage {
                if df == fi {
                    present[di] = false;
                }
            }
            files.push((
                Par2File {
                    file_id: [fi as u8; 16],
                    name: format!("f{fi}.bin"),
                    length: d.len() as u64,
                    md5: Md5::digest(d).into(),
                    md5_16k: Md5::digest(d).into(),
                    blocks: Vec::new(),
                },
                present,
            ));
        }
        let io = MemIo::new(
            pristine
                .iter()
                .enumerate()
                .map(|(fi, d)| {
                    let mut v = d.clone();
                    for &(df, di) in damage {
                        if df == fi {
                            let s = di * bs;
                            let e = (s + bs).min(v.len());
                            v[s..e].fill(0);
                        }
                    }
                    v
                })
                .collect(),
            None,
        );
        let n = repair_mapped(&files, bs, &recovery, &io, false).expect("repairs");
        assert_eq!(n, damage.len());
        assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
    }

    #[test]
    fn mapped_driver_catches_a_lying_write_path() {
        let damage = [(0usize, 1usize)];
        let (files, bs, recovery, pristine) = mapped_fixture(&damage);
        let io = MemIo::new(pristine.clone(), Some((0, bs + 5))); // inside the rebuilt block
        match repair_mapped(&files, bs, &recovery, &io, false) {
            Err(RepairError::VerifyFailed(name)) => assert_eq!(name, "f0.bin"),
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn mapped_driver_rejects_short_recovery_and_bad_present_len() {
        let (files, bs, recovery, pristine) = mapped_fixture(&[(0, 0), (0, 1), (0, 2), (1, 0), (1, 1)]);
        let io = MemIo::new(pristine.clone(), None);
        // 5 missing, only 4 recovery slices.
        assert!(matches!(
            repair_mapped(&files, bs, &recovery, &io, false),
            Err(RepairError::Malformed(_))
        ));
        // Present-vector length mismatch.
        let mut bad = files.clone();
        bad[0].1.push(true);
        assert!(matches!(
            repair_mapped(&bad, bs, &recovery, &io, false),
            Err(RepairError::Malformed(_))
        ));
        // No damage at all is a no-op success.
        let clean: Vec<(Par2File, Vec<bool>)> = files
            .iter()
            .map(|(f, p)| (f.clone(), vec![true; p.len()]))
            .collect();
        assert_eq!(repair_mapped(&clean, bs, &recovery, &io, false).unwrap(), 0);
        assert_eq!(io.snapshot(), pristine, "no-op wrote nothing");
    }

    /// Every block of every mapped file missing (a single-volume set
    /// whose data articles were all lost, headers parsed, recovery
    /// plentiful): the driver must DECLINE cleanly so the caller falls
    /// back to the disk path - `work.chunks(0)` used to panic here and
    /// unwind out of the async repair.
    #[test]
    fn mapped_driver_declines_when_all_blocks_are_missing() {
        let bs = 64usize;
        let pristine = payload_bytes(200, 42); // 4 slices, odd tail
        let mut slices: Vec<Vec<u8>> = Vec::new();
        for c in pristine.chunks(bs) {
            let mut v = c.to_vec();
            v.resize(bs, 0);
            slices.push(v);
        }
        let recovery: Vec<(u32, Vec<u8>)> = (0..slices.len() as u32)
            .map(|e| (e, generate_recovery(&slices, bs, e)))
            .collect();
        let files = vec![(
            Par2File {
                file_id: [7u8; 16],
                name: "f.bin".into(),
                length: pristine.len() as u64,
                md5: Md5::digest(&pristine).into(),
                md5_16k: Md5::digest(&pristine).into(),
                blocks: Vec::new(),
            },
            vec![false; slices.len()],
        )];
        let io = MemIo::new(vec![vec![0u8; pristine.len()]], None);
        match repair_mapped(&files, bs, &recovery, &io, false) {
            Err(RepairError::Malformed(m)) => assert!(m.contains("declining"), "{m}"),
            other => panic!("expected a graceful decline, got {other:?}"),
        }
    }

    #[test]
    fn rolling_crc_matches_crc32fast_at_every_offset() {
        for &window in &[4usize, 6, 64, 1000] {
            let data: Vec<u8> = (0..2500u32)
                .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
                .collect();
            let roll = RollingCrc::new(window);
            let mut reg = 0xFFFF_FFFFu32;
            for &b in &data[..window] {
                reg = roll.push(reg, b);
            }
            assert_eq!(reg ^ !0, crc32fast::hash(&data[..window]), "w{window} o0");
            for o in 1..=data.len() - window {
                reg = roll.roll(reg, data[o - 1], data[o + window - 1]);
                assert_eq!(
                    reg ^ !0,
                    crc32fast::hash(&data[o..o + window]),
                    "window {window} offset {o}"
                );
            }
            // Virtual zero tail: rolling zeros in must equal the CRC of
            // the zero-padded final windows (the spec's padded tail).
            let mut padded = data.clone();
            padded.resize(data.len() + window - 1, 0);
            for o in data.len() - window + 1..data.len() {
                reg = roll.roll(reg, padded[o - 1], padded[o + window - 1]);
                assert_eq!(
                    reg ^ !0,
                    crc32fast::hash(&padded[o..o + window]),
                    "padded window {window} offset {o}"
                );
            }
        }
    }

    #[test]
    fn singular_matrix_is_reported() {
        // Duplicate rows are singular by construction.
        let a = vec![vec![1u16, 2], vec![1u16, 2]];
        assert!(matches!(invert(a), Err(RepairError::SingularMatrix)));
    }

    /// The structured Vandermonde inverse must equal the Gauss-Jordan
    /// inverse EXACTLY (the inverse is unique) for consecutive
    /// exponents, at small and fanned-out sizes, with and without an
    /// exponent offset e0, and on non-prefix missing sets (scattered
    /// bases). This is the differential oracle for the O(m²) path.
    #[test]
    fn vandermonde_inverse_matches_gauss_jordan() {
        for (m, e0, scatter) in [
            (1usize, 0u32, false),
            (2, 0, false),
            (5, 3, true),
            (37, 0, true),
            (PAR_INVERT_MIN + 16, 2, true),
        ] {
            // Scattered missing sets exercise non-contiguous bases.
            let logs = input_base_logs(if scatter { m * 3 } else { m }).unwrap();
            let ks: Vec<u32> = (0..m)
                .map(|i| logs[if scatter { i * 3 + 1 } else { i }])
                .collect();
            let a: Vec<Vec<u16>> = (0..m)
                .map(|r| {
                    ks.iter()
                        .map(|&k| gf16::pow2(k as u64 * (e0 as u64 + r as u64)))
                        .collect()
                })
                .collect();
            let want = invert(a).expect("PAR2-shaped matrix inverts");
            let got = invert_vandermonde(&ks, e0).expect("distinct bases cannot fail");
            assert_eq!(got, want, "m={m} e0={e0} scatter={scatter}");
        }
    }

    /// The fanned-out inversion must agree with the serial one exactly
    /// (the inverse is unique, so pivot-order differences must wash
    /// out), at a size past PAR_INVERT_MIN so the parallel path really
    /// runs. Also: a singular matrix that large must still be REPORTED,
    /// not solved wrong or deadlocked on - every worker has to leave the
    /// barrier dance on the same column.
    #[test]
    fn parallel_invert_matches_serial_and_reports_singular() {
        let m = PAR_INVERT_MIN + 32;
        let logs = input_base_logs(m).unwrap();
        let a: Vec<Vec<u16>> = (0..m)
            .map(|e| {
                (0..m)
                    .map(|j| gf16::pow2(logs[j] as u64 * e as u64))
                    .collect()
            })
            .collect();
        let par = invert(a.clone()).expect("PAR2-shaped matrix inverts");
        let ser = invert_serial(a.clone()).expect("serial agrees it inverts");
        assert_eq!(par, ser, "parallel and serial inverses must be identical");

        let mut sing = a;
        sing[m - 1] = sing[0].clone(); // duplicate row: singular
        assert!(matches!(invert(sing), Err(RepairError::SingularMatrix)));
    }
}

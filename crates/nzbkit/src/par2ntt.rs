//! Output-pruned multiplicative NTT over GF(65536) for PAR2 syndrome
//! computation - the Stage 1 flat module of the merged NTT plan
//! (`research/NTT-STAGE1-flat-module-2026-07-30.md`), relocated from the
//! research harness. EXPERIMENTAL: reachable only through par2repair's
//! disabled-by-default dispatch gate, with the streaming fold as the
//! unconditional fallback.
//!
//! Mathematical identity (differential-tested here and in the research
//! stack): PAR2's syndrome `S_e = Σ_i d_i·2^{L_i·e}` over present
//! slices with base logs L_i is exactly output `e` of the 65535-point
//! DFT (root 2) of the slice array scattered to coefficient slots L_i.
//! The multiplicative group order factors as 65535 = 3·5·17·257, so a
//! mixed-radix Cooley-Tukey with direct Rader-257 leaves applies; base
//! logs are coprime to 65535, which structurally zeroes one residue
//! class per small-prime stage (only 128 of 255 leaves run), and both
//! repair paths request the smallest exponents, so combine stages prune
//! to the `needed = max_exponent + 1` prefix.
//!
//! Shape: one immutable [`FlatPlan`] per (present set, needed) - stage
//! descriptors, live branches, Rader permutations, and every combine
//! coefficient precomputed as a raw GF value (no lookup tables at all;
//! ~1 ms at the heavy geometry). Per-worker [`Scratch`] arenas, zero
//! allocation inside a transform. The hot loops are the production
//! fused multi-source kernel ([`gf16::xor_mul_multi_into`]): each
//! Rader leaf output row is a ~n/128-source region fold, each combine
//! row a 2/4/16-source fold. Sources are pointers straight into the
//! caller's resident slices - there is no scatter step.
//!
//! Measured (2026-07-30, retained outputs, bit-verified): M1 Ultra
//! heavy leg (16384/1500/64 KiB) 0.905 s vs the shipped fold's 4.45 s.

use crate::gf16;

/// Transform length: the order of GF(65536)'s multiplicative group.
pub const N: usize = 65535;

const RADER_G: u64 = 3;
const LEAF_ROOT_LOG: u64 = 255;

/// Caller's identifier for one present slice (index into its slice
/// table); resolved to stripe data by the `src_of` callback.
pub type SrcId = u32;

struct LeafPlan {
    buf: usize,
    /// Conv sources sorted by Rader index i (a_i = x[g^{-i}]): (i, source).
    conv_sources: Vec<(u16, SrcId)>,
    /// Occupant of local slot 0, if present (participates in X[0] and
    /// is XORed into every conv output).
    x0: Option<SrcId>,
}

struct CombinePlan {
    buf: usize,
    /// Output rows (min(needed, node size)).
    rows: usize,
    /// Child DFT length (row index into child buffers is k % q).
    q: usize,
    /// Live children buffer slots at depth+1, in class order.
    children: Vec<usize>,
    /// Raw GF coefficients, rows-major: coeffs[k*children.len() + j]
    /// = 2^{root_log · u_j · k}.
    coeffs: Vec<u16>,
    child_nodes: Vec<Node>,
}

enum Node {
    Leaf(LeafPlan),
    Combine(CombinePlan),
}

/// Immutable transform plan for one (present set, requested prefix).
pub struct FlatPlan {
    root: Node,
    g_pow: [usize; 256],
    /// b[t] = 2^{255·g^t} - the fixed Rader kernel, raw values.
    kernel: [u16; 256],
    /// Rows the root produces: max selected exponent + 1.
    pub needed: usize,
}

/// Per-worker scratch arenas: one pool per tree depth, reused across
/// stripes. Allocated once per worker outside any timed/hot region.
pub struct Scratch {
    w: usize,
    leaf: Vec<u16>,   // 17 slots x 257 rows
    depth2: Vec<u16>, // 5 slots x min(needed, 4369) rows
    rows2: usize,
    depth1: Vec<u16>, // 3 slots x min(needed, 21845) rows
    rows1: usize,
}

impl FlatPlan {
    /// Build the plan. `present` maps base logs to caller slice ids;
    /// `needed` is max selected exponent + 1. Fails (so the caller can
    /// fall back to the fold) on empty input, out-of-range logs or
    /// exponents, and duplicate logs - a duplicate feed is representable
    /// by the XOR-accumulating fold but not by coefficient slots.
    pub fn build(present: &[(u32, SrcId)], needed: usize) -> Result<FlatPlan, String> {
        if present.is_empty() {
            return Err("empty present set".into());
        }
        if needed == 0 || needed > N {
            return Err(format!("needed {needed} out of range"));
        }
        let mut g_pow = [0usize; 256];
        let mut g_inv_pow = [0usize; 256];
        let mut v = 1u64;
        for i in 0..256 {
            g_pow[i] = v as usize;
            g_inv_pow[(256 - i) % 256] = v as usize;
            v = v * RADER_G % 257;
        }
        let mut ip = [0u16; 257];
        for (i, &s) in g_inv_pow.iter().enumerate() {
            ip[s] = i as u16;
        }
        let mut kernel = [0u16; 256];
        for t in 0..256 {
            kernel[t] = gf16::pow2(LEAF_ROOT_LOG * g_pow[t] as u64 % N as u64);
        }
        let mut slots: Vec<Option<SrcId>> = vec![None; N];
        for &(log, src) in present {
            if log as usize >= N {
                return Err(format!("base log {log} out of range"));
            }
            let slot = &mut slots[log as usize];
            if slot.is_some() {
                return Err(format!("duplicate base log {log}"));
            }
            *slot = Some(src);
        }
        let root = build_node(&slots, 1, needed, 0, &ip).expect("nonempty set built no tree");
        Ok(FlatPlan { root, g_pow, kernel, needed })
    }

    pub fn new_scratch(&self, w: usize) -> Scratch {
        let rows2 = self.needed.min(4369);
        let rows1 = self.needed.min(21845);
        Scratch {
            w,
            leaf: vec![0u16; 17 * 257 * w],
            rows2,
            depth2: vec![0u16; 5 * rows2 * w],
            rows1,
            depth1: vec![0u16; 3 * rows1 * w],
        }
    }

    /// Bytes ONE worker allocates at stripe width `w`: everything
    /// [`Self::new_scratch`] reserves, plus that worker's `needed * w`
    /// output rows.
    ///
    /// An associated function because the repair dispatcher has to price
    /// this BEFORE a plan exists. Keep the pool clamps in step with
    /// `new_scratch` directly above - they are the same numbers, and the
    /// admission gate is only as honest as this estimate.
    pub fn scratch_bytes(needed: usize, w: usize) -> usize {
        (17 * 257 + 5 * needed.min(4369) + 3 * needed.min(21845) + needed)
            .saturating_mul(w)
            .saturating_mul(2)
    }

    /// Transform one stripe of `w` words. `src_of` resolves a SrcId to
    /// the stripe's byte pointer (at least `2*w` readable bytes).
    /// Writes syndrome rows 0..needed, rows-major, into `out`
    /// (needed*w words). No allocation inside.
    pub fn transform(
        &self,
        src_of: &dyn Fn(SrcId) -> *const u8,
        w: usize,
        scratch: &mut Scratch,
        out: &mut [u16],
    ) {
        assert!(scratch.w >= w, "scratch narrower than stripe");
        assert!(out.len() >= self.needed * w);
        eval(&self.root, self, src_of, w, 0, scratch as *mut Scratch, out);
    }
}

/// Recursive plan builder mirroring the differential-tested prototype's
/// decimation exactly. Returns None for structurally dead subtrees.
fn build_node(
    slots: &[Option<SrcId>],
    root_log: u64,
    needed: usize,
    buf: usize,
    ip: &[u16; 257],
) -> Option<Node> {
    let n = slots.len();
    if slots.iter().all(|s| s.is_none()) {
        return None;
    }
    if n == 257 {
        debug_assert_eq!(root_log % N as u64, LEAF_ROOT_LOG);
        let mut conv_sources: Vec<(u16, SrcId)> = Vec::new();
        for (s, slot) in slots.iter().enumerate().skip(1) {
            if let Some(src) = slot {
                conv_sources.push((ip[s], *src));
            }
        }
        conv_sources.sort_unstable();
        return Some(Node::Leaf(LeafPlan { buf, conv_sources, x0: slots[0] }));
    }
    let p = [3usize, 5, 17].iter().copied().find(|p| n % p == 0).expect("bad node size");
    let q = n / p;
    let sub_needed = needed.min(q);
    let mut children = Vec::new();
    let mut child_nodes = Vec::new();
    let mut lives = Vec::new();
    for u in 0..p {
        let class: Vec<Option<SrcId>> = slots.iter().skip(u).step_by(p).copied().collect();
        debug_assert_eq!(class.len(), q);
        if let Some(node) = build_node(&class, root_log * p as u64, sub_needed, children.len(), ip)
        {
            children.push(child_buf(&node));
            child_nodes.push(node);
            lives.push(u);
        }
    }
    let rows = needed.min(n);
    let mut coeffs = vec![0u16; rows * lives.len()];
    for k in 0..rows {
        for (j, &u) in lives.iter().enumerate() {
            coeffs[k * lives.len() + j] =
                gf16::pow2(root_log * (u as u64) * (k as u64) % N as u64);
        }
    }
    Some(Node::Combine(CombinePlan { buf, rows, q, children, coeffs, child_nodes }))
}

fn child_buf(n: &Node) -> usize {
    match n {
        Node::Leaf(l) => l.buf,
        Node::Combine(c) => c.buf,
    }
}

/// Fused multi-source fold with scalar tail: dst ^= Σ coeff_j·src_j.
/// Groups of 8 hit the kernel's monomorphized path; the group array is
/// on the stack - no allocation.
fn fold_into(dst: &mut [u16], srcs: &[*const u8], coeffs: &[u16], w: usize) {
    debug_assert_eq!(srcs.len(), coeffs.len());
    let mut g = 0;
    while g < srcs.len() {
        let cnt = (srcs.len() - g).min(8);
        let mut group: [&[u8]; 8] = [&[]; 8];
        for (t, &p) in srcs[g..g + cnt].iter().enumerate() {
            group[t] = unsafe { std::slice::from_raw_parts(p, w * 2) };
        }
        let done = gf16::xor_mul_multi_into(&mut dst[..w], &group[..cnt], &coeffs[g..g + cnt]);
        if done < w {
            // Scalar tail; also the whole fold when no fused kernel
            // exists or the stripe is narrower than one kernel granule.
            for (src, &c) in group[..cnt].iter().zip(&coeffs[g..g + cnt]) {
                for t in done..w {
                    let word = u16::from_le_bytes([src[t * 2], src[t * 2 + 1]]);
                    dst[t] ^= gf16::mul(c, word);
                }
            }
        }
        g += cnt;
    }
}

/// Post-order evaluation. Children write into the next depth's pool;
/// sibling slots are disjoint by construction and cousins reuse them
/// only after the parent has consumed its children (depth-first order),
/// so the raw pool pointer never aliases a live borrow.
fn eval(
    node: &Node,
    plan: &FlatPlan,
    src_of: &dyn Fn(SrcId) -> *const u8,
    w: usize,
    depth: usize,
    scratch: *mut Scratch,
    out: &mut [u16],
) {
    match node {
        Node::Leaf(leaf) => {
            debug_assert!(out.len() >= 257 * w);
            let mut ptrs: Vec<*const u8> = Vec::with_capacity(leaf.conv_sources.len() + 1);
            let mut ones: Vec<u16> = Vec::with_capacity(leaf.conv_sources.len() + 1);
            if let Some(x0) = leaf.x0 {
                ptrs.push(src_of(x0));
                ones.push(1);
            }
            for &(_, src) in &leaf.conv_sources {
                ptrs.push(src_of(src));
                ones.push(1);
            }
            out[..257 * w].fill(0);
            // X[0] = x[0] + every conv source, coefficient 1.
            fold_into(&mut out[..w], &ptrs, &ones, w);
            // X[g^m] = x[0] + Σ_i a_i · b[(m-i) mod 256].
            let x0_ptr = leaf.x0.map(|s| src_of(s));
            let mut cptrs: Vec<*const u8> = Vec::with_capacity(leaf.conv_sources.len() + 1);
            let mut cco: Vec<u16> = Vec::with_capacity(leaf.conv_sources.len() + 1);
            for &(_, src) in &leaf.conv_sources {
                cptrs.push(src_of(src));
            }
            if let Some(p0) = x0_ptr {
                cptrs.push(p0);
            }
            for m in 0..256usize {
                cco.clear();
                for &(i, _) in &leaf.conv_sources {
                    cco.push(plan.kernel[(m + 256 - i as usize) & 255]);
                }
                if x0_ptr.is_some() {
                    cco.push(1);
                }
                let row = plan.g_pow[m];
                fold_into(&mut out[row * w..row * w + w], &cptrs, &cco, w);
            }
        }
        Node::Combine(c) => {
            let (child_pool, child_rows): (*mut u16, usize) = unsafe {
                match depth {
                    0 => ((*scratch).depth1.as_mut_ptr(), (*scratch).rows1),
                    1 => ((*scratch).depth2.as_mut_ptr(), (*scratch).rows2),
                    2 => ((*scratch).leaf.as_mut_ptr(), 257),
                    _ => unreachable!(),
                }
            };
            for child in &c.child_nodes {
                let b = child_buf(child);
                let cbuf = unsafe {
                    std::slice::from_raw_parts_mut(
                        child_pool.add(b * child_rows * w),
                        child_rows * w,
                    )
                };
                eval(child, plan, src_of, w, depth + 1, scratch, cbuf);
            }
            // out[k] = Σ_j coeff(k,j) · child_j[k mod q].
            let nc = c.children.len();
            let mut srcs: Vec<*const u8> = vec![std::ptr::null(); nc];
            out[..c.rows * w].fill(0);
            for k in 0..c.rows {
                let s = k % c.q;
                for (j, &b) in c.children.iter().enumerate() {
                    srcs[j] =
                        unsafe { child_pool.add(b * child_rows * w + s * w) as *const u8 };
                }
                let co = &c.coeffs[k * nc..(k + 1) * nc];
                fold_into(&mut out[k * w..k * w + w], &srcs, co, w);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn word(&mut self) -> u16 {
            (self.next() >> 32) as u16
        }
    }

    /// The n smallest naturals coprime to 65535 (the product's
    /// input_base_logs, replicated to keep this module self-contained).
    fn logs(n: usize) -> Vec<u32> {
        let mut out = Vec::with_capacity(n);
        let mut k = 0u32;
        while out.len() < n {
            k += 1;
            if k % 3 != 0 && k % 5 != 0 && k % 17 != 0 && k % 257 != 0 {
                out.push(k);
            }
        }
        out
    }

    /// Reference syndrome, accumulated exactly the way the shipped fold
    /// does (same tables, same xor path).
    fn syndrome_ref(present: &[(u32, Vec<u16>)], e: u32, w: usize) -> Vec<u16> {
        let mut s = vec![0u16; w];
        for (log, data) in present {
            let t = gf16::MulTable::new(gf16::pow2(*log as u64 * e as u64 % N as u64));
            t.xor_mul_words(&mut s, data);
        }
        s
    }

    fn run_case(n_slices: usize, holes: usize, w: usize, needed: usize, seed: u64) {
        let all = logs(n_slices);
        let mut rng = Rng(seed);
        let mut present: Vec<(u32, Vec<u16>)> = Vec::new();
        for (i, &log) in all.iter().enumerate() {
            if i % holes == 0 {
                continue;
            }
            present.push((log, (0..w).map(|_| rng.word()).collect()));
        }
        let ids: Vec<(u32, SrcId)> =
            present.iter().enumerate().map(|(i, (l, _))| (*l, i as SrcId)).collect();
        let plan = FlatPlan::build(&ids, needed).unwrap();
        let mut scratch = plan.new_scratch(w);
        let mut out = vec![0u16; needed * w];
        let src_of = |s: SrcId| present[s as usize].1.as_ptr() as *const u8;
        plan.transform(&src_of, w, &mut scratch, &mut out);
        for e in 0..needed {
            let want = syndrome_ref(&present, e as u32, w);
            assert_eq!(&out[e * w..(e + 1) * w], &want[..], "e={e} w={w}");
        }
    }

    #[test]
    fn matches_fold_reference_scalar_width() {
        // w=8 is below the fused kernel's granule: full scalar path.
        run_case(500, 7, 8, 80, 0xA5);
    }

    #[test]
    fn matches_fold_reference_kernel_width() {
        // w=64 exercises the fused kernel; needed past 257 exercises the
        // leaf-row wraparound in the combine stages.
        run_case(2500, 11, 64, 300, 0x51);
    }

    #[test]
    fn build_rejects_bad_input() {
        assert!(FlatPlan::build(&[], 10).is_err());
        assert!(FlatPlan::build(&[(1, 0)], 0).is_err());
        assert!(FlatPlan::build(&[(1, 0)], N + 1).is_err());
        assert!(FlatPlan::build(&[(65535, 0)], 10).is_err());
        assert!(FlatPlan::build(&[(1, 0), (1, 1)], 10).is_err(), "duplicate log");
    }
}

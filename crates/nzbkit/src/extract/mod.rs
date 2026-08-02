//! Store-mode direct extraction (design: M3): decoded article spans are
//! written straight into the *extracted* files; RAR volumes never touch
//! disk on the happy path.
//!
//! The extractor owns all data-file writing in `get`:
//! - A slot is sniffed at its offset-0 article: RAR signature → mapping
//!   mode; anything else → plain mode (ordinary file, exactly the old
//!   behavior). Pre-sniff spans are held in memory (bounded).
//! - Mapping mode feeds the volume's [`VolumeMapper`]; spans intersecting
//!   known data areas `pwrite` into the inner file at
//!   `piece_base + offset_in_piece`; spans beyond the parsed region are
//!   held until more headers arrive.
//! - Volumes group by their FIRST inner-file name - obfuscation-proof
//!   (subjects lie, archive contents don't). Order within a group comes
//!   from RAR5 volume numbers, falling back to natural name sort
//!   (.partNN.rar, .rar < .r00 < .r01).
//! - Non-split pieces extract immediately (base 0); split continuations
//!   wait for every earlier volume's piece length (base resolution).
//! - Any blocker (compressed, encrypted, corrupt, holds cap) falls the
//!   whole group back to materialized volumes - already-extracted bytes
//!   are reconstructed into the volume files via the map, so nothing is
//!   lost and PAR2 repair sees ordinary files. The holds cap gets one
//!   relief valve first: held spans page to a scratch file
//!   ([`HoldSpan`]/[`HoldsScratch`]) and the set stays one-pass; only a
//!   breach of the scratch ceiling too demotes.
//! - [`Extractor::read_at`] serves byte-exact volume reads for the live
//!   verifier's read-back path (header stash + inner-file pread), so
//!   in-stream PAR2 verification of the *volume* blocks works even though
//!   volumes were never written.
//! - Nested store archives (a store-mode RAR whose payload is itself a
//!   store-mode RAR) route through a lazily-created CHILD extractor: each
//!   level-1 inner file becomes a dynamically-allocated child slot, and
//!   the child's own offset-0 sniff classifies it - RAR store magic means
//!   nested mapping (the inner archive never touches disk either), while
//!   anything else goes Plain (a real file, byte-identical to the
//!   single-level output). Read-back and coverage compose by delegation,
//!   so verifier settle, mapped repair, and fallback materialization keep
//!   working unchanged. Depth-capped; any blocker at a nested level
//!   demotes that level to a materialized file, never a failure.
//! - COMPRESSED RAR5 nested archives decompress while their bytes arrive
//!   (the chasing decompressor): the chased slot's spans feed a frontier
//!   buffer, a worker drives the RAR engine's streaming reader over the
//!   group's volumes in order, and extracted members route back through
//!   the same child seam - so store archives below a compressed layer
//!   still stream. Any chase failure demotes to the materialize path.
//! - 7z nested archives extract in-stream via tail prefetch: a child slot
//!   sniffing 7z magic parses the 32-byte start header, asks the promote
//!   hook to front-load the articles carrying the end header (the archive
//!   map lives at the tail), and a worker drives the 7z engine through a
//!   blocking Read+Seek view of the arriving bytes - entries stream into
//!   fresh child slots (the same routing seam). Header-encrypted without
//!   a password, unsupported codecs, budget breach, and missing bytes all
//!   demote to a materialized .7z for the disk post-pass.

use crate::sync::MutexExt;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};

use crate::disk::{FileWriter, sanitize_filename};
use crate::rar::{ArchiveMap, ArithGate, EntryCrypt, MapBlocker, Method, RarVersion, VolumeMapper};
use crate::rarcrypt;

mod chase;
mod config;
mod crypto;
mod frontier;
mod holds;
mod reader;
mod settle;
mod sevenz;
#[cfg(test)]
mod testutil;
mod zip;

use chase::*;
use config::*;
pub use config::{
    nested_depth_cap, prefer_external_unrar, set_nested_depth_cap, set_prefer_external_unrar,
};
use crypto::*;
pub use crypto::{CryptoJournalEvent, StreamCrypt, StreamOpen};
use frontier::*;
use holds::*;
use settle::*;
use sevenz::*;

/// Reason prefix for a demote of a TOP-LEVEL 7z chase. The archive
/// materializes into the output directory, which is precisely the disk
/// post-pass's input, so the demote is owned - the caller must keep it
/// out of the RAR unpack ladder (handing a directory holding one .7z to
/// unrar fails a job that is fine). The underlying reason, "held-bytes
/// cap: chase memory" included, stays readable inside the string.
pub const SEVENZ_DISK_FALLBACK_PREFIX: &str = "7z materialized for the disk pass: ";

/// [`SEVENZ_DISK_FALLBACK_PREFIX`]'s zip twin: a demoted top-level zip
/// chase leaves a `.zip` the disk post-pass owns (its ladder step 5),
/// and its reason text must stay out of the RAR unpack ladder for the
/// same three-arms-all-wrong reason.
pub const ZIP_DISK_FALLBACK_PREFIX: &str = "zip materialized for the disk pass: ";

/// Article-promotion hook (nested 7z tail prefetch, offset-0 probe):
/// `(output name, file size, byte spans, urgent)` of a file at THIS
/// extractor's level - the daemon wires the root's hook to its
/// seek/promote ladder, which front-loads the pending articles carrying
/// those bytes. `urgent` promotes may also flip the pool into stream
/// mode (shallow pipelines, 60 s linger) because a worker is BLOCKED on
/// the bytes (the 7z chase reading its footer); non-urgent ones (the
/// offset-0 classification probe) just reorder the queue - a scrambled
/// many-volume set probes once per slot, and stream mode for the whole
/// download would cost real throughput on long links.
pub type PromoteHook = Arc<dyn Fn(&str, u64, &[(u64, u64)], bool) + Send + Sync>;

/// Permission to publish decrypted plaintext over the named outputs.
///
/// The finish decrypt turns an encrypted store output from the ciphertext
/// the crash-resume journal recorded into plaintext. Those two facts -
/// "this file has been mutated" and "the journal still claims it is a
/// faithful copy" - must never both be true on disk at once, so the
/// extractor asks first and publishes nothing until the hook returns `Ok`
/// (main.rs wires it to `journal::Journal::invalidate`, which is durable
/// before it returns). Unwired (tests, the CLI re-extract pass), there is
/// no journal to poison and the publish proceeds.
pub type DecryptBarrier = Arc<dyn Fn(&[String]) -> io::Result<()> + Send + Sync>;

/// Strip release-file suffixes down to the shared stem:
/// `x.part01.rar`/`x.r00`/`x.vol000+01.par2`/`x.par2`/`x.rar` → `x`,
/// and split-container volumes `x.7z.001`/`x.zip.001` → `x.7z`/`x.zip`
/// (the container extension stays: it is the shared base every part
/// and its par2 sidecar reduce to, mirroring `sevenz_part_name`).
///
/// The split rule exists because without it a 100-part obfuscated 7z
/// set indexes as 100 half-GB "releases" - found live 2 Aug 2026 via
/// the Supergirl acceptance case (122 rows, 67 GB) - which hides the
/// set's true size from everything that reasons about it.
pub fn release_stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut end = lower.len();
    let cut = |s: &str, end: usize, f: &dyn Fn(&str) -> Option<usize>| -> usize {
        f(&s[..end]).unwrap_or(end)
    };
    end = cut(&lower, end, &|s| s.strip_suffix(".par2").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        let vol = s.rfind(".vol")?;
        let tail = &s[vol + 4..];
        // par2cmdline "vol01+02" or range-style "vol001-003".
        let (a, b) = tail.split_once(['+', '-'])?;
        (!a.is_empty()
            && a.bytes().all(|c| c.is_ascii_digit())
            && !b.is_empty()
            && b.bytes().all(|c| c.is_ascii_digit()))
        .then_some(vol)
    });
    end = cut(&lower, end, &|s| {
        // Split-container volume: 3-4 digit tail (7-Zip names volumes
        // `%s.%03d`, four digits past 999 - same bounds as
        // `sevenz_part_name`) directly after a container extension.
        // One and two digits stay: `Track.01` is somebody's music.
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        if tail.len() < 3 || tail.len() > 4 || !tail.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let head = &s[..p];
        (head.ends_with(".7z") || head.ends_with(".zip")).then_some(p)
    });
    end = cut(&lower, end, &|s| s.strip_suffix(".rar").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        let p = s.rfind(".part")?;
        let tail = &s[p + 5..];
        (!tail.is_empty() && tail.bytes().all(|c| c.is_ascii_digit())).then_some(p)
    });
    end = cut(&lower, end, &|s| {
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        // Old-style continuations roll past .r99 into .s00 … .z99 (and
        // vol_sort_key already orders that whole range) - accepting only
        // r/s here left .t00+ volumes with their extension in the stem,
        // splitting 200+ volume sets across "releases" and starving the
        // repair path's stem filter of everything past .s99.
        (tail.len() >= 2
            && (b'r'..=b'z').contains(&tail.as_bytes()[0])
            && tail[1..].bytes().all(|c| c.is_ascii_digit()))
        .then_some(p)
    });
    name[..end].to_string()
}

/// Natural volume order key: `.rar` < `.r00` < `.r01`; `.part1` < `.part2`.
pub fn vol_sort_key(name: &str) -> (u64, String) {
    let lower = name.to_ascii_lowercase();
    if let Some(p) = lower.rfind(".part") {
        let tail = &lower[p + 5..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u64>() {
            return (n, lower.clone());
        }
    }
    if lower.ends_with(".rar") {
        return (0, lower.clone());
    }
    if let Some(p) = lower.rfind('.') {
        let tail = &lower[p + 1..];
        // Old-style continuations roll the letter past .r99: .s00 = 101,
        // .t00 = 201… (each letter is another 10^digits volumes). Keying
        // only 'r' broke base-resolution at the r→s boundary on 100+
        // volume sets.
        if tail.len() >= 2
            && (b'r'..=b'z').contains(&tail.as_bytes()[0])
            && let Ok(n) = tail[1..].parse::<u64>()
        {
            let span = 10u64.pow((tail.len() - 1) as u32);
            return (
                (tail.as_bytes()[0] - b'r') as u64 * span + n + 1,
                lower.clone(),
            );
        }
        // WinRAR numeric volume naming: .001, .002 …
        if tail.len() >= 2
            && tail.bytes().all(|c| c.is_ascii_digit())
            && let Ok(n) = tail.parse::<u64>()
        {
            return (n, lower.clone());
        }
    }
    (u64::MAX, lower)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotMode {
    /// Waiting for the offset-0 article to sniff.
    Unknown,
    /// Ordinary file - write through.
    Plain,
    /// RAR volume in mapping mode.
    Rar,
    /// Compressed RAR5 volume being chased: spans feed the slot's
    /// frontier buffer, the chase worker decodes behind the frontier.
    RarChase,
    /// Inner 7z archive being chased (child slots only): spans feed the
    /// slot's frontier buffer, the 7z worker parses/decodes through a
    /// blocking Read+Seek view (footer first, via tail prefetch).
    SevenZ,
    /// RAR volume after fallback - volume file materialized.
    RarFallback,
    /// Source-protected fallback: the slot's bytes already live in a real
    /// file the caller owns (re-extraction reads volumes off disk), so a
    /// fallback must never materialize - writes are dropped instead.
    Discard,
}

struct Slot {
    mode: SlotMode,
    name: String,
    size: u64,
    /// `vol_sort_key(&name)`, computed once - `reresolve` runs per volume
    /// arrival over EVERY group slot, and recomputing the key allocated
    /// 2-3 Strings per slot per call (quadratic on many-volume sets).
    sort_key: Option<(u64, String)>,
    /// Pre-sniff / unmappable spans (RAM or paged to scratch).
    holds: Vec<(u64, HoldSpan)>,
    /// Bytes held while still Unknown (pre-classification). Bounded by
    /// the per-slot spill: an NZB with synthesized segment numbering
    /// ("segment 1" is not the yEnc offset-0 article - seen live on a
    /// fully-obfuscated 9.6 GB single-file post) would otherwise hold the
    /// entire file in RAM waiting for a sniff that may come last.
    pre_bytes: usize,
    /// The offset-0 probe already went out: the FIRST out-of-order span
    /// asks the promote hook to front-load the article carrying offset 0
    /// (see the hold branch in `write_impl_scratched`). Once per slot -
    /// a wrong guess never re-arms; `spill_unclassified_slot` stays the
    /// backstop for posts whose offset 0 genuinely never comes early.
    probe0_sent: bool,
    /// Plain-file or materialized-volume writer.
    writer: Option<Arc<FileWriter>>,
    mapper: Option<VolumeMapper>,
    /// Raw header/meta bytes (offset, bytes) kept for reconstruction
    /// (RAM or paged to scratch, like `holds`).
    header_spans: Vec<(u64, HoldSpan)>,
    /// Canonical group key (the archive's identity), set once entries
    /// parse. Groups start keyed by a volume's first inner-file name and
    /// merge when split pieces prove two keys are one archive.
    group: Option<String>,
    /// Chase attachment (modes RarChase and SevenZ): the slot's
    /// in-flight bytes.
    chase: Option<ChaseSlot>,
    /// 7z chase control (mode SevenZ): the worker and its sink slots.
    sevenz: Option<Arc<SevenZCtl>>,
    /// Which container format the SevenZ-mode chase is driving (see
    /// [`ChaseFormat`]). Set at attach; meaningless outside that mode.
    container_fmt: ChaseFormat,
    /// Entry index → composed CRC32 of the routed piece bytes, for the
    /// finish-time check against the RAR5 header CRC. That check is the
    /// only verifier a store payload has - the download's PAR2 vouches
    /// for the OUTER bytes as posted, damage the poster packed in
    /// included. Nested levels always compose; level 0 composes under
    /// the verify_output_crc gate.
    piece_crcs: HashMap<usize, CrcRuns>,
    /// Increment A (one-pass encrypted plan): the mapper hit a
    /// password-shaped blocker while a candidate probe may still find
    /// the password (a sidecar in this very NZB, the release stem).
    /// While set, spans park in `holds` (same budget, same read_at
    /// visibility) instead of demoting; a Verified probe hit rebuilds
    /// the mapper keyed and re-feeds them, a miss demotes through the
    /// exact path this state deferred - the stored reason keeps the
    /// finish ladder's remediation keyed the same either way.
    pw_await: Option<&'static str>,
}

struct Group {
    slots: Vec<usize>,
    /// (slot, entry) → inner-file base offset, rebuilt as mappers progress.
    bases: HashMap<(usize, usize), u64>,
    /// (slot count, numbered-mapper count, total parsed entries) at the
    /// last `reresolve` recompute. Order and bases are pure functions of
    /// these, so an unchanged stamp skips the sort + resolve entirely -
    /// `reresolve` fires on every parse progression, roughly twice per
    /// volume, and recomputing from scratch each time was O(V^2) per set.
    resolve_stamp: Option<(usize, usize, u64)>,
    /// (slot, entry) bases placed by the ARITHMETIC gate (uniform
    /// single-file store sets, `ArchiveMap::resolve_arithmetic`) that
    /// nothing else has confirmed yet: valid under the uniform premise,
    /// but beyond what chain resolution has reached. Confirmed (removed)
    /// when the chain independently derives the same value or when the
    /// complete set closes at settle; a contradiction, or leftovers at
    /// settle, demote the whole group ("non-uniform store set"). Bytes
    /// may already sit at these offsets, so an entry here must keep its
    /// value in `bases` until confirmed or demoted - fallback read-back
    /// reconstructs volumes through the base each byte was WRITTEN under.
    arith_provisional: HashMap<(usize, usize), u64>,
    /// Latched when the arithmetic gate ever placed beyond the chain -
    /// test introspection (the multi-file regression asserts it stays
    /// unset on the chain path).
    arith_ever: bool,
    fallback: bool,
    fallback_reason: Option<String>,
    /// sanitized inner-file name → actual output filename. Output files
    /// are OWNED by their group: another archive in the same NZB reusing
    /// an inner name gets its own (disambiguated) file, and a fallback
    /// deletes only the files listed here - never another group's.
    out_names: HashMap<String, String>,
    /// raw inner-file name → the child's stable Plain writer (Finding 4):
    /// once a routed child classifies as Plain that mode never changes, so
    /// later articles write straight to its file from the parent's job
    /// drain instead of walking the parent-lock / child-lock /
    /// revalidation ladder per article. `routed` stays authoritative for
    /// fallback, finish, and merge; this cache is cleared whenever those
    /// paths touch the route, and the post-write RarFallback recheck in
    /// write_impl still guards the race.
    routed_plain: HashMap<String, (usize, Arc<FileWriter>)>,
    /// sanitized inner-file name → CHILD slot, for inner files routed
    /// into the nested child extractor. Group-owned for the same reason
    /// as `out_names`: two archives reusing an inner name must not share
    /// a destination, and a fallback abandons only its own child slots.
    routed: HashMap<String, usize>,
    /// Live chasing decompressor over this group's volumes (compressed
    /// RAR5 inner archive). Cleared at finish once the worker is joined.
    chase: Option<Arc<ChaseCtl>>,
}

pub struct ExtractReport {
    /// Inner files written via direct extraction (name, size).
    pub extracted: Vec<(String, u64)>,
    /// Groups that fell back to materialized volumes (key, why).
    pub fallbacks: Vec<(String, String)>,
    /// Bytes that went through the direct-extraction path.
    pub extracted_bytes: u64,
    /// Extracted files that were AES-decrypted in place at finish
    /// (encrypted RAR5 store sets - no unrar involved).
    pub decrypted: Vec<String>,
}

/// Where one piece of an article's decoded bytes landed on disk: `len`
/// bytes at `file_off` of `file` (a name in the out dir), carrying the
/// volume-view bytes at `vol_off` (article yEnc offset + span offset).
/// The crash-resume journal records these so a later run can rebuild the
/// volume file from wherever the bytes physically went - identity for
/// plain files, translated for direct-extracted inner files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frag {
    pub file: String,
    pub file_off: u64,
    pub vol_off: u64,
    pub len: u64,
}

/// What [`Extractor::write`] did with a span, for the crash-resume
/// journal. `Placed` means EVERY byte of the article is durably on disk
/// at the recorded fragments - the only state a plain `R` record may
/// describe. `PlacedCrypto` is the same coverage claim for a span that
/// fed an in-stream-decrypted (plaintext-once) file: what is on disk is
/// PLAINTEXT, so it journals as a `D` record that a resume can only
/// honor by re-encrypting through the file's journaled `E`/`K`/`T`
/// facts - an old binary parses `D` as an unknown message-id and simply
/// refetches. Held spans, header bytes retained in memory, and
/// discarded spans return `No`.
pub enum Persist {
    No,
    Placed(Vec<Frag>),
    PlacedCrypto(Vec<Frag>),
}

// ---- Phase 0(b): nested-archive prevalence instrumentation ----
//
// Learn real-world nesting prevalence from live daemons and testers.
// Every nested level processed (an archive INSIDE another archive - depth
// > 0) emits one concise, greppable log line and bumps a process-global
// tally the daemon stats API can surface. A single-layer job (depth 0)
// never reaches this path, so the common case pays nothing. Two paths
// feed the ONE counter set: the in-stream child extractor here (store /
// chase / 7z inners that stream in RAM) and the disk post-pass in nzbfast
// (materialized inners the stream demoted, plus never-streamed shapes
// like RAR4 and resumed jobs).
//
// Counting model (kept consistent across both call sites so a demoted
// inner is never double-counted):
//   * an inner that STAYS in-stream          -> `in_stream` (this crate)
//   * an inner handled by the disk post-pass -> `disk`      (nzbfast)
//   * an in-stream attempt that DEMOTES      -> `demoted` only
// A demoted inner materializes and is then re-extracted by the disk
// post-pass, where it is tallied once under `disk`; the `demoted` bump is
// a diagnostic that records WHY a `disk` line exists. Hence the invariant
// `levels == in_stream + disk`, with `demoted <= disk`.

static NESTED_LEVELS: AtomicU64 = AtomicU64::new(0);
static NESTED_IN_STREAM: AtomicU64 = AtomicU64::new(0);
static NESTED_DEMOTED: AtomicU64 = AtomicU64::new(0);
static NESTED_DISK: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_STORE: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_COMPRESSED: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_ENCRYPTED: AtomicU64 = AtomicU64::new(0);
static NESTED_SEVENZ: AtomicU64 = AtomicU64::new(0);
static NESTED_OTHER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Archive shape: what the set turned out to BE, published live.
//
// The mappers already learn every fact here the moment a volume's headers
// parse - RAR version, per-entry method, encryption - and the routing
// decisions know whether the bytes are being extracted as they arrive or
// materialized for a disk unpack. None of it used to leave the extractor
// before finish(). The latch below collects it into a small token list
// the daemon can poll mid-download and the dashboard can translate.
//
// Bits are LATCHED, never cleared: a set that starts on the fast path and
// later demotes reads as "partly on disk", which is what actually
// happened. One latch is shared by a whole extractor chain, with nested
// levels writing a separate word, so an inner 7z inside a RAR5 store set
// shows up as "7z inside" rather than overwriting the outer format.
// ---------------------------------------------------------------------------

const SH_RAR4: u32 = 1 << 0;
const SH_RAR5: u32 = 1 << 1;
const SH_7Z: u32 = 1 << 2;
const SH_STORE: u32 = 1 << 3;
const SH_COMPRESSED: u32 = 1 << 4;
const SH_ENCRYPTED: u32 = 1 << 5;
/// Encrypted content that decrypts at write time (plaintext-once) rather
/// than being assembled as ciphertext for the finish pass.
const SH_ENC_INSTREAM: u32 = 1 << 6;
/// At least one inner file was routed to direct extraction.
const SH_ONE_PASS: u32 = 1 << 7;
/// At least one group/slot fell back to volumes on disk.
const SH_MATERIALIZED: u32 = 1 << 8;
/// The outer container is a zip (one-pass zip, phase 2).
const SH_ZIP: u32 = 1 << 9;

/// Shared observations for one extractor chain (see the section note).
#[derive(Default)]
struct ShapeLatch {
    outer: AtomicU32,
    nested: AtomicU32,
    /// The first whole-file CRC32 an inner entry's header stated, with
    /// the entry's name. Latched from the same parse the shape bits come
    /// from, because it is the same fact: what the archive says it
    /// contains.
    ///
    /// It rides here rather than in a field of its own so a nested level
    /// contributes to it without a second Arc through `build` - and
    /// because a naming oracle wants the OUTERMOST content it can get, a
    /// first-writer-wins latch is the right shape as well as the cheap
    /// one.
    crc: Mutex<Option<(String, u32)>>,
}

impl ShapeLatch {
    fn note(&self, depth: usize, bits: u32) {
        let w = if depth == 0 {
            &self.outer
        } else {
            &self.nested
        };
        w.fetch_or(bits, Ordering::Relaxed);
    }

    /// First writer wins: the volumes of one set repeat their entries in
    /// every header, and re-latching would just churn the lock at line
    /// rate for the same answer.
    fn note_crc(&self, name: &str, crc: u32) {
        let mut g = self.crc.lock_ok();
        if g.is_none() {
            *g = Some((name.to_string(), crc));
        }
    }

    fn snapshot(&self) -> (u32, u32) {
        (
            self.outer.load(Ordering::Relaxed),
            self.nested.load(Ordering::Relaxed),
        )
    }
}

/// What an archive set turned out to be, as an ordered list of stable
/// tokens: format, then how the content is packed, then how it is being
/// unpacked, then what was found inside.
///
/// The tokens are the wire format - the daemon persists them and the
/// dashboard translates them - so they must stay stable. [`Self::display`]
/// renders the English the CLI prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveShape {
    tokens: Vec<&'static str>,
}

impl ArchiveShape {
    fn from_bits(outer: u32, nested: u32) -> Option<ArchiveShape> {
        let mut t: Vec<&'static str> = Vec::new();
        if outer & SH_RAR5 != 0 {
            t.push("rar5");
        } else if outer & SH_RAR4 != 0 {
            t.push("rar4");
        } else if outer & SH_7Z != 0 {
            t.push("7z");
        } else if outer & SH_ZIP != 0 {
            t.push("zip");
        } else {
            // Nothing archive-shaped has been recognized yet (or the job
            // is loose files) - no badge rather than a guess.
            return None;
        }
        match (outer & SH_STORE != 0, outer & SH_COMPRESSED != 0) {
            (true, true) => t.push("mixed"),
            (true, false) => t.push("store"),
            (false, true) => t.push("compressed"),
            (false, false) => {}
        }
        if outer & SH_ENCRYPTED != 0 {
            t.push("encrypted");
        }
        let one_pass = outer & SH_ONE_PASS != 0;
        let on_disk = outer & SH_MATERIALIZED != 0;
        if one_pass && on_disk {
            t.push("mixed-pass");
        } else if on_disk {
            t.push("on-disk");
        } else if one_pass {
            // Legacy encrypted sets assemble ciphertext and unlock in the
            // finish pass; plaintext-once unlocks as the bytes arrive, so
            // it is a plain one-pass set like any other.
            if outer & SH_ENCRYPTED != 0 && outer & SH_ENC_INSTREAM == 0 {
                t.push("unlock-at-end");
            } else {
                t.push("one-pass");
            }
        }
        if nested & SH_7Z != 0 {
            t.push("inner-7z");
        } else if nested & (SH_RAR4 | SH_RAR5) != 0 {
            t.push("inner-rar");
        }
        Some(ArchiveShape { tokens: t })
    }

    pub fn tokens(&self) -> &[&'static str] {
        &self.tokens
    }

    /// The space-separated form carried by the API and the history file.
    pub fn tag(&self) -> String {
        self.tokens.join(" ")
    }

    /// English, for the CLI and as the dashboard's fallback.
    pub fn display(&self) -> String {
        self.tokens
            .iter()
            .map(|t| shape_word(t))
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// English for one [`ArchiveShape`] token. Unknown tokens pass through so
/// an older daemon's persisted tag still reads sensibly.
pub fn shape_word(token: &str) -> &str {
    match token {
        "rar5" => "RAR5",
        "rar4" => "RAR4",
        "7z" => "7z",
        "zip" => "zip",
        "store" => "stored",
        "compressed" => "compressed",
        "mixed" => "mixed",
        "encrypted" => "encrypted",
        "one-pass" => "one-pass",
        "unlock-at-end" => "unlocked at the end",
        "on-disk" => "unpacked after download",
        "mixed-pass" => "partly on disk",
        "inner-7z" => "7z inside",
        "inner-rar" => "RAR inside",
        other => other,
    }
}

/// How a nested inner archive was handled, for [`note_nested_level`].
pub enum NestedDisposition<'a> {
    /// Extracted entirely in-stream - its volumes never touched disk.
    InStream,
    /// An in-stream attempt fell back to materialized volumes; the reason
    /// is the demote cause (a mixed set, a budget breach, a bad CRC, ...).
    Demoted(&'a str),
    /// Handled by the disk post-pass (a demoted inner, or one never
    /// eligible for streaming - RAR4, multipart 7z, a resumed job).
    Disk,
}

/// A snapshot of the nested-prevalence tally, for the stats API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NestedPrevalence {
    /// Distinct nested inner archives processed (`in_stream + disk`).
    pub levels: u64,
    pub in_stream: u64,
    pub demoted: u64,
    pub disk: u64,
    pub rar_store: u64,
    pub rar_compressed: u64,
    pub rar_encrypted: u64,
    pub sevenz: u64,
    pub other: u64,
}

/// Record one processed nested level: log a line and bump the tally. Cheap
/// and non-spammy - called once per nested archive at a terminal seam, not
/// per span. `kind` is one of `rar-store` / `rar-compressed` /
/// `rar-encrypted` / `7z` / `other`.
pub fn note_nested_level(depth: usize, kind: &str, disposition: NestedDisposition) {
    let bump_kind = || {
        match kind {
            "rar-store" => &NESTED_RAR_STORE,
            "rar-compressed" => &NESTED_RAR_COMPRESSED,
            "rar-encrypted" => &NESTED_RAR_ENCRYPTED,
            "7z" => &NESTED_SEVENZ,
            _ => &NESTED_OTHER,
        }
        .fetch_add(1, Ordering::Relaxed)
    };
    match disposition {
        NestedDisposition::InStream => {
            NESTED_LEVELS.fetch_add(1, Ordering::Relaxed);
            NESTED_IN_STREAM.fetch_add(1, Ordering::Relaxed);
            bump_kind();
            println!("nested-prevalence: depth={depth} type={kind} stream=in-stream");
        }
        NestedDisposition::Disk => {
            NESTED_LEVELS.fetch_add(1, Ordering::Relaxed);
            NESTED_DISK.fetch_add(1, Ordering::Relaxed);
            bump_kind();
            println!("nested-prevalence: depth={depth} type={kind} stream=disk");
        }
        NestedDisposition::Demoted(reason) => {
            // Diagnostic only - the archive is tallied under `disk` when
            // the post-pass re-extracts the volumes this demote produced.
            NESTED_DEMOTED.fetch_add(1, Ordering::Relaxed);
            println!(
                "nested-prevalence: depth={depth} type={kind} stream=demoted reason=\"{reason}\""
            );
        }
    }
}

/// Current nested-prevalence tally (process lifetime). Surfaced by the
/// daemon stats API and asserted by the prevalence tests.
pub fn nested_prevalence() -> NestedPrevalence {
    NestedPrevalence {
        levels: NESTED_LEVELS.load(Ordering::Relaxed),
        in_stream: NESTED_IN_STREAM.load(Ordering::Relaxed),
        demoted: NESTED_DEMOTED.load(Ordering::Relaxed),
        disk: NESTED_DISK.load(Ordering::Relaxed),
        rar_store: NESTED_RAR_STORE.load(Ordering::Relaxed),
        rar_compressed: NESTED_RAR_COMPRESSED.load(Ordering::Relaxed),
        rar_encrypted: NESTED_RAR_ENCRYPTED.load(Ordering::Relaxed),
        sevenz: NESTED_SEVENZ.load(Ordering::Relaxed),
        other: NESTED_OTHER.load(Ordering::Relaxed),
    }
}

/// Reset the tally to zero. Test-only: the counters are process-global, so
/// a test that asserts exact counts must isolate itself first.
#[doc(hidden)]
pub fn reset_nested_prevalence() {
    for c in [
        &NESTED_LEVELS,
        &NESTED_IN_STREAM,
        &NESTED_DEMOTED,
        &NESTED_DISK,
        &NESTED_RAR_STORE,
        &NESTED_RAR_COMPRESSED,
        &NESTED_RAR_ENCRYPTED,
        &NESTED_SEVENZ,
        &NESTED_OTHER,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}

/// One deferred pwrite: performed after the routing lock drops.
struct WriteJob {
    writer: Arc<FileWriter>,
    file_off: u64,
    src_start: usize,
    len: usize,
    /// In-stream decrypt state when this span belongs to an encrypted
    /// store entry under plaintext-once: the executor routes the bytes
    /// through [`CryptoState::ingest`]/[`CryptoState::patch`] instead of
    /// a raw pwrite, and the article is never journaled (Persist::No -
    /// what lands on disk is plaintext, not the posted bytes a resume
    /// would copy into volume files).
    crypto: Option<Arc<CryptoState>>,
    repair: bool,
}

/// One deferred child forward from the hot write path: `len` bytes of the
/// caller's span (at `src_start`) go to the child slot the routing map
/// names at DELIVERY time, at `file_off` of the level-1 file - executed
/// after the routing lock drops, exactly like the deferred pwrites (the
/// child takes its own lock and defers its own pwrites; running that
/// under our lock would serialize disk I/O behind routing again). The
/// destination is re-resolved rather than captured: a group merge in the
/// window can displace (and abandon) the slot routing picked.
struct FwdSpan {
    name: String,
    size: u64,
    file_off: u64,
    src_start: usize,
    len: usize,
    /// Mapped-repair rewrite: the bytes may DIFFER from an earlier
    /// delivery of the same range, so the child must overwrite (not
    /// clip) its piece-CRC composition - see [`CrcRuns::overwrite`].
    repair: bool,
}

/// An OWNED child forward, queued by the under-the-lock re-feed paths
/// (drain_holds / reresolve / settle) that cannot call into the child
/// while the lock is held. Delivered by `flush_pending_fwd` once the lock
/// drops; `parent_slot`/`vol_off` let delivery re-route the bytes into a
/// materialized volume if the slot fell back in the meantime.
struct FwdJob {
    parent_slot: usize,
    vol_off: u64,
    name: String,
    size: u64,
    file_off: u64,
    bytes: Vec<u8>,
    /// See [`FwdSpan::repair`].
    repair: bool,
}

/// Where an inner file's bytes go: a real output writer, or a slot of the
/// nested child extractor.
enum Dest {
    Writer(Arc<FileWriter>),
    Child(Arc<Extractor>, usize),
}

// ---------------------------------------------------------------------------
// The chasing decompressor (nested one-pass, phase 2): a COMPRESSED RAR5
// inner archive decompresses while its bytes arrive, instead of demoting
// to a materialized file. Each chased volume feeds a frontier buffer the
// routing path appends to; a chase worker thread drives the RAR engine's
// streaming reader over those buffers in volume order, and its extracted
// member bytes route back through the same seam - a child-extractor slot
// per member - so a store archive UNDER the compressed layer still
// streams. Any failure demotes the group to today's materialize path.
// ---------------------------------------------------------------------------

/// Sort and coalesce touching/overlapping `[a, b)` ranges. Every
/// coverage answer in this file ends with this shape; it was written out
/// four times before the trim split made it five.
fn merge_intervals(mut ivs: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ivs.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (a, b) in ivs {
        if let Some(last) = out.last_mut()
            && a <= last.1
        {
            last.1 = last.1.max(b);
            continue;
        }
        out.push((a, b));
    }
    out
}

/// Job-wide extraction limits, shared by every level of one nesting
/// chain (like `HoldsBudget`), so a bomb split across nested archives or
/// many inner files can never hand itself a fresh allowance.
///
/// Both numbers default to "no limit", so an `Extractor` built without
/// them behaves exactly as it did before they existed.
#[derive(Debug)]
pub struct Limits {
    /// PREALLOCATION ceiling for inner-file writers. An inner file's
    /// declared `unpacked_size` is an attacker-controlled RAR header
    /// vint, and on Linux preallocation is a real `fallocate` - so a
    /// few-hundred-KB post could reserve the whole volume until the
    /// finish-time gates demoted it. The defensible bound is the NZB's
    /// own posted byte count: a STORE archive cannot legitimately unpack
    /// to more than what was posted. Applied to the RESERVATION only -
    /// never to `FileWriter.size`, which feeds resume truncation and the
    /// reported extracted size (see `disk::preallocate_capped`).
    prealloc_cap: AtomicU64,
    /// Distinct extracted bytes the whole chain may write - the in-stream
    /// half of the decompression-bomb guard the disk/post-pass sinks have
    /// always had. Separate from `prealloc_cap` on purpose: one bounds a
    /// reservation and is deliberately soft (writes past it still
    /// succeed), the other bounds bytes actually landed and is hard.
    budget: Arc<crate::disk::WriteBudget>,
}

impl Limits {
    fn unlimited() -> Limits {
        Limits {
            prealloc_cap: AtomicU64::new(u64::MAX),
            budget: Arc::new(crate::disk::WriteBudget::unlimited()),
        }
    }

    fn prealloc_cap(&self) -> u64 {
        self.prealloc_cap.load(Ordering::Relaxed)
    }
}

pub struct Extractor {
    out_dir: PathBuf,
    enabled: bool,
    /// Crash-resume: open existing files without truncating.
    resume: bool,
    /// Nesting level: 0 = the top-level extractor over the download's
    /// volume slots, +1 per child. A child created AT the depth cap
    /// (`inner.nested_max_depth`) is disabled (everything materializes
    /// Plain).
    depth: usize,
    /// The extractor one level up (dead for the root, and for children
    /// created before the root's [`Self::set_promote_hook`] anchored the
    /// chain). Carries the tail-prefetch promote walk: a child's file
    /// ranges translate level by level up to the root's hook.
    parent: Weak<Extractor>,
    /// What this set turned out to be, shared with every nested level.
    /// Deliberately outside `inner`: the daemon polls it once a second
    /// while the routing lock is the hot path.
    shape: Arc<ShapeLatch>,
    inner: Mutex<Inner>,
}

struct Inner {
    slots: Vec<Slot>,
    groups: HashMap<String, Group>,
    /// Inner-file name → canonical group key. Entries are added when a
    /// split piece links a name to an archive; following the chain maps
    /// any name to the group that owns it.
    alias: HashMap<String, String>,
    /// Extracted inner-file writers, keyed by OUTPUT filename (see
    /// `Group::out_names` for the entry-name → output-name step).
    inner_writers: HashMap<String, Arc<FileWriter>>,
    /// M15: held-span budget, SHARED down the child chain (nested holds
    /// charge the same slice; beyond it groups spill to materialized
    /// volumes).
    budget: Arc<HoldsBudget>,
    /// Held-span scratch file, SHARED down the child chain like the
    /// budget it relieves (see [`HoldsScratch`]).
    scratch: Arc<HoldsScratch>,
    /// Holds-paging gate (`NZBFAST_NO_HOLDS_PAGE` / runtime setter).
    /// Off: a budget breach demotes exactly as before paging existed.
    holds_page_on: bool,
    /// Preallocation ceiling + extracted-byte budget, SHARED down the
    /// child chain (see [`Limits`]).
    limits: Arc<Limits>,
    /// Output-name claims, SHARED down the child chain so name
    /// disambiguation spans nesting levels (a child's plain file must not
    /// collide with a parent-level output). Leaf lock: only ever taken
    /// with no other lock acquired after it.
    names_taken: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Whether `names_taken` keys are case-folded, i.e. whether the OUTPUT
    /// VOLUME is case-insensitive. Probed once at the root and threaded down
    /// with `names_taken` so every level keys that shared set the same way.
    fold_names: bool,
    /// Lazily-created nested child extractor (level+1 inner files become
    /// its slots).
    child: Option<Arc<Extractor>>,
    /// Child forwards queued by under-the-lock re-feed paths; delivered
    /// by `flush_pending_fwd` after the lock drops.
    pending_fwd: Vec<FwdJob>,
    /// Promotes raised while the routing lock is held (a 7z part joining
    /// its set, a held slot's offset-0 probe). `promote_file` walks UP
    /// the chain taking each level's own lock, so it can never be called
    /// from under one - these are queued here and flushed off-lock. The
    /// bool is the hook's `urgent` flag (see [`PromoteHook`]).
    pending_promote: Vec<(usize, Vec<(u64, u64)>, bool)>,
    /// Nested routing gate (env escape hatch / rollout setting). With it
    /// off, level-1 inner files write directly to disk as before the
    /// child path existed.
    nested_on: bool,
    /// Chasing-decompressor gate (`NZBFAST_NO_NESTED_CHASE` / runtime
    /// setter). Off: a compressed inner archive demotes to a
    /// materialized file exactly as before the chase existed.
    chase_on: bool,
    /// 7z-chase gate (`NZBFAST_NO_NESTED_7Z` / runtime setter). Off: an
    /// inner .7z materializes exactly as before the 7z path existed.
    sevenz_on: bool,
    /// Nested-zip gate (`NZBFAST_NO_NESTED_ZIP` / runtime setter), the
    /// zip twin of `sevenz_on`. Off: an inner zip materializes exactly
    /// as it did before the depth guard came off.
    nested_zip_on: bool,
    /// Top-level 7z gate (`NZBFAST_NO_TOP_7Z` / runtime setter). Only
    /// depth 0 reads it, so children carry it unused. Off: a posted
    /// `.7z` materializes for the disk post-pass, the pre-TODO-37
    /// behaviour.
    top_sevenz_on: bool,
    /// Top-level RAR chase gate (`NZBFAST_NO_TOP_RAR_CHASE` / the
    /// `prefer_external_unrar` setting / runtime setter). Only depth 0
    /// reads it, so children carry it unused. Off: a posted compressed
    /// RAR materializes for the unrar ladder, the pre-lift behaviour.
    top_chase_on: bool,
    /// Top-level zip gate (`NZBFAST_NO_TOP_ZIP` / runtime setter). Only
    /// depth 0 reads it, so children carry it unused. Off: a posted
    /// `.zip` materializes for the disk post-pass, the phase-1
    /// behaviour.
    top_zip_on: bool,
    /// Drop-behind trim gate (`NZBFAST_NO_7Z_TRIM` / runtime setter).
    /// Off: a 7z chase retains everything and an archive over the
    /// retention cap demotes, as it did before trimming existed.
    sevenz_trim_on: bool,
    /// Drop-behind trim gate for the RAR chase (`NZBFAST_NO_RAR_TRIM` /
    /// runtime setter). Off: a chased RAR set retains everything and a
    /// set over the retention cap demotes to the unrar ladder, as it did
    /// before the incremental split decode existed.
    rar_trim_on: bool,
    /// Bytes a RAR chase drop-behind trim has spilled out of RAM in this
    /// extractor. Chain-wide totals come from
    /// [`Extractor::chase_trimmed_bytes`].
    chase_trimmed: u64,
    /// Live split-7z sets, keyed by `sevenz_part_name` base, so a
    /// `.7z.002` classifying later can find the container `.7z.001`
    /// opened and join it. Cleared as each set settles. Zip splits
    /// share the map (the base grammars are disjoint: `.7z.NNN` vs
    /// `.zip.NNN`).
    sevenz_sets: HashMap<String, Arc<SevenZCtl>>,
    /// Byte-split zip sets the CALLER declared from the NZB's own file
    /// list: `split_part_name` base -> part count. A zip split needs
    /// this where a 7z split does not, because no zip part carries a
    /// header that sizes the container - the count says when every
    /// part's decoded size is in and the geometry can resolve. A part
    /// whose base is not declared here never chases (it materializes
    /// for the disk pass, the phase-1 behaviour).
    zip_split_decl: HashMap<String, u32>,
    /// Nested depth cap for this chain: the child created AT this depth is
    /// disabled, so the deepest layer materializes (never a hard failure).
    /// Resolved from the daemon setting / env at construction and inherited
    /// unchanged by every child. See [`nested_depth_cap`].
    nested_max_depth: usize,
    /// Final-output CRC gate (`NZBFAST_NO_OUTPUT_CRC` / runtime setter).
    /// On (the default): level 0 composes and checks its store payloads'
    /// header CRCs exactly like the nested levels, so a payload the
    /// poster packed damaged (outer PAR2 accepts it as-posted) demotes
    /// to materialized volumes instead of shipping silently corrupt.
    /// Off: level 0 skips composition and the check, today's behavior.
    verify_output_crc: bool,
    /// Tail-prefetch promote hook, installed on the ROOT only (main.rs
    /// wires it to the seek/promote ladder). Levels below reach it by
    /// walking `parent` and translating ranges as they go.
    promote: Option<PromoteHook>,
    /// Weak self-handle (set by `ensure_child` - only children chase, and
    /// children are always Arc-owned). The chase worker upgrades per
    /// callback so a cancelled extractor can actually drop: its Drop
    /// aborts the buffers and the worker's next upgrade fails.
    self_weak: Weak<Extractor>,
    extracted_bytes: u64,
    /// Reusable buffer for `map_span_into` - one heap allocation per
    /// ARTICLE under the routing lock otherwise. Taken (empty) during
    /// `extract_span`, returned cleared; a re-entrant taker just works
    /// on a fresh empty vector.
    map_scratch: Vec<(usize, u64, u64, u64)>,
    /// Fallbacks of slots that never joined a group (blocker before any
    /// entry parsed) - reported alongside group fallbacks.
    slot_fallbacks: Vec<(String, String)>,
    /// Slot bytes come from real files in `out_dir` (re-extraction): a
    /// fallback must never create a slot writer - `FileWriter::create`
    /// truncates, and the slot's name IS the source file being read.
    /// Fallback slots discard instead; the sources are the deliverable.
    protect_sources: bool,
    /// Archive password (M23a plumbing): lets mappers accept RAR5
    /// encrypted headers / encrypted store entries. The ciphertext is
    /// assembled at the usual store offsets and decrypted in one pass at
    /// finish - during the download the inner files hold volume-exact
    /// bytes, so verifier read-back and fallback reconstruction are
    /// untouched by encryption.
    password: Option<std::sync::Arc<str>>,
    /// Per-encrypted-output stream lifecycle (out name → shared state),
    /// created on first /stream open or at the finish decrypt.
    stream_states: HashMap<String, Arc<StreamState>>,
    /// Publish gate for the finish decrypt, inherited by every child (a
    /// nested level's outputs are journal recovery sources too). See
    /// [`DecryptBarrier`].
    decrypt_barrier: Option<DecryptBarrier>,
    /// Plaintext-once gate (see [`CryptoState`]): encrypted store
    /// entries decrypt at write time instead of assembling ciphertext
    /// for the finish pass. `NZBFAST_NO_INSTREAM_DECRYPT=1` restores
    /// the legacy path.
    instream_decrypt: bool,
    /// In-stream decrypt state per OUTPUT name (same key space as
    /// `inner_writers`). Presence marks the file plaintext-on-disk:
    /// posted-bytes readers go through [`CryptoState::read_posted`],
    /// its articles journal as `D` records (restorable only by
    /// re-encryption), and the finish decrypt skips it.
    crypto_files: HashMap<String, Arc<CryptoState>>,
    /// Resume-journal events from every [`CryptoState`] in the chain
    /// (children share it like the holds budget); drained by
    /// [`Extractor::drain_crypto_events`].
    crypto_events: CryptoEventSink,
    /// Increment A: candidate-password probe hook, installed by the
    /// caller (the daemon's harvest over the job's own sidecars and
    /// stems). Called OFF the routing lock with the archive's crypt
    /// parameters; a `Some` return is a check-VERIFIED password (the
    /// hook does the KDFs and only surrenders a candidate the stored
    /// check accepts). Root level only - a nested level's sidecars are
    /// inner files the disk pass's password-chain already covers.
    pw_probe: Option<PwProbeHook>,
    /// True while any slot is `pw_await` and a probe attempt is due:
    /// set at blocker onset and re-armed by the cadence check in
    /// [`Extractor::flush_pw_probe`]; cleared by every flush.
    pw_probe_due: bool,
    /// Last probe attempt, for the re-probe cadence (a sidecar that
    /// lands AFTER the archive blocked must still be seen mid-run, not
    /// only at finish).
    pw_probe_last: Option<std::time::Instant>,
}

/// Increment A: caller-supplied candidate probe. Given the blocked
/// archive's RAR5 crypt parameters, harvest + test candidates and
/// return one the stored check VERIFIES (never an unverified guess -
/// a wrong password past this point writes garbage).
pub type PwProbeHook =
    std::sync::Arc<dyn Fn(&crate::rar::CryptProbe) -> Option<String> + Send + Sync>;

impl Extractor {
    /// `n_slots` = number of slots in the download; `enabled=false` makes
    /// every slot Plain (the pre-M3 behavior, e.g. --no-extract).
    pub fn new(out_dir: &Path, n_slots: usize, enabled: bool) -> Extractor {
        Self::with_resume(out_dir, n_slots, enabled, false)
    }

    /// Test hook: is every parsed piece of each named inner file placed
    /// (a base derived for it)? Distinguishes "resolution reached these
    /// bytes" from "the job happened to succeed".
    #[cfg(test)]
    pub(crate) fn bases_known(&self, names: &[&str]) -> bool {
        let inner = self.inner.lock().unwrap();
        for si in 0..inner.slots.len() {
            let Some(m) = inner.slots[si].mapper.as_ref() else {
                continue;
            };
            for (ei, e) in m.entries.iter().enumerate() {
                if !names.contains(&e.name.as_str()) || e.is_dir {
                    continue;
                }
                if Self::base_for(&inner, si, ei).is_none() {
                    return false;
                }
            }
        }
        true
    }

    /// Test hook: keys of groups whose pieces the arithmetic gate ever
    /// placed beyond what chain resolution had confirmed. The multi-file
    /// regressions assert this stays empty - those sets must live and
    /// die on the chain path.
    #[cfg(test)]
    pub(crate) fn arith_engaged_groups(&self) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner
            .groups
            .iter()
            .filter(|(_, g)| g.arith_ever)
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn with_resume(out_dir: &Path, n_slots: usize, enabled: bool, resume: bool) -> Extractor {
        // Crash leftovers from a killed run: at most one extractor owns a
        // job dir at a time, so a stale scratch here is provably dead.
        sweep_holds_scratch(out_dir);
        Self::build(
            out_dir,
            n_slots,
            enabled,
            resume,
            0,
            Weak::new(),
            Arc::new(HoldsBudget::new(HOLDS_DEFAULT_CAP)),
            Arc::new(HoldsScratch::new(out_dir)),
            Arc::new(Limits::unlimited()),
            Arc::new(Mutex::new(Default::default())),
            crate::disk::case_insensitive_dir(out_dir),
            !nested_env_off(),
            !chase_env_off(),
            !sevenz_env_off(),
            !nested_zip_env_off(),
            !holds_page_env_off(),
            nested_depth_cap(),
            !output_crc_env_off(),
            None,
            Arc::new(ShapeLatch::default()),
        )
    }

    /// Full constructor - the public ctors and `ensure_child` both land
    /// here. Children share the parent's holds budget and name claims.
    #[allow(clippy::too_many_arguments)]
    fn build(
        out_dir: &Path,
        n_slots: usize,
        enabled: bool,
        resume: bool,
        depth: usize,
        parent: Weak<Extractor>,
        budget: Arc<HoldsBudget>,
        scratch: Arc<HoldsScratch>,
        limits: Arc<Limits>,
        names_taken: Arc<Mutex<std::collections::HashSet<String>>>,
        fold_names: bool,
        nested_on: bool,
        chase_on: bool,
        sevenz_on: bool,
        nested_zip_on: bool,
        holds_page_on: bool,
        nested_max_depth: usize,
        verify_output_crc: bool,
        password: Option<std::sync::Arc<str>>,
        shape: Arc<ShapeLatch>,
    ) -> Extractor {
        Extractor {
            out_dir: out_dir.to_path_buf(),
            enabled,
            resume,
            depth,
            parent,
            shape,
            inner: Mutex::new(Inner {
                slots: (0..n_slots).map(|_| Self::new_slot()).collect(),
                groups: HashMap::new(),
                alias: HashMap::new(),
                inner_writers: HashMap::new(),
                budget,
                scratch,
                holds_page_on,
                limits,
                names_taken,
                fold_names,
                child: None,
                pending_fwd: Vec::new(),
                pending_promote: Vec::new(),
                nested_on,
                chase_on,
                sevenz_on,
                nested_zip_on,
                // Read here rather than threaded through `build`: only
                // depth 0 consults it, and depth 0 is exactly what the
                // public constructors make. Same construction-time
                // latching as every other gate.
                top_sevenz_on: !top_sevenz_env_off(),
                // A user preferring their own unrar latches the RAR
                // chase off too: the set materializes and the disk
                // ladder (where that preference picks the engine) gets
                // it, instead of the native decoder streaming it here.
                top_chase_on: !top_chase_env_off() && !prefer_external_unrar(),
                top_zip_on: !top_zip_env_off(),
                sevenz_trim_on: !sevenz_trim_env_off(),
                rar_trim_on: !rar_trim_env_off(),
                chase_trimmed: 0,
                sevenz_sets: HashMap::new(),
                zip_split_decl: HashMap::new(),
                nested_max_depth: nested_max_depth.max(1),
                verify_output_crc,
                promote: None,
                self_weak: Weak::new(),
                extracted_bytes: 0,
                map_scratch: Vec::new(),
                slot_fallbacks: Vec::new(),
                protect_sources: false,
                password,
                stream_states: HashMap::new(),
                decrypt_barrier: None,
                // Plaintext-once gate: on for a live (enabled, fresh)
                // extractor unless the env kill-switch restores the
                // legacy ciphertext-then-finish-decrypt path. Resume
                // never maps in-stream, so the flag is moot there.
                instream_decrypt: enabled
                    && !resume
                    && std::env::var("NZBFAST_NO_INSTREAM_DECRYPT").map_or(true, |v| v != "1"),
                crypto_files: HashMap::new(),
                crypto_events: Arc::new(Mutex::new(Vec::new())),
                pw_probe: None,
                pw_probe_due: false,
                pw_probe_last: None,
            }),
        }
    }

    /// What this download's archives turned out to be, as far as the
    /// mappers and the routing have got. `None` until something
    /// archive-shaped is recognized (loose files never report a shape).
    ///
    /// Safe to call from any thread at any time - it reads the latch, not
    /// the routing lock - and it is the same answer during the download
    /// and after finish(), so the live badge and the history entry agree.
    pub fn archive_shape(&self) -> Option<ArchiveShape> {
        let (outer, nested) = self.shape.snapshot();
        ArchiveShape::from_bits(outer, nested)
    }

    /// `(inner file name, CRC32)` for the first inner file whose header
    /// stated one - an exact identity key for the open release
    /// databases, available for free because the mappers read those
    /// headers anyway.
    ///
    /// `None` for a set with no readable archive headers, which includes
    /// every header-encrypted (`-hp`) post. Same lifetime as
    /// [`Self::archive_shape`]: readable during the download and still
    /// true after finish().
    pub fn inner_crc(&self) -> Option<(String, u32)> {
        self.shape.crc.lock_ok().clone()
    }

    fn new_slot() -> Slot {
        Slot {
            mode: SlotMode::Unknown,
            name: String::new(),
            size: 0,
            sort_key: None,
            holds: Vec::new(),
            pre_bytes: 0,
            probe0_sent: false,
            writer: None,
            mapper: None,
            header_spans: Vec::new(),
            group: None,
            chase: None,
            sevenz: None,
            container_fmt: ChaseFormat::SevenZ,
            piece_crcs: HashMap::new(),
            pw_await: None,
        }
    }

    /// Dynamically add a slot (nested routing: every level-1 inner file
    /// becomes one slot of the child extractor). Returns its index.
    pub fn alloc_slot(&self) -> usize {
        let mut inner = self.inner.lock_ok();
        inner.slots.push(Self::new_slot());
        inner.slots.len() - 1
    }

    /// The nested child extractor, created on first use. Shares the holds
    /// budget, the name claims, the password, and the routing gate; a
    /// child AT the depth cap is created disabled, so every deeper file
    /// simply materializes Plain.
    fn ensure_child(&self, inner: &mut Inner) -> Arc<Extractor> {
        if inner.child.is_none() {
            let depth = self.depth + 1;
            let child = Arc::new(Self::build(
                &self.out_dir,
                0,
                depth < inner.nested_max_depth,
                self.resume,
                depth,
                inner.self_weak.clone(),
                inner.budget.clone(),
                inner.scratch.clone(),
                inner.limits.clone(),
                inner.names_taken.clone(),
                inner.fold_names,
                inner.nested_on,
                inner.chase_on,
                inner.sevenz_on,
                inner.nested_zip_on,
                inner.holds_page_on,
                inner.nested_max_depth,
                inner.verify_output_crc,
                inner.password.clone(),
                // One latch per chain: the child's observations land in
                // the nested word of the same summary the root publishes.
                self.shape.clone(),
            ));
            {
                let mut ci = child.inner.lock_ok();
                // The child knows its own Arc (weakly): the chase worker
                // reaches its extractor through this without pinning it.
                ci.self_weak = Arc::downgrade(&child);
                // A nested level decrypts its own encrypted store outputs
                // at ITS finish, and those files are journal recovery
                // sources exactly like the parent's - same gate.
                ci.decrypt_barrier = inner.decrypt_barrier.clone();
                // One event sink per chain: a nested encrypted output's
                // E/K/T records drain through the root exactly like its
                // placements fold into the root's frags.
                ci.crypto_events = inner.crypto_events.clone();
            }
            inner.child = Some(child);
        }
        inner.child.clone().unwrap()
    }

    /// Write one decoded span. `name`/`size` from the yEnc header.
    ///
    /// The global lock covers only routing/mapping decisions - the actual
    /// `pwrite`s run after it drops, so concurrent decoders don't
    /// serialize on disk I/O (measured: the locked-write version capped
    /// `get` ~2 Gbps below the network on London).
    ///
    /// Returns [`Persist::Placed`] with the physical fragments when EVERY
    /// byte of the span is durably on disk after this call - at its final
    /// offset in a plain/materialized file, or translated into an
    /// extracted inner file. Held spans, retained header bytes, and
    /// discards return [`Persist::No`] (their articles refetch on resume).
    pub fn write(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, false, None)
    }

    /// [`Self::write`] carrying what the decode established about this
    /// article: `article_crc` is the pcrc32 that was present, calculated
    /// and MATCHED, over exactly `data`. Passing it lets a STORE span
    /// that is byte-for-byte this article compose from the verified value
    /// instead of hashing the same bytes a second time. `None` is always
    /// safe and simply hashes.
    pub fn write_verified(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        article_crc: Option<u32>,
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, false, article_crc)
    }

    /// [`Self::write`] with the repair marker exposed: parity-as-a-source
    /// reconstruction feeds whole recreated files through this normal
    /// arrival path, so a rebuilt volume one-passes through whatever
    /// route its shape earns (store map, RAR chase, zip chase, plain).
    /// Unlike [`Self::patch_volume_span`] - which requires an
    /// already-mapped slot - this starts from an untouched (or freshly
    /// allocated) slot and lets routing classify it from the
    /// reconstructed offset-0 bytes. The repair marker still matters:
    /// a range whose earlier (wire-damaged) arrival already composed
    /// into the piece CRCs must REPLACE it, not be clipped as a
    /// duplicate (see [`CrcRuns::overwrite`]).
    pub fn write_repair(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, true, None)
    }

    /// [`Self::write`] with the repair marker: `repair` says this span is
    /// a mapped-repair rewrite (patch_volume_span), whose bytes may
    /// DIFFER from an earlier arrival of the same range. Everything on
    /// disk overwrites naturally; the piece-CRC composition is the one
    /// consumer that must be told, or it keeps the stale pre-repair
    /// value (first-writer-wins) and the finish gate demotes a job whose
    /// output healed cleanly.
    fn write_impl(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<Persist> {
        // Per-thread scratch for the span's job/forward queues - filled
        // under the routing lock, so their per-article allocation was
        // lock-held. A STACK of pairs, not one pair: a forwarded span
        // re-enters write_impl on the child extractor from this same
        // thread, and each nesting level needs its own buffers.
        thread_local! {
            static SPAN_SCRATCH: std::cell::RefCell<Vec<(Vec<WriteJob>, Vec<FwdSpan>)>> =
                const { std::cell::RefCell::new(Vec::new()) };
        }
        let (mut jobs, mut fwd) = SPAN_SCRATCH
            .with(|s| s.borrow_mut().pop())
            .unwrap_or_default();
        let result = self.write_impl_scratched(
            &mut jobs,
            &mut fwd,
            slot,
            name,
            size,
            offset,
            data,
            repair,
            article_crc,
        );
        jobs.clear();
        fwd.clear();
        SPAN_SCRATCH.with(|s| s.borrow_mut().push((jobs, fwd)));
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn write_impl_scratched(
        &self,
        jobs: &mut Vec<WriteJob>,
        fwd: &mut Vec<FwdSpan>,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<Persist> {
        let mut pending: Vec<FwdJob> = Vec::new();
        let mut routed_rar = false;
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            {
                let s = &mut inner.slots[slot];
                if s.name.is_empty() && !name.is_empty() {
                    s.name = name.to_string();
                }
                if s.size == 0 {
                    s.size = size;
                }
            }

            match inner.slots[slot].mode {
                SlotMode::Unknown => {
                    if !self.enabled {
                        // No mapping possible - no reason to wait for the
                        // offset-0 sniff (crucial on resume, where segment
                        // 1 may never be refetched).
                        inner.slots[slot].mode = SlotMode::Plain;
                        self.plain_job(inner, slot, offset, data, &mut *jobs)?;
                        self.drain_holds(inner, slot)?;
                    } else if offset != 0 {
                        inner.budget.add(data.len());
                        inner.slots[slot].pre_bytes += data.len();
                        inner.slots[slot]
                            .holds
                            .push((offset, HoldSpan::Ram(data.to_vec())));
                        if !inner.slots[slot].probe0_sent {
                            // The slot's very first span arrived out of
                            // order, so the M3 head prefetch did NOT
                            // deliver the offset-0 sniff - front-load it
                            // instead of waiting (synthesized segment
                            // numbering can put it anywhere in the
                            // queue). Two guesses, one promote:
                            //   (0, 1)  - offset 0 where the NZB ladder
                            //     says it is; pulls a late/retried head
                            //     article forward when the ladder is
                            //     honest.
                            //   (size-offset, +1) - the rotation guess,
                            //     root only: if numbering preserved
                            //     posting order but started mid-sequence
                            //     (the indexer-synthesized norm), the
                            //     article at declared byte 0 carrying
                            //     actual offset X puts actual offset 0
                            //     at declared byte size-X. The ladder's
                            //     ±slack absorbs a couple articles of
                            //     arrival jitter.
                            // One shot per slot: a one-time promote
                            // cannot fight the M11 stream reader, whose
                            // newest-alive generation re-promotes its
                            // rolling window every few MB (serve.rs
                            // LiveRangeReader) and so always ends up in
                            // front; a wrong guess for a genuinely
                            // shuffled post costs a few articles once,
                            // and `spill_unclassified_slot` stays the
                            // backstop.
                            inner.slots[slot].probe0_sent = true;
                            let size = inner.slots[slot].size;
                            let mut spans = vec![(0u64, 1u64)];
                            if self.parent.upgrade().is_none() && offset < size {
                                spans.push((size - offset, size - offset + 1));
                            }
                            inner.pending_promote.push((slot, spans, false));
                        }
                        let spill =
                            inner.slots[slot].pre_bytes > unclassified_spill(inner.budget.cap());
                        if inner.budget.over() && !self.page_out_holds(inner) {
                            self.overflow_to_plain(inner)?;
                        } else if spill {
                            // The offset-0 sniff hasn't arrived after this
                            // much of the slot - synthesized segment
                            // numbering can put it anywhere in the queue.
                            // Give up mapping THIS slot: plain writes are
                            // always correct (a real RAR volume simply
                            // materializes on disk, the pre-M3 behavior),
                            // while holding on livelocks the pipeline in
                            // RAM with nothing on disk, in stats, or in
                            // the journal.
                            self.spill_unclassified_slot(inner, slot)?;
                        }
                        // This branch returns before the function's
                        // shared off-lock flush, and the next write for
                        // a still-Unknown slot lands right back here -
                        // the probe would sit queued until the sniff it
                        // exists to fetch. Flush it now, off the lock.
                        drop(g);
                        self.flush_pending_promote();
                        return Ok(Persist::No);
                    } else {
                        let is_rar = data.starts_with(b"Rar!\x1a\x07\x01\x00")
                            || data.starts_with(b"Rar!\x1a\x07\x00");
                        if is_rar {
                            inner.slots[slot].mode = SlotMode::Rar;
                            routed_rar = true;
                            let size = inner.slots[slot].size;
                            inner.slots[slot].mapper =
                                Some(VolumeMapper::with_password(size, inner.password.clone()));
                            self.rar_span(
                                inner,
                                slot,
                                offset,
                                data,
                                Some((&mut *jobs, &mut *fwd)),
                                repair,
                                article_crc,
                            )?;
                        } else if self.try_attach_sevenz(inner, slot, data)? {
                            // Phase 3: a .7z gets the tail-prefetch chase -
                            // this span (and everything held) feeds its
                            // frontier buffer. Only the FORMAT is known
                            // yet; `one-pass` is claimed in sevenz_finish,
                            // once the archive actually decoded. Claiming
                            // it here would badge a top-level archive that
                            // demoted on the retention cap "partly on
                            // disk" when every byte of it went to disk.
                            self.shape.note(self.depth, SH_7Z);
                            self.chase_span(inner, slot, offset, data)?;
                        } else if self.try_attach_zip(inner, slot, data)? {
                            // One-pass zip (phase 2): the same claim
                            // discipline as 7z - only the FORMAT is
                            // known yet; `one-pass` is claimed at
                            // successful finish.
                            self.shape.note(self.depth, SH_ZIP);
                            self.chase_span(inner, slot, offset, data)?;
                        } else if inner.protect_sources {
                            // A supposed volume that isn't RAR: writing it
                            // out plain would truncate the source file.
                            let name = inner.slots[slot].name.clone();
                            inner
                                .slot_fallbacks
                                .push((name, "not a RAR volume".to_string()));
                            self.discard_slot(inner, slot);
                            return Ok(Persist::No);
                        } else {
                            if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
                                // A .7z the chase can't take (top level, a
                                // multipart .001, gate off): it lands on
                                // disk for the post-pass, and the badge
                                // should say so rather than say nothing.
                                self.shape.note(self.depth, SH_7Z | SH_MATERIALIZED);
                            } else if self.depth == 0
                                && data.starts_with(b"PK\x03\x04")
                                && crate::zip::chase_eligible_name(&inner.slots[slot].name)
                            {
                                // Same for a zip the chase can't take
                                // (gate off, too small). The name gate
                                // keeps phase 0's rules: a `.cbz` or a
                                // named non-zip never reads as packaging.
                                // Still depth-0 only, unlike the 7z arm
                                // above, because `from_bits` renders the
                                // nested word as `inner-7z`/`inner-rar`
                                // and has no zip token - a nested note
                                // here would set bits nothing reads.
                                // Giving nested zip a badge means adding
                                // a persisted wire token plus dashboard
                                // copy, which is its own piece of work.
                                self.shape.note(self.depth, SH_ZIP | SH_MATERIALIZED);
                            }
                            inner.slots[slot].mode = SlotMode::Plain;
                            self.plain_job(inner, slot, offset, data, &mut *jobs)?;
                        }
                        self.drain_holds(inner, slot)?;
                    }
                }
                SlotMode::Plain | SlotMode::RarFallback => {
                    self.plain_job(inner, slot, offset, data, &mut *jobs)?;
                }
                SlotMode::Rar => {
                    routed_rar = true;
                    self.rar_span(
                        inner,
                        slot,
                        offset,
                        data,
                        Some((&mut *jobs, &mut *fwd)),
                        repair,
                        article_crc,
                    )?;
                }
                // Chased slot (RAR or 7z): the span feeds the frontier
                // buffer (RAM, budget-charged) - not on disk, so never
                // journalable.
                SlotMode::RarChase | SlotMode::SevenZ => {
                    self.chase_span(inner, slot, offset, data)?
                }
                SlotMode::Discard => return Ok(Persist::No),
            }
            if !fwd.is_empty() || !inner.pending_fwd.is_empty() {
                pending = std::mem::take(&mut inner.pending_fwd);
            }
        }
        // The routing lock is down: a 7z part that joined its set above
        // can have its tail articles front-loaded now (the promote walk
        // takes locks up the chain and must not be called from under
        // one). Cheap and usually empty.
        self.flush_pending_promote();
        // Candidate-password probe for parked encrypted slots (Increment
        // A) - KDF work, so off the lock; cadence-gated to a no-op lock
        // peek on the hot path.
        self.flush_pw_probe(false)?;
        for j in jobs.iter() {
            let part = &data[j.src_start..j.src_start + j.len];
            match &j.crypto {
                // The AES runs here, outside the routing lock, under the
                // file's own crypto mutex.
                Some(cs) if j.repair => cs.patch(&j.writer, j.file_off, part)?,
                Some(cs) => cs.ingest(&j.writer, j.file_off, part)?,
                None => j.writer.write_at(j.file_off, part)?,
            }
        }
        // Owned forwards queued by the re-feed paths inside the lock
        // (drain_holds / reresolve) deliver now, then this span's own
        // forwards. Each child call runs lock-free here and returns the
        // child's Persist for the frag composition below.
        if !pending.is_empty() {
            self.deliver_fwd(pending)?;
        }
        let mut fwd_persist: Vec<Persist> = Vec::with_capacity(fwd.len());
        for f in fwd.iter() {
            fwd_persist.push(self.deliver_routed(
                slot,
                offset + f.src_start as u64,
                &f.name,
                f.size,
                f.file_off,
                &data[f.src_start..f.src_start + f.len],
                f.repair,
            )?);
        }
        // The pwrites above ran without the lock. If a fallback flipped
        // this slot meanwhile, its read-back could not see these bytes
        // (interval-gated) and may already have unlinked the inner files
        // the jobs targeted - so the materialized volume is missing this
        // span. Re-route it through the slot's current mode: duplicate
        // writes are harmless, a lost span is silent corruption. The
        // journal skips the article (Persist::No) - its fragments may
        // name just-deleted inner files, and a refetch on resume is the
        // safe outcome for a span that raced a fallback. Forwards to the
        // child already re-resolved their destination in deliver_routed;
        // the whole-span rewrite here duplicates their bytes into the
        // materialized volume, which is harmless (identical offsets,
        // identical bytes).
        if routed_rar && (!jobs.is_empty() || !fwd.is_empty()) {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            if matches!(inner.slots[slot].mode, SlotMode::RarFallback) {
                self.plain_span(inner, slot, offset, data)?;
                return Ok(Persist::No);
            }
        }
        // Spans that fed an in-stream-decrypted file journal as `D`
        // records (restore-by-re-encryption), never as `R` - a plain
        // copy of the plaintext into a volume file would rebuild
        // silently corrupt volumes on a downgrade resume.
        let crypto_span = jobs.iter().any(|j| j.crypto.is_some());
        // Journalable only if the queued writes cover the whole span - a
        // span partially held (or with header bytes kept in memory) is not
        // fully on disk and must refetch on resume.
        let mut frags: Vec<Frag> = jobs
            .iter()
            .map(|j| Frag {
                file: j
                    .writer
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                file_off: j.file_off,
                vol_off: offset + j.src_start as u64,
                len: j.len as u64,
            })
            .collect();
        // Fold the child placements in: a child frag names a child-level
        // output file (already final for the journal); its vol_off is in
        // the CHILD slot's address space, translated back through the
        // affine forward window. Any child part not fully placed makes
        // the whole article refetch on resume.
        let mut crypto_span = crypto_span;
        for (f, p) in fwd.iter().zip(fwd_persist) {
            let cfrags = match p {
                Persist::No => return Ok(Persist::No),
                Persist::Placed(cfrags) => cfrags,
                // A nested plaintext-once output: the whole article's
                // record must be a D line, since at least one fragment
                // can only restore by re-encryption.
                Persist::PlacedCrypto(cfrags) => {
                    crypto_span = true;
                    cfrags
                }
            };
            for cf in cfrags {
                frags.push(Frag {
                    file: cf.file,
                    file_off: cf.file_off,
                    vol_off: offset + f.src_start as u64 + (cf.vol_off - f.file_off),
                    len: cf.len,
                });
            }
        }
        frags.sort_by_key(|f| f.vol_off);
        let mut covered_to = offset;
        for f in &frags {
            if f.vol_off > covered_to {
                return Ok(Persist::No);
            }
            covered_to = covered_to.max(f.vol_off + f.len);
        }
        if !frags.is_empty() && covered_to >= offset + data.len() as u64 {
            Ok(if crypto_span {
                Persist::PlacedCrypto(frags)
            } else {
                Persist::Placed(frags)
            })
        } else {
            Ok(Persist::No)
        }
    }

    /// Queue a plain write of the whole span (lock held; write happens
    /// after it drops).
    fn plain_job(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        jobs: &mut Vec<WriteJob>,
    ) -> io::Result<()> {
        let w = self.ensure_plain_writer(inner, slot)?;
        jobs.push(WriteJob {
            writer: w,
            file_off: offset,
            src_start: 0,
            len: data.len(),
            crypto: None,
            repair: false,
        });
        Ok(())
    }

    fn ensure_plain_writer(&self, inner: &mut Inner, slot: usize) -> io::Result<Arc<FileWriter>> {
        if inner.slots[slot].writer.is_none() {
            let s = &inner.slots[slot];
            let base = if s.name.is_empty() {
                format!("slot{slot:03}")
            } else {
                s.name.clone()
            };
            let mut fname = sanitize_filename(&base);
            Self::claim_name(inner, slot, &mut fname);
            let path = self.out_dir.join(&fname);
            // The same two bounds as `inner_writer`, and for the same
            // reason: with nested routing on (the default) a group's inner
            // files are forwarded to the CHILD, so a non-archive inner
            // file materializes HERE, at depth > 0, with the slot size the
            // parent forwarded - i.e. the poster's declared
            // `unpacked_size`. At level 0 the slot size comes from the NZB
            // and is below the posted ceiling by construction, so the cap
            // never binds there and preallocation is untouched.
            let size = inner.slots[slot].size;
            let cap = inner.limits.prealloc_cap();
            let w = if self.resume {
                FileWriter::create_resume_capped(&path, size, cap)?
            } else {
                FileWriter::create_capped(&path, size, cap)?
            };
            // Only a NESTED plain file is extraction output. Level 0's
            // plain files are the downloaded volumes themselves, which the
            // disk-path `BombGuardWriter` does not count either.
            let w = if self.depth > 0 {
                w.with_budget(inner.limits.budget.clone())
            } else {
                w
            };
            inner.slots[slot].writer = Some(Arc::new(w));
        }
        Ok(inner.slots[slot].writer.clone().unwrap())
    }

    /// Claim an output filename in the chain-shared set, disambiguating
    /// on collision. Shared with nested children, so a child's plain file
    /// can never silently overwrite (or be overwritten by) another
    /// level's output of the same name.
    fn claim_name(inner: &Inner, slot: usize, out: &mut String) {
        let fold = inner.fold_names;
        let mut names = inner.names_taken.lock_ok();
        if names.insert(name_collision_key(fold, out)) {
            return;
        }
        let mut n = 0usize;
        loop {
            let cand = if n == 0 {
                format!("{slot:03}-{out}")
            } else {
                format!("{slot:03}-{n}-{out}")
            };
            if names.insert(name_collision_key(fold, &cand)) {
                *out = cand;
                return;
            }
            n += 1;
        }
    }

    /// Plain write-through under the lock (fallback/drain paths where the
    /// data is locally owned).
    fn plain_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let w = self.ensure_plain_writer(inner, slot)?;
        w.write_at(offset, data)
    }

    /// Deliver queued child forwards. Never called with the routing lock
    /// held - each job re-resolves its destination in
    /// [`Self::deliver_routed`], so a slot that fell back (or a child
    /// slot a merge displaced) in any window still gets its bytes.
    fn deliver_fwd(&self, pending: Vec<FwdJob>) -> io::Result<()> {
        for j in pending {
            self.deliver_routed(
                j.parent_slot,
                j.vol_off,
                &j.name,
                j.size,
                j.file_off,
                &j.bytes,
                j.repair,
            )?;
        }
        Ok(())
    }

    /// Deliver one routed span to whatever destination the routing map
    /// names NOW, re-resolving under the lock until the write has landed
    /// somewhere still live. Between capture and delivery a group merge
    /// can displace the child slot routing picked and abandon it - a
    /// write into an abandoned slot is silently swallowed while the
    /// span's bytes were already composed into the piece CRCs, so
    /// delivering by stale slot index could let the finish gate vouch
    /// for a hole. The loop is bounded by the number of merges (each
    /// retry means the destination changed again), and duplicate
    /// deliveries land on identical offsets (routing is deterministic),
    /// so retries are harmless. Never called with the routing lock held.
    #[allow(clippy::too_many_arguments)]
    fn deliver_routed(
        &self,
        parent_slot: usize,
        vol_off: u64,
        name: &str,
        size: u64,
        file_off: u64,
        bytes: &[u8],
        repair: bool,
    ) -> io::Result<Persist> {
        enum Target {
            Child(Arc<Extractor>, usize),
            Writer(Arc<FileWriter>),
            Done,
        }
        loop {
            let tgt = {
                let mut g = self.inner.lock_ok();
                let inner = &mut *g;
                match inner.slots[parent_slot].mode {
                    SlotMode::Rar => match Self::dest_for(inner, parent_slot, name) {
                        Some(Dest::Child(c, cs)) => Target::Child(c, cs),
                        Some(Dest::Writer(w)) => Target::Writer(w),
                        // The routed entry vanished while the slot still
                        // maps (structurally unexpected): materialize the
                        // slot rather than drop bytes the piece CRCs
                        // already counted.
                        None => {
                            self.fallback_slot_or_group(
                                inner,
                                parent_slot,
                                "routed span lost its destination",
                            )?;
                            if !matches!(inner.slots[parent_slot].mode, SlotMode::Discard) {
                                self.plain_span(inner, parent_slot, vol_off, bytes)?;
                            }
                            Target::Done
                        }
                    },
                    SlotMode::Plain | SlotMode::RarFallback => {
                        self.plain_span(inner, parent_slot, vol_off, bytes)?;
                        Target::Done
                    }
                    // A chase-eligible slot blocks on its FIRST entry, so
                    // it can never have routed a forward while mapped -
                    // nothing to deliver.
                    SlotMode::Unknown
                    | SlotMode::RarChase
                    | SlotMode::SevenZ
                    | SlotMode::Discard => Target::Done,
                }
            };
            match tgt {
                Target::Done => return Ok(Persist::No),
                Target::Writer(w) => {
                    w.write_at(file_off, bytes)?;
                    return Ok(Persist::No);
                }
                Target::Child(c, cs) => {
                    // No article CRC across the boundary: these are mapped
                    // sub-ranges of OUR span, and the child's own article
                    // boundaries are its own.
                    let p = c.write_impl(cs, name, size, file_off, bytes, repair, None)?;
                    // Promotion probe BEFORE re-taking our lock (child and
                    // parent locks are never nested, in either order).
                    let promote = c.stable_plain_writer(cs);
                    let mut g = self.inner.lock_ok();
                    let inner = &mut *g;
                    match inner.slots[parent_slot].mode {
                        SlotMode::Rar => {
                            let live = matches!(
                                Self::dest_for(inner, parent_slot, name),
                                Some(Dest::Child(ref c2, cs2)) if Arc::ptr_eq(c2, &c) && cs2 == cs
                            );
                            if live {
                                // The route still points at this child and
                                // its slot is stably Plain: later articles
                                // skip the whole ladder (Finding 4).
                                if let Some(w) = promote
                                    && let Some(gk) = inner.slots[parent_slot].group.clone()
                                    && let Some(grp) = inner.groups.get_mut(&gk)
                                    && grp.routed.get(name) == Some(&cs)
                                {
                                    grp.routed_plain.insert(name.to_string(), (cs, w));
                                }
                                return Ok(p);
                            }
                            // Displaced mid-delivery - resolve again.
                        }
                        SlotMode::Plain | SlotMode::RarFallback => {
                            self.plain_span(inner, parent_slot, vol_off, bytes)?;
                            return Ok(Persist::No);
                        }
                        _ => return Ok(Persist::No),
                    }
                }
            }
        }
    }

    /// Take and deliver any queued child forwards (public entry points
    /// that may have re-fed holds under the lock call this after it
    /// drops).
    /// Run the tail-prefetch promotes queued under the routing lock.
    /// Off-lock by construction: `promote_file` walks up the chain
    /// taking one level's lock at a time, so calling it from under this
    /// level's own lock self-deadlocks.
    fn flush_pending_promote(&self) {
        let queued = std::mem::take(&mut self.inner.lock_ok().pending_promote);
        for (slot, spans, urgent) in queued {
            self.promote_slot_spans(slot, &spans, urgent);
        }
    }

    fn flush_pending_fwd(&self) -> io::Result<()> {
        self.flush_pending_promote();
        let pending = std::mem::take(&mut self.inner.lock_ok().pending_fwd);
        if pending.is_empty() {
            return Ok(());
        }
        self.deliver_fwd(pending)
    }

    /// Keep the parts of a span not covered by any data area (header/meta
    /// bytes below the parse cursor) for byte-exact reconstruction.
    /// Returns the bytes newly stashed; they are charged to the shared
    /// holds budget here and released wherever the stash is dropped.
    fn retain_header_bytes(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> usize {
        let s = &mut inner.slots[slot];
        let Some(m) = s.mapper.as_ref() else { return 0 };
        let mut covered: Vec<(u64, u64)> = m
            .map_span(offset, data.len() as u64)
            .into_iter()
            .map(|(_, _, span_off, len)| (span_off, span_off + len))
            .collect();
        covered.sort_unstable();
        let mut pos = 0u64;
        let mut keep: Vec<(u64, u64)> = Vec::new();
        for (cs, ce) in covered {
            if cs > pos {
                keep.push((pos, cs));
            }
            pos = pos.max(ce);
        }
        if pos < data.len() as u64 {
            keep.push((pos, data.len() as u64));
        }
        let mut stashed = 0usize;
        for (ks, ke) in keep {
            let abs_s = offset + ks;
            if abs_s >= m.mapped_through() {
                continue; // not header - just not-yet-mapped data
            }
            let abs_e = (offset + ke).min(m.mapped_through());
            if abs_e > abs_s {
                let part = data[ks as usize..(abs_e - offset) as usize].to_vec();
                stashed += part.len();
                s.header_spans.push((abs_s, HoldSpan::Ram(part)));
            }
        }
        inner.budget.add(stashed);
        stashed
    }

    /// Unlink a slot's own file and release the name it claimed. Used
    /// when a trimmed 7z chase SUCCEEDS: the spilled prefix is a
    /// truncated archive whose payload already shipped by another route.
    fn drop_slot_file(inner: &mut Inner, slot: usize) {
        let Some(w) = inner.slots[slot].writer.take() else {
            return;
        };
        let _ = std::fs::remove_file(&w.path);
        let name = w
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        inner
            .names_taken
            .lock()
            .unwrap()
            .remove(&name_collision_key(inner.fold_names, &name));
    }

    /// Ask the chain above to front-load the outer articles carrying
    /// `spans` of this slot's byte space (7z tail prefetch). A slot's
    /// byte space IS its level-N file's byte space, and that file is an
    /// entry of the parent's groups - so the parent handles it as a
    /// file promote. At the ROOT there is no parent and none is needed:
    /// the slot is a posted file already, so it goes straight to this
    /// level's own hook.
    fn promote_slot_spans(&self, slot: usize, spans: &[(u64, u64)], urgent: bool) {
        let (name, size) = {
            let inner = self.inner.lock_ok();
            (inner.slots[slot].name.clone(), inner.slots[slot].size)
        };
        if name.is_empty() || size == 0 {
            return;
        }
        let name = sanitize_filename(&name);
        match self.parent.upgrade() {
            Some(p) => p.promote_file(&name, size, spans, urgent),
            // The ROOT: a slot here is a POSTED file, so its byte space
            // is already the byte space the installed hook resolves to
            // articles - no translation left to do, hand it straight
            // over. This used to be `else { return }`, which silently
            // no-opped, which is why a top-level 7z never got its tail
            // front-loaded even after the depth guard came off.
            None => self.promote_file(&name, size, spans, urgent),
        }
    }

    /// Promote byte spans of file `name` (an inner file of one of THIS
    /// extractor's groups): the root hands them to the installed hook
    /// (the daemon's seek/promote ladder resolves them to articles);
    /// a level below the root translates them to its own slot ranges
    /// via [`Self::map_output_range`] and recurses upward - the §3b
    /// map_to_root composition. All-store levels only by construction:
    /// a chased (compressed) level yields no offset mapping, so the
    /// promote quietly stops there. Never called with any routing lock
    /// held; each level takes only its own lock, one at a time.
    fn promote_file(&self, name: &str, size: u64, spans: &[(u64, u64)], urgent: bool) {
        let hook = self.inner.lock_ok().promote.clone();
        if let Some(h) = hook {
            h(name, size, spans, urgent);
            return;
        }
        let Some(p) = self.parent.upgrade() else {
            return;
        };
        let mut per_slot: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();
        for &(s, e) in spans {
            if s >= e {
                continue;
            }
            for (slot, vs, ve, _) in self.map_output_range(name, s, e) {
                if vs < ve {
                    per_slot.entry(slot).or_default().push((vs, ve));
                }
            }
        }
        for (slot, ranges) in per_slot {
            let (sname, ssize) = {
                let inner = self.inner.lock_ok();
                (inner.slots[slot].name.clone(), inner.slots[slot].size)
            };
            if sname.is_empty() {
                continue;
            }
            p.promote_file(&sanitize_filename(&sname), ssize, &ranges, urgent);
        }
    }

    /// Base offset of (slot, entry) within its inner file: 0 for pieces
    /// that start a file; group-resolved for split continuations.
    fn base_for(inner: &Inner, slot: usize, ei: usize) -> Option<u64> {
        let m = inner.slots[slot].mapper.as_ref()?;
        if !m.entries[ei].split_before {
            return Some(0);
        }
        let key = inner.slots[slot].group.as_ref()?;
        inner.groups.get(key)?.bases.get(&(slot, ei)).copied()
    }

    /// Route the mapped parts of a span into inner files or the nested
    /// child (queued when the caller collects a sink, inline/pending
    /// otherwise); hold the rest.
    fn extract_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<()> {
        // Reuse the Inner-owned hit buffer: this runs under the routing
        // lock for every article, and the per-article Vec was measurable
        // allocator traffic. A re-entrant call (fallback re-feed) takes
        // an empty fresh vector and simply allocates like before.
        let mut hits = std::mem::take(&mut inner.map_scratch);
        {
            let m = inner.slots[slot].mapper.as_ref().unwrap();
            m.map_span_into(offset, data.len() as u64, &mut hits);
        }
        let result =
            self.extract_span_hits(inner, slot, offset, data, sink, repair, article_crc, &hits);
        hits.clear();
        inner.map_scratch = hits;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_span_hits(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        mut sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
        hits: &[(usize, u64, u64, u64)],
    ) -> io::Result<()> {
        // The yEnc decode already computed and CHECKED this article's
        // CRC32 over exactly these bytes. When the article maps to a
        // single STORE data range covering the whole buffer, that value
        // IS the CRC the stored-file composition needs, so the second
        // scan over ~700 KiB is pure waste (measured on a real corpus:
        // 98.75% of STORE payload bytes qualify; the exceptions are the
        // header-bearing first article, the trailing article, volume and
        // member boundaries, and multi-entry spans).
        //
        // Every reuse condition is checked, not assumed: the CRC exists
        // and matched (`article_crc` is None otherwise, including on the
        // bare-LF scalar path and under delegated verification), this is
        // not a repair rewrite (its bytes deliberately DIFFER from what
        // composed earlier), the entry is `checkable` (unencrypted store,
        // not a directory) at the use site, and the range is untouched -
        // `add_run` refuses an overlap and the hash path takes over. A
        // single hit spanning the whole buffer is what makes the mapped
        // range byte-for-byte the decoded output.
        let single_whole_hit = matches!(
            hits,
            [(_, _, 0, len)] if *len == data.len() as u64
        );
        let whole_article = single_whole_hit && !repair && article_crc.is_some();
        let mut covered_end = offset;
        for &(ei, piece_off, span_off, len) in hits {
            covered_end = covered_end.max(offset + span_off + len);
            let base = match Self::base_for(inner, slot, ei) {
                Some(b) => b,
                None => {
                    let part = data[span_off as usize..(span_off + len) as usize].to_vec();
                    inner.budget.add(part.len());
                    inner.slots[slot]
                        .holds
                        .push((offset + span_off, HoldSpan::Ram(part)));
                    if inner.budget.over() && !self.page_out_holds(inner) {
                        // Write the whole article through after the
                        // demote, exactly as the sibling demote routes do
                        // (header-stash, blocker, joined-fallen-group).
                        // This `return` is from INSIDE the hits loop, so
                        // every remaining hit of a multi-entry span was
                        // otherwise never queued, forwarded or held - and
                        // the compensating whole-span rewrite in
                        // write_impl_scratched is gated on there being
                        // queued work, which there is not. The volume
                        // then materialized with a sparse hole that
                        // preads as zeros and failed the inner file's
                        // CRC. "A lost span is silent corruption" is
                        // stated a few hundred lines up; this was the one
                        // route that broke it. plain_span writes at the
                        // volume offset, which is what a materialized
                        // volume wants; the already-drained holds rewrite
                        // identical bytes, which the other routes accept
                        // too. The Discard check keeps protect_sources
                        // from opening a writer over a source file.
                        self.fallback_slot_or_group(inner, slot, "held-bytes cap")?;
                        if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                            return Ok(());
                        }
                        return self.plain_span(inner, slot, offset, data);
                    }
                    continue;
                }
            };
            // POD fields only - the entry NAME stays in the mapper and the
            // routing lookups borrow it in place (route_dest/crypto_for key
            // by (slot, ei)). Cloning it here cost a String per article
            // under the routing lock; only the child-forward arms, which
            // queue owned work, still materialize one.
            let (total, encrypted, checkable) = {
                let m = inner.slots[slot].mapper.as_ref().unwrap();
                let e = &m.entries[ei];
                (
                    e.unpacked_size,
                    e.encrypted,
                    matches!(e.method, Method::Store) && !e.encrypted && !e.is_dir,
                )
            };
            // Compose the routed bytes' CRC32 per piece for the
            // finish-time check against the header CRC (encrypted
            // entries have their own post-decrypt check). Nested levels
            // always compose; level 0's PAR2 only vouches for the outer
            // bytes AS POSTED, so the final store payload gets the same
            // treatment under the verify_output_crc gate (default on;
            // `NZBFAST_NO_OUTPUT_CRC=1` restores the skip). A repair
            // span overwrites: its bytes REPLACE a range that may have
            // composed wire-damaged bytes earlier, and clipping it as a
            // duplicate would keep the stale CRC while the file heals.
            if (self.depth > 0 || inner.verify_output_crc) && checkable {
                let part = &data[span_off as usize..(span_off + len) as usize];
                let runs = inner.slots[slot].piece_crcs.entry(ei).or_default();
                if repair {
                    runs.overwrite(piece_off, part);
                } else if !(whole_article && runs.add_run(piece_off, len, article_crc.unwrap())) {
                    // Not the exact-article case, or the range was already
                    // (partly) composed: hash the routed bytes as before.
                    runs.add(piece_off, part);
                }
            }
            match self.route_dest(inner, slot, ei, total, encrypted)? {
                Dest::Writer(w) => {
                    // Plaintext-once: an encrypted store span decrypts at
                    // write time instead of assembling ciphertext for the
                    // finish pass. The state needs the HEAD entry's crypt
                    // parameters; a continuation piece racing its head
                    // volume's headers holds like an unresolved base.
                    // An output that is already plaintext-once must STAY
                    // plaintext-once, whatever the live password cell now
                    // holds. The gate re-reads `inner.password` per span,
                    // so a mid-download re-key - `apply_probed_password`
                    // overwrites it unconditionally, and the probe is
                    // installed on every job - flipped it false for a
                    // file already being decrypted in-stream (one job may
                    // legitimately carry two encrypted sets with
                    // different passwords). Later spans then took the
                    // `crypto == None` path and pwrote RAW CIPHERTEXT at
                    // the offsets plaintext belonged at. Consulting the
                    // writer-keyed state FIRST is strictly narrowing: it
                    // changes behaviour only for a writer whose password
                    // was already check-verified before its first byte
                    // was written.
                    let existing = Self::crypto_of(inner, &w);
                    let crypto = if existing.is_some() {
                        existing
                    } else if encrypted
                        && inner.instream_decrypt
                        && Self::instream_decrypt_allowed(inner, slot, ei)
                    {
                        match Self::crypto_for(inner, slot, ei, &w) {
                            Some(cs) => {
                                // Plaintext-once is live for this set:
                                // the badge says "one-pass", not
                                // "unlocked at the end".
                                self.shape.note(self.depth, SH_ENC_INSTREAM);
                                Some(cs)
                            }
                            None => {
                                let part =
                                    data[span_off as usize..(span_off + len) as usize].to_vec();
                                inner.budget.add(part.len());
                                inner.slots[slot]
                                    .holds
                                    .push((offset + span_off, HoldSpan::Ram(part)));
                                if inner.budget.over() && !self.page_out_holds(inner) {
                                    // Same write-through as the hold arm
                                    // above - this return also leaves the
                                    // rest of a multi-entry span
                                    // unwritten. See the comment there.
                                    self.fallback_slot_or_group(inner, slot, "held-bytes cap")?;
                                    if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                                        return Ok(());
                                    }
                                    return self.plain_span(inner, slot, offset, data);
                                }
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    match sink.as_mut() {
                        Some((jobs, _)) => jobs.push(WriteJob {
                            writer: w,
                            file_off: base + piece_off,
                            src_start: span_off as usize,
                            len: len as usize,
                            crypto,
                            repair,
                        }),
                        // Under-the-lock re-feed (drain_holds/reresolve):
                        // cold path, so the AES here is acceptable.
                        None => {
                            let part = &data[span_off as usize..(span_off + len) as usize];
                            match &crypto {
                                Some(cs) if repair => cs.patch(&w, base + piece_off, part)?,
                                Some(cs) => cs.ingest(&w, base + piece_off, part)?,
                                None => w.write_at(base + piece_off, part)?,
                            }
                        }
                    }
                }
                Dest::Child(..) => {
                    let name = Self::entry_name(inner, slot, ei).to_string();
                    match sink.as_mut() {
                        Some((_, fwd)) => fwd.push(FwdSpan {
                            name,
                            size: total,
                            file_off: base + piece_off,
                            src_start: span_off as usize,
                            len: len as usize,
                            repair,
                        }),
                        // Under-the-lock re-feed: the child cannot be called
                        // here (it defers pwrites behind its own lock), so
                        // queue an owned copy for flush_pending_fwd. Cold
                        // paths only - the hot write path always has a sink.
                        None => inner.pending_fwd.push(FwdJob {
                            parent_slot: slot,
                            vol_off: offset + span_off,
                            name,
                            size: total,
                            file_off: base + piece_off,
                            bytes: data[span_off as usize..(span_off + len) as usize].to_vec(),
                            repair,
                        }),
                    }
                }
            }
            inner.extracted_bytes += len;
        }
        // Anything past the mapped region: hold until headers advance.
        let m = inner.slots[slot].mapper.as_ref().unwrap();
        let span_end = offset + data.len() as u64;
        let unmapped_from = covered_end.max(m.mapped_through()).max(offset);
        if unmapped_from < span_end && !m.complete {
            let part = data[(unmapped_from - offset) as usize..].to_vec();
            inner.budget.add(part.len());
            inner.slots[slot]
                .holds
                .push((unmapped_from, HoldSpan::Ram(part)));
            if inner.budget.over() && !self.page_out_holds(inner) {
                return self.fallback_slot_or_group(inner, slot, "held-bytes cap");
            }
        }
        Ok(())
    }

    /// The in-stream decrypt state for entry `name`'s output (keyed by
    /// the writer's on-disk filename), created on first touch from the
    /// HEAD entry's crypt parameters. None while the head volume's
    /// headers have not been seen (the caller holds the span) or when no
    /// usable key exists - the latter cannot normally happen, because an
    /// encrypted entry only maps after the stored password check passed.
    /// The RAW entry name behind `(slot, ei)` - the routing key. Borrowed
    /// in place: the article hot path must not clone a String per span.
    fn entry_name(inner: &Inner, slot: usize, ei: usize) -> &str {
        &inner.slots[slot].mapper.as_ref().unwrap().entries[ei].name
    }

    /// The destination for `slot`'s view of inner file `name` - decided
    /// once per (group, name) and sticky thereafter, so write-side routing
    /// and read-side delegation always agree. Non-encrypted files route
    /// into the nested child (whose offset-0 sniff classifies them: RAR
    /// store maps on, everything else lands as a plain file, exactly the
    /// single-level output). Encrypted entries stay on the direct writer
    /// path - the ciphertext-at-store-offsets assembly and the finish
    /// decrypt own that lifecycle.
    fn route_dest(
        &self,
        inner: &mut Inner,
        slot: usize,
        ei: usize,
        total: u64,
        encrypted: bool,
    ) -> io::Result<Dest> {
        // Group identity is the RAW entry name, not its sanitized form: two
        // distinct archive entries whose names sanitize alike (e.g. "a/b.txt"
        // and "a_b.txt" both -> "a_b.txt") must get SEPARATE child slots and
        // writers, or the second silently overwrites/interleaves the first at
        // offset 0. The same raw name across split volumes still maps to one
        // output (the intended "one inner file, many pieces" case). The
        // sanitized form is used only to derive the on-disk filename, in
        // inner_writer/claim_name.
        // Reaching here means the fast path owns this inner file - its
        // bytes go straight to their destination and the volumes never
        // land. That is what "one-pass" on the badge means.
        //
        // This runs per span under the routing lock: the lookups below
        // borrow the group key and entry name in place (cloning them cost
        // two Strings per article); only the once-per-file route insert
        // owns anything.
        self.shape.note(self.depth, SH_ONE_PASS);
        let mut route_new = None;
        if let Some(gk) = inner.slots[slot].group.as_ref() {
            let key = Self::entry_name(inner, slot, ei);
            // Promoted plain child: write straight to its file. The route
            // still exists in `routed` for fallback/finish; only the hot
            // path skips the child extractor.
            // `!encrypted` is load-bearing, not belt-and-braces. Under the
            // pre-promotion ladder a name in `routed` returned Dest::Child,
            // and the Child arm has no crypto handling at all, so an
            // encrypted span could never reach a decrypt path through a
            // routed name. Promotion turns the same name into Dest::Writer,
            // which DOES run the in-stream decrypt arm (instream_decrypt
            // defaults on). An archive where one raw name appears as a plain
            // STORE piece in one volume and an encrypted one in another would
            // then have the parent create a CryptoState keyed by a
            // child-owned filename, journal E/K/T records for a file it does
            // not own, and AES-decrypt into the child's plain output. Falling
            // through to the Child arm keeps the old structural exclusion.
            if !encrypted
                && let Some((_, w)) = inner.groups.get(gk).and_then(|g| g.routed_plain.get(key))
            {
                return Ok(Dest::Writer(Arc::clone(w)));
            }
            if let Some(&cs) = inner.groups.get(gk).and_then(|g| g.routed.get(key)) {
                let c = inner.child.clone().expect("routed name without a child");
                return Ok(Dest::Child(c, cs));
            }
            let already_written = inner
                .groups
                .get(gk)
                .is_some_and(|g| g.out_names.contains_key(key));
            if !already_written && inner.nested_on && !encrypted {
                route_new = Some((gk.clone(), key.to_string()));
            }
        }
        if let Some((gk, key)) = route_new {
            let child = self.ensure_child(inner);
            let cs = child.alloc_slot();
            inner.groups.get_mut(&gk).unwrap().routed.insert(key, cs);
            return Ok(Dest::Child(child, cs));
        }
        Ok(Dest::Writer(self.inner_writer(inner, slot, ei, total)?))
    }

    /// The output writer for `name` as seen by `slot`'s group. Output
    /// files are group-owned: two archives in one NZB that reuse an inner
    /// filename each get their own file (the second is disambiguated),
    /// instead of interleaving writes into one writer at conflicting
    /// offsets - inner files are not PAR2-covered, so that corruption was
    /// silent and deterministic.
    fn inner_writer(
        &self,
        inner: &mut Inner,
        slot: usize,
        ei: usize,
        total: u64,
    ) -> io::Result<Arc<FileWriter>> {
        // Keyed on the RAW name (see route_dest); the sanitized form is only
        // the on-disk filename. Distinct raw names that sanitize alike get
        // distinct writers (claim_name disambiguates the on-disk name).
        //
        // The existing-writer lookups run per span under the routing lock
        // (encrypted sets never route to a child, so THIS is their hot
        // path) and borrow the key and group in place; only the
        // once-per-file creation below owns strings.
        let key = Self::entry_name(inner, slot, ei);
        match inner.slots[slot].group.as_ref() {
            Some(gk) => {
                if let Some(out) = inner.groups.get(gk).and_then(|g| g.out_names.get(key))
                    && let Some(w) = inner.inner_writers.get(out)
                {
                    return Ok(w.clone());
                }
            }
            None => {
                if let Some(w) = inner.inner_writers.get(sanitize_filename(key).as_str()) {
                    return Ok(w.clone());
                }
            }
        }
        let key = key.to_string();
        let fname = sanitize_filename(&key);
        let gkey = inner.slots[slot].group.clone();
        let mut out = fname;
        Self::claim_name(inner, slot, &mut out);
        let path = self.out_dir.join(&out);
        // `total` is the entry's declared `unpacked_size` - an untrusted
        // header vint. It stays the writer's `size` (resume truncation and
        // the reported extracted size both depend on it) but it does NOT
        // get to reserve the disk: the reservation is capped at the
        // chain's ceiling, and the extracted bytes are charged against the
        // chain's bomb budget. See [`Limits`].
        let cap = inner.limits.prealloc_cap();
        let budget = inner.limits.budget.clone();
        let w = Arc::new(
            if self.resume {
                FileWriter::create_resume_capped(&path, total, cap)?
            } else {
                FileWriter::create_capped(&path, total, cap)?
            }
            .with_budget(budget),
        );
        inner.inner_writers.insert(out.clone(), w.clone());
        if let Some(gk) = gkey
            && let Some(g) = inner.groups.get_mut(&gk)
        {
            g.out_names.insert(key, out);
        }
        Ok(w)
    }

    /// Resolve `slot`'s view of an inner-file name to its destination -
    /// the read-side mirror of `route_dest`, consulting the group's
    /// routed map first so delegation always agrees with routing.
    fn dest_for(inner: &Inner, slot: usize, entry_name: &str) -> Option<Dest> {
        // Keyed on the RAW name, matching route_dest/inner_writer.
        if let Some(gk) = inner.slots[slot].group.as_ref()
            && let Some(g) = inner.groups.get(gk)
        {
            if let Some(&cs) = g.routed.get(entry_name) {
                return inner.child.clone().map(|c| Dest::Child(c, cs));
            }
            if let Some(out) = g.out_names.get(entry_name) {
                return inner.inner_writers.get(out).cloned().map(Dest::Writer);
            }
        }
        inner
            .inner_writers
            .get(&sanitize_filename(entry_name))
            .cloned()
            .map(Dest::Writer)
    }

    /// Unlink and forget every output file a group owns (fallback: the
    /// bytes were reconstructed into the volume files, and a sparse
    /// half-written "extracted" file would masquerade as output). Only
    /// files in the group's own `out_names` are touched - a file another
    /// group is still extracting is structurally unreachable from here.
    /// Routed inner files are abandoned in the child by the same
    /// ownership argument: the child slots drained here belong to this
    /// group alone.
    fn delete_group_out_files(inner: &mut Inner, key: &str) {
        let (outs, routed): (Vec<String>, Vec<usize>) = match inner.groups.get_mut(key) {
            Some(g) => {
                g.routed_plain.clear();
                (
                    g.out_names.drain().map(|(_, v)| v).collect(),
                    g.routed.drain().map(|(_, v)| v).collect(),
                )
            }
            None => return,
        };
        for out in outs {
            if let Some(w) = inner.inner_writers.remove(&out) {
                let _ = std::fs::remove_file(&w.path);
                inner
                    .names_taken
                    .lock()
                    .unwrap()
                    .remove(&name_collision_key(inner.fold_names, &out));
            }
        }
        if let Some(c) = inner.child.clone() {
            for cs in routed {
                c.abandon_slot(cs);
            }
        }
    }

    /// Parent-group fallback support: this routed slot's bytes were (or
    /// will be) reconstructed into the parent's materialized volumes, so
    /// drop everything it produced - holds, its own file, and the group
    /// outputs once every member slot is abandoned - and swallow all
    /// future spans. Silent by design: the parent already reported the
    /// fallback, a child-side entry would double-count it.
    fn abandon_slot(&self, slot: usize) {
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        if matches!(inner.slots[slot].mode, SlotMode::Discard) {
            return;
        }
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        for (_, span) in &holds {
            Self::uncharge_span(inner, span);
        }
        inner.slots[slot].pre_bytes = 0;
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (_, span) in &headers {
            Self::uncharge_span(inner, span);
        }
        inner.slots[slot].piece_crcs = HashMap::new();
        if let Some(ch) = inner.slots[slot].chase.take() {
            inner.budget.sub(ch.charged);
            ch.buf.abort("slot abandoned");
        }
        // An abandoned 7z chase dies with the slot: buffer already
        // aborted above (the worker exits on its next read), and its
        // partial sink outputs go too. The sink-open path re-checks the
        // slot's mode under this lock, so no NEW sink can appear after.
        // The ctl stays in the slot so sevenz_finish / Drop still find
        // and join the worker.
        if let Some(ctl) = inner.slots[slot].sevenz.clone() {
            self.sevenz_abandon_sinks(inner, &ctl);
        }
        // No mapper means finish() sees neither holds nor an incomplete
        // parse here - an abandoned slot must not read as a fallback.
        inner.slots[slot].mapper = None;
        if let Some(w) = inner.slots[slot].writer.take() {
            let _ = std::fs::remove_file(&w.path);
            let name = w
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            inner
                .names_taken
                .lock()
                .unwrap()
                .remove(&name_collision_key(inner.fold_names, &name));
        }
        inner.slots[slot].mode = SlotMode::Discard;
        if let Some(key) = inner.slots[slot].group.clone() {
            let all_gone = inner.groups.get(&key).is_some_and(|g| {
                g.slots
                    .iter()
                    .all(|&si| matches!(inner.slots[si].mode, SlotMode::Discard))
            });
            if all_gone {
                // The group's chase (if any) dies with its last slot -
                // the worker stops, partial sink outputs go too.
                if let Some(ctl) = inner.groups.get(&key).and_then(|g| g.chase.clone()) {
                    self.chase_teardown(inner, &ctl, "group abandoned");
                }
                Self::delete_group_out_files(inner, &key);
            }
        }
    }

    /// Follow the alias chain from an inner-file name to the canonical
    /// group key that owns it (itself when unlinked).
    fn canon_key(inner: &Inner, name: &str) -> String {
        let mut k = name;
        for _ in 0..64 {
            match inner.alias.get(k) {
                Some(next) if next != k => k = next,
                _ => break,
            }
        }
        k.to_string()
    }

    /// The slot's writer, if it has stably classified as a plain file:
    /// mode Plain, writer created, no held spans, no chase or 7z engine.
    /// Plain is terminal for a slot, so a caller may cache the writer
    /// (Finding 4); takes only OUR lock, so callers must not hold any
    /// other extractor's lock (parent<->child nesting deadlocks).
    fn stable_plain_writer(&self, slot: usize) -> Option<Arc<FileWriter>> {
        let inner = self.inner.lock_ok();
        let s = inner.slots.get(slot)?;
        if s.mode == SlotMode::Plain
            && s.holds.is_empty()
            && s.chase.is_none()
            && s.sevenz.is_none()
        {
            s.writer.clone()
        } else {
            None
        }
    }

    /// Poison-tolerant lock acquisition for the READ-ONLY accessors
    /// (`read_at` / `covered` / `covered_intervals` / `open_stream` /
    /// `writers_snapshot` / `map_output_range`). The daemon's stream
    /// server and verifier call these concurrently with the decode
    /// threads, so a single panic on a thread holding the routing lock
    /// would otherwise turn every later accessor call into a poison
    /// panic - wedging live /stream and stats reads for the rest of the
    /// job. Recovering the guard here is sound because these paths only
    /// OBSERVE a snapshot: whatever partial mutation the panicking
    /// thread left behind is exactly the state Drop-side recovery
    /// already exposes, a subsequent read cannot make it worse, and
    /// poisoning is purely advisory (no memory safety is at stake - the
    /// worst case is a read that reflects a half-applied routing step,
    /// which the interval/coverage checks already treat as "not there
    /// yet"). Write/mutate paths keep the strict unwrap on purpose: a
    /// poisoned lock there signals state too suspect to EXTEND, and
    /// failing loud beats folding more data into it.
    fn inner_read(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock_ok()
    }

    /// Close the OS handle on every output file this extractor holds, at this
    /// level and every nested one, so an EXTERNAL process can open them
    /// exclusively. Pair with [`unpark_outputs`] - always, and on every exit
    /// path - and see [`FileWriter::park`] for what parking does and does not
    /// disturb.
    ///
    /// This exists for the external-par2 repair fallback: par2cmdline opens
    /// its targets with share mode 0, so on Windows any handle we still hold
    /// makes its open fail and it reports the file missing and declines to
    /// repair (measured: `Could not open "payload.bin"` → `Target: missing` →
    /// `Repair is not possible`). Nested levels wrote into the same tree and
    /// pin it too, hence the recursion.
    ///
    /// Needed because [`finish`] syncs the writers but KEEPS them: the
    /// extractor holds output handles for the streaming endpoint's benefit,
    /// and it stays alive well past completion (the daemon leaves it installed
    /// for post-completion streaming, and the fetch task holds its own `Arc`
    /// until it returns). So the handles are still there at repair time, which
    /// runs BEFORE `finish` - and that ordering is why these park rather than
    /// close: `finish` has yet to settle groups, verify inner CRCs and run the
    /// decrypt pass, all of which need live writers.
    ///
    /// Deliberately NOT used for the Windows folder rename that first
    /// motivated closing handles at all: that went in as
    /// `smart::move_dir_contents`, which moves the directory's CONTENTS and
    /// needs no handles closed. Parking is visible to a concurrent /stream
    /// read (it gets `NotConnected` instead of bytes), which is the honest
    /// answer while an external tool rewrites those very bytes, but it is not
    /// something to inflict on a path that has a handle-free alternative.
    ///
    /// [`unpark_outputs`]: Extractor::unpark_outputs
    /// [`FileWriter::park`]: crate::disk::FileWriter::park
    pub fn park_outputs(&self) -> io::Result<()> {
        self.each_output(&|w| w.park())
    }

    /// Reopen everything [`park_outputs`] closed, at this level and every
    /// nested one. Idempotent, so it is safe to call on an error path that may
    /// or may not have parked.
    ///
    /// [`park_outputs`]: Extractor::park_outputs
    pub fn unpark_outputs(&self) -> io::Result<()> {
        self.each_output(&|w| w.unpark())
    }

    /// Apply `f` to every live output writer at this level and below,
    /// attempting ALL of them and returning the first error. Attempting all
    /// matters on the unpark side: bailing at the first failure would leave
    /// the rest of the tree parked and every later write to them failing.
    fn each_output(&self, f: &dyn Fn(&FileWriter) -> io::Result<()>) -> io::Result<()> {
        let (writers, child) = {
            let g = self.inner.lock_ok();
            let mut ws: Vec<Arc<FileWriter>> = g.inner_writers.values().cloned().collect();
            ws.extend(g.slots.iter().filter_map(|s| s.writer.clone()));
            (ws, g.child.clone())
        };
        // Cloned out from under the lock: park/unpark do file I/O (an fsync on
        // a multi-GB output is not instant), and holding the routing lock
        // across it would block the daemon's stats and stream calls.
        let mut first_err: Option<io::Error> = None;
        for w in &writers {
            if let Err(e) = f(w) {
                first_err.get_or_insert(e);
            }
        }
        if let Some(c) = child
            && let Err(e) = c.each_output(f)
        {
            first_err.get_or_insert(e);
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// End-of-download: settle groups that never finished mapping, flush
    /// stray holds, sync writers, and report. A nested child finishes
    /// BEFORE this level's sync phase - its own settle demotes any
    /// unfinished child slot to a materialized level-1 file (today's
    /// output), and its report folds into ours.
    pub fn finish(&self) -> io::Result<ExtractReport> {
        // Parked password-awaits resolve FIRST (Increment A): a hit here
        // re-keys and re-feeds while every held byte is still in RAM -
        // the set then settles/decrypts below like any start-time
        // password job - and a miss demotes before the group settle
        // reasons about volumes.
        self.resolve_pw_awaits()?;
        // Chase workers join FIRST: their sink writes must have landed
        // before the child settles/finishes, and a chase still blocked
        // here (bytes never arrived) aborts and demotes. The 7z workers
        // follow the same contract.
        self.chase_finish()?;
        self.sevenz_finish()?;
        self.settle_groups()?;
        // Settle re-fed holds under the lock; any child forwards it
        // queued must land before the child settles itself.
        self.flush_pending_fwd()?;
        // Every byte is routed now; check nested store payloads against
        // their header CRCs BEFORE the decrypt pass (a demoting group
        // must still materialize exact volume bytes) and before the
        // child finishes (the demote abandons its routed child slots).
        self.verify_inner_crcs()?;
        // The decrypt pass does its own phased locking: the in-place AES
        // I/O over multi-GB files must not hold the routing lock (the
        // daemon's stats/stream calls read through it).
        let mut decrypted = self.decrypt_finished()?;
        let child = self.inner.lock_ok().child.clone();
        let child_fold = match &child {
            Some(c) => Some((c.finish()?, c.slot_output_files())),
            None => None,
        };
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;

        // A sync failure (ENOSPC/EIO) means buffered pwrites never reached
        // disk - swallowing it here let a job exit 0 with corrupt output
        // and a journal that recorded those articles persisted. Sync
        // everything, then fail loud if anything failed.
        let mut sync_err: Option<io::Error> = None;
        let mut extracted: Vec<(String, u64)> = Vec::new();
        for (name, w) in &inner.inner_writers {
            extracted.push((name.clone(), w.size));
            if let Err(e) = w.sync() {
                sync_err.get_or_insert(e);
            }
        }
        for s in &inner.slots {
            if let Some(w) = &s.writer
                && let Err(e) = w.sync()
            {
                sync_err.get_or_insert(e);
            }
        }
        if let Some(e) = sync_err {
            return Err(e);
        }
        let mut fallbacks: Vec<(String, String)> = inner
            .groups
            .iter()
            .filter(|(_, g)| g.fallback)
            .map(|(s, g)| (s.clone(), g.fallback_reason.clone().unwrap_or_default()))
            .collect();
        fallbacks.extend(inner.slot_fallbacks.iter().cloned());
        // Phase 0(b): one prevalence line per inner archive this level
        // streamed. Runs on THIS level's own groups/slots (self.depth);
        // each child level already reported its own via c.finish() above.
        self.report_nested_prevalence(inner);
        // Fold the child chain in: its slot files (Plain level-1 files
        // and materialized nested demotions) and its own extracted list
        // are all outputs of THIS extraction; its fallbacks are demotions
        // that already produced today's output, reported distinctly so
        // volume-level remediation never keys off them.
        if let Some((crep, cfiles)) = child_fold {
            extracted.extend(crep.extracted);
            extracted.extend(cfiles);
            for (key, why) in crep.fallbacks {
                fallbacks.push((key, nested_reason(&why)));
            }
            decrypted.extend(crep.decrypted);
            decrypted.sort();
        }
        extracted.sort();
        // The chain's holds scratch has done its job: every hold drained
        // at settle, and what is still paged (a healthy group's header
        // stash) stays readable through the kept handle. Root only - the
        // file is chain-shared.
        if self.depth == 0 {
            inner.scratch.cleanup();
        }
        Ok(ExtractReport {
            extracted,
            fallbacks,
            extracted_bytes: inner.extracted_bytes,
            decrypted,
        })
    }

    /// Phase 0(b) prevalence: emit one line per inner archive this level
    /// handled in-stream, with its type and disposition. Nested levels
    /// only (`self.depth > 0`) - a single-layer job's outer archives are
    /// depth 0 and never counted. RAR inners live in `groups` (store and
    /// chase alike; the kind reads off the mapper's first entry, which
    /// survives a demote); an in-stream 7z is a group-less slot in
    /// `SevenZ` mode. A demoted inner is logged `demoted` (with the
    /// reason) and left for the disk post-pass to tally under `disk`, so
    /// it is never counted twice.
    fn report_nested_prevalence(&self, inner: &Inner) {
        if self.depth == 0 {
            return;
        }
        for grp in inner.groups.values() {
            let kind = Self::group_inner_kind(inner, grp);
            match (grp.fallback, grp.fallback_reason.as_deref()) {
                (true, reason) => note_nested_level(
                    self.depth,
                    kind,
                    NestedDisposition::Demoted(reason.unwrap_or("demoted")),
                ),
                (false, _) => note_nested_level(self.depth, kind, NestedDisposition::InStream),
            }
        }
        // In-stream 7z inners are slot-level (not in `groups`): a slot
        // still in `SevenZ` mode at finish streamed successfully. A
        // demoted 7z is `RarFallback` by now - its `demoted` diagnostic
        // was emitted at the demote site (fallback_slot_or_group, which
        // still sees the `SevenZ` mode), and the materialized volume is
        // tallied under `disk` by the post-pass.
        for s in &inner.slots {
            if matches!(s.mode, SlotMode::SevenZ) && s.group.is_none() {
                note_nested_level(
                    self.depth,
                    s.container_fmt.noun(),
                    NestedDisposition::InStream,
                );
            }
        }
    }

    /// Classify a single group-less slot for a demote-site prevalence
    /// line, or `None` when it is not a nested archive. Only the three
    /// nested-archive modes count: a plain file, an unclassified span, or
    /// an already-demoted slot returns `None` and stays silent, so a
    /// demoting non-archive never biases the tally. Must be read BEFORE
    /// `fallback_slot` flips the slot to `RarFallback`. `RarChase` slots
    /// always own a group (handled at finish), so a group-less chase mode
    /// is defensive only.
    fn slot_inner_kind(inner: &Inner, slot: usize) -> Option<&'static str> {
        match inner.slots[slot].mode {
            SlotMode::SevenZ => Some(inner.slots[slot].container_fmt.noun()),
            SlotMode::RarChase => Some("rar-compressed"),
            SlotMode::Rar => Some(
                match inner.slots[slot]
                    .mapper
                    .as_ref()
                    .and_then(|m| m.entries.first())
                {
                    Some(e) if e.encrypted || e.crypt.is_some() => "rar-encrypted",
                    Some(e) => match e.method {
                        Method::Store => "rar-store",
                        Method::Compressed => "rar-compressed",
                    },
                    // Mode Rar means it mapped as a store RAR, so this is
                    // effectively unreachable; classify as store rather than
                    // guess a sub-type.
                    None => "rar-store",
                },
            ),
            SlotMode::Unknown | SlotMode::Plain | SlotMode::RarFallback | SlotMode::Discard => None,
        }
    }

    /// Classify a RAR group for the prevalence line from its first mapped
    /// entry - encryption wins (it is the salient blocker), then the
    /// compression method. Reads the mapper, which outlives a demote, so a
    /// fallen-back group still classifies correctly.
    fn group_inner_kind(inner: &Inner, grp: &Group) -> &'static str {
        for si in &grp.slots {
            if let Some(m) = inner.slots[*si].mapper.as_ref()
                && let Some(e) = m.entries.first()
            {
                if e.encrypted || e.crypt.is_some() {
                    return "rar-encrypted";
                }
                return match e.method {
                    Method::Store => "rar-store",
                    Method::Compressed => "rar-compressed",
                };
            }
        }
        "other"
    }
}

impl Drop for Extractor {
    /// Cancel path: a dropped extractor must not leave chase workers
    /// blocked on frontiers that will never fill. Abort every live chase
    /// and join - except from the worker's own thread (a worker holding
    /// the last transient Arc would otherwise join itself; after the
    /// abort it exits on its own anyway).
    fn drop(&mut self) {
        let inner = match self.inner.get_mut() {
            Ok(i) => i,
            Err(p) => p.into_inner(),
        };
        // Cancel path for the holds scratch (finish() already unlinked on
        // the normal path; a second unlink is a harmless miss).
        if self.depth == 0 {
            inner.scratch.cleanup();
        }
        let mut handles = Vec::new();
        for g in inner.groups.values_mut() {
            if let Some(ctl) = g.chase.take() {
                ctl.abort("extractor dropped");
                ctl.shared.lock_ok().no_more = true;
                ctl.cv.notify_all();
                if let Some(h) = ctl.worker.lock_ok().take() {
                    handles.push(h);
                }
            }
        }
        for s in inner.slots.iter_mut() {
            // A split set's parts share one ctl, so `take()` on the
            // worker yields a handle for the first member only - which
            // is exactly right, there is one thread per container.
            if let Some(ctl) = s.sevenz.take() {
                ctl.set.abort();
                if let Some(h) = ctl.worker.lock_ok().take() {
                    handles.push(h);
                }
            }
        }
        for h in handles {
            if h.thread().id() != std::thread::current().id() {
                let _ = h.join();
            }
        }
    }
}

fn nofile() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no backing data")
}

/// Collision key for the chain-shared output-name set. On a case-insensitive
/// volume `README` and `readme` name ONE object, so claiming both would let
/// the second `FileWriter::create` (truncating) clobber the first; folding to
/// lowercase makes the second name disambiguate instead. On a case-sensitive
/// volume they are genuinely distinct files, so the exact name is kept and
/// neither gets needlessly renamed.
///
/// `fold` is PROBED from the output volume (`disk::case_insensitive_dir`) and
/// threaded down the chain next to `names_taken`, so every level keys that
/// shared set identically. It is deliberately not `cfg!(target_os)`: the
/// Linux container/NAS build writing to a CIFS/SMB or exFAT share is
/// case-insensitive, and that is precisely the deployment where losing an
/// output file hurts most.
fn name_collision_key(fold: bool, name: &str) -> String {
    if fold {
        name.to_lowercase()
    } else {
        name.to_string()
    }
}

/// Reword a child-level fallback reason for the parent's report. The
/// caller keys VOLUME-level remediation (unrar passes, loose-volume job
/// failure) off substrings of top-level reasons ("compressed",
/// "encrypted"/"password", "held-bytes cap", "incomplete mapping"); a
/// nested demotion has already materialized the level-1 file - exactly
/// the single-level output, which the disk post-pass handles - so its
/// reason must never pattern-match those branches.
fn nested_reason(why: &str) -> String {
    let safe: String = if why.contains("compressed") {
        "inner archive is not store-mode".to_string()
    } else if why.contains("password") || why.contains("encrypted") {
        "inner archive is protected".to_string()
    } else if why.contains("held-bytes cap") {
        "inner holds budget exceeded".to_string()
    } else if why.contains("incomplete mapping") {
        "inner mapping unfinished at end of download".to_string()
    } else {
        why.to_string()
    };
    format!("nested fallback: {safe}")
}

fn blocker_reason(b: &MapBlocker) -> &'static str {
    match b {
        MapBlocker::NotRar => "not a RAR volume",
        MapBlocker::EncryptedHeaders => "encrypted headers (password required)",
        MapBlocker::NotStore => "compressed or encrypted entries",
        // Deliberately free of "compressed": the finish ladder's first arm
        // keys on that substring and would run an unrar attempt that cannot
        // succeed without a password, failing a job whose volumes are fine.
        // "encrypted"/"password" route it to the locked-no-password arm
        // (volumes kept, 🔒 prompt), matching EncryptedHeaders sets.
        MapBlocker::EncryptedNoPassword => "encrypted entries (password required)",
        MapBlocker::BadPassword => "wrong archive password",
        MapBlocker::Corrupt(w) => w,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::fixtures;

    use super::testutil::*;

    /// The stem is the grouping identity for a whole posted set, so
    /// every volume-naming shape must reduce to one base - and things
    /// that merely LOOK like part numbers must survive untouched.
    #[test]
    fn release_stems_reduce_every_volume_shape() {
        let st = |n: &str| release_stem(n);
        // The classic RAR shapes, unchanged.
        assert_eq!(st("x.part01.rar"), "x");
        assert_eq!(st("x.r00"), "x");
        // Old-style rollover volumes past .r99: the letter walks s..z,
        // one stem the whole way (vol_sort_key orders the same range).
        assert_eq!(st("x.s00"), "x");
        assert_eq!(st("x.t00"), "x");
        assert_eq!(st("x.z99"), "x");
        assert_eq!(st("x.z01"), "x");
        assert_eq!(st("x.vol000+01.par2"), "x");
        assert_eq!(st("x.par2"), "x");
        // Split containers: parts and their par2 sidecars share a base.
        assert_eq!(st("Some.Set.7z.001"), "Some.Set.7z");
        assert_eq!(st("Some.Set.7z.122"), "Some.Set.7z");
        assert_eq!(st("Some.Set.7z.1000"), "Some.Set.7z");
        assert_eq!(st("Some.Set.zip.001"), "Some.Set.zip");
        assert_eq!(st("Some.Set.7z.001.par2"), "Some.Set.7z");
        assert_eq!(st("Some.Set.7z.vol03+04.par2"), "Some.Set.7z");
        // Not volumes: a single archive, short numeric tails, digits
        // with no container extension in front of them.
        assert_eq!(st("Album.Track.01"), "Album.Track.01");
        assert_eq!(st("v1.7z"), "v1.7z");
        assert_eq!(st("Backup.2019.001"), "Backup.2019.001");
        assert_eq!(st("Some.Set.7z.01"), "Some.Set.7z.01");
    }

    #[test]
    fn vol_sort_key_letter_rollover_and_numeric() {
        let k = |n: &str| vol_sort_key(n).0;
        assert!(k("x.rar") < k("x.r00"));
        assert_eq!(k("x.r00"), 1);
        assert_eq!(k("x.r99"), 100);
        // 100+-volume sets roll the letter: continuity across .r99 → .s00
        // (was u64::MAX, breaking base-resolution at the boundary).
        assert_eq!(k("x.s00"), 101);
        assert_eq!(k("x.t00"), 201);
        // WinRAR numeric volumes order numerically.
        assert!(k("x.001") < k("x.002"));
        // Non-volume extensions stay in the terminal bucket.
        assert_eq!(k("x.srt"), u64::MAX);
        assert_eq!(k("x.mkv"), u64::MAX);
    }

    #[test]
    fn single_volume_direct_extract() {
        let dir = tmpdir("single");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_000)]);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        // The volume file must NOT exist (one-pass!).
        assert!(!dir.join("v.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A slot fed strictly out of order (offset 0 dead LAST - the
    /// synthesized-segment-numbering shape) must ask the installed
    /// promote hook to front-load the offset-0 article on its FIRST held
    /// span, and exactly once: the honest-ladder span (0, 1) plus the
    /// rotation guess (size-X, +1) derived from that first span's offset
    /// X. Later out-of-order spans must not re-arm it. The set still
    /// classifies when offset 0 lands and extracts one-pass.
    #[test]
    fn out_of_order_slot_probes_offset0_promote_once() {
        let dir = tmpdir("probe0");
        let data = payload(200_000, 11);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>, bool)>>>;
        let calls: Calls = Default::default();
        let sink = calls.clone();
        ex.set_promote_hook(Arc::new(
            move |n: &str, s: u64, sp: &[(u64, u64)], u: bool| {
                sink.lock()
                    .unwrap()
                    .push((n.to_string(), s, sp.to_vec(), u));
            },
        ));
        let art = 7000usize;
        let n_arts = vol.len().div_ceil(art);
        let size = vol.len() as u64;
        for i in (1..n_arts).chain([0]) {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", size, s as u64, &vol[s..e]).unwrap();
        }
        // Asked once, on the first hold: offset 0 where the ladder says
        // it is, and where a posting-order rotation would put it given
        // that the first arrival carried offset `art`. The second call
        // is the inner file's own one-shot probe: drain_holds re-feeds
        // the held spans BEFORE the classifying span's own forward, so
        // the child slot also starts out of order (no rotation guess
        // below the root - rotation is a posting-layer phenomenon).
        // Probes are NON-urgent: nothing blocks on them, so they must
        // not flip the pool into stream mode.
        let x = art as u64;
        assert_eq!(
            calls.lock().unwrap().clone(),
            vec![
                (
                    "v.rar".to_string(),
                    size,
                    vec![(0, 1), (size - x, size - x + 1)],
                    false
                ),
                ("movie.mkv".to_string(), 200_000, vec![(0, 1)], false),
            ]
        );
        let rep = ex.finish().unwrap();
        assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_000)]);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        assert!(!dir.join("v.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (HIGH): the in-stream extractor reserved an attacker-declared
    /// size. `inner_writer` passes the entry's `unpacked_size` - a RAR
    /// header vint the poster controls - straight to `FileWriter::create`,
    /// which `set_len`s and (on Linux) really `fallocate`s it. The
    /// volume-bounds check does NOT close this in the `split_after`
    /// shape: the writer is created with the inflated declaration DURING
    /// the download and the demote only lands at `finish()`, long after
    /// the blocks are gone.
    ///
    /// The ceiling is the NZB's own posted byte count: a store archive
    /// cannot legitimately unpack to more than what was posted.
    #[test]
    fn an_inflated_unpacked_size_cannot_reserve_past_the_posted_ceiling() {
        let dir = tmpdir("prealloc-cap");
        let data = payload(200_000, 9);
        // 200 KB really posted; the header declares 8 TiB and sets
        // split_after, so nothing demotes until finish().
        const HUGE: u64 = 8 << 40;
        let vol = fixtures::rar5_volume(&[("movie.mkv", HUGE, &data, false, true)]);
        let ex = Extractor::new(&dir, 1, true);
        let posted = vol.len() as u64;
        ex.set_prealloc_ceiling(posted);
        feed(&ex, 0, "x.part1.rar", &vol, 7000, 3);

        // MID-DOWNLOAD - the window the finish-time gates cannot cover.
        let reserved = std::fs::metadata(dir.join("movie.mkv")).unwrap().len();
        assert!(
            reserved <= posted,
            "reserved {reserved} bytes for a {posted}-byte post declaring {HUGE}"
        );
        let _ = ex.finish();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The other half, and the one a wrong fix breaks silently: a
    /// legitimate inner file BIGGER than any single volume must still be
    /// preallocated in full as soon as the first volume identifies it -
    /// the whole point of preallocation is that the extents are reserved
    /// before the rest of the download races other files for them.
    ///
    /// (This is also why the ceiling is the NZB total and not the sum of
    /// the group's slot sizes: group membership accretes as volumes
    /// arrive, so at this point only ONE volume is known.)
    #[test]
    fn a_legitimate_large_inner_file_still_preallocates_in_full() {
        let dir = tmpdir("prealloc-ok");
        let total = payload(500_000, 2);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
        ];
        let posted: u64 = vols.iter().map(|v| v.len() as u64).sum();
        assert!(posted > 500_000);
        let ex = Extractor::new(&dir, 3, true);
        ex.set_prealloc_ceiling(posted);

        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
        assert_eq!(
            std::fs::metadata(dir.join("film.mkv")).unwrap().len(),
            500_000,
            "a legitimate 500 KB inner file must be reserved in full from the first volume"
        );

        feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
        feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.extracted, vec![("film.mkv".to_string(), 500_000)]);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (MEDIUM): the decompression-bomb guard counted bytes only on
    /// the disk and post-pass sinks, so it protected the fallback and not
    /// the in-stream path every download actually takes. The budget is
    /// shared across the whole job - inner files do not each get a fresh
    /// allowance.
    #[test]
    fn the_in_stream_path_is_bounded_by_the_extract_budget() {
        let dir = tmpdir("bomb-instream");
        let a = payload(200_000, 4);
        let b = payload(200_000, 5);
        let vol = fixtures::rar5_volume(&[
            ("one.bin", 200_000, &a, false, false),
            ("two.bin", 200_000, &b, false, false),
        ]);
        let ex = Extractor::new(&dir, 1, true);
        // Room for the first inner file and not the second: a shared
        // budget must refuse, a per-file one would wave both through.
        ex.set_extract_budget(300_000);

        let art = 8192;
        let mut err = None;
        for s in (0..vol.len()).step_by(art) {
            let e = (s + art).min(vol.len());
            if let Err(x) = ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e]) {
                err = Some(x);
                break;
            }
        }
        let err = err.expect("a 400 KB extract under a 300 KB budget must be refused");
        assert!(err.to_string().contains("decompression bomb"), "{err}");
        assert!(ex.extract_budget_used() > 300_000);
        let _ = ex.finish();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The budget must not fire on a job that merely fits - the guard
    /// exists for bombs, not for large legitimate extracts.
    #[test]
    fn the_extract_budget_never_trips_on_a_job_that_fits() {
        let dir = tmpdir("bomb-fits");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_extract_budget(200_000);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        assert_eq!(ex.extract_budget_used(), 200_000);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn split_volumes_out_of_order() {
        let dir = tmpdir("split");
        let total = payload(500_000, 2);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
        ];
        // Feed volumes interleaved and shuffled - vol 3 first.
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
        feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert!(!dir.join("x.part1.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A store entry that DECLARES far more data than the volume holds
    /// must never ship as a successful extraction. Before the
    /// volume-bounds check the parse cursor jumped past the volume end,
    /// the EOF rule marked the volume complete, `mapped_through()` went
    /// to u64::MAX (so no tail-hold), the end-of-download settle saw
    /// nothing incomplete, and the CRC gate skipped the file because its
    /// composed run was shorter than the declared piece - leaving a
    /// preallocated, mostly-zero file reported as output with exit 0.
    #[test]
    fn oversized_data_area_never_ships_a_sparse_file() {
        let dir = tmpdir("oversize-a");
        let data = payload(4_000, 5);
        // 4 KB really posted; the header claims 8 MB of data area.
        let vol = fixtures::rar5_volume_oversized("movie.mkv", 8 << 20, &data, 8 << 20);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 700, 3);
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "a volume that overruns itself must demote, got {:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "no sparse output may survive the demote"
        );
        assert!(
            rep.extracted.iter().all(|(n, _)| n != "movie.mkv"),
            "{:?}",
            rep.extracted
        );
        // The volume itself materialized for the disk path, byte-exact,
        // so unrar gets to fail the job honestly.
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Variant B: every per-volume invariant holds (the data area ends
    /// exactly at the volume end, the end-of-archive block is there, the
    /// bytes all arrive) but `split_after` is set on the only piece and
    /// `unpacked_size` is 8 MB against 4 KB of real data. The parser
    /// cannot object - the continuation volume it promises simply never
    /// exists - so the CRC gate has to notice that the header set does
    /// not tile the file it declares. It used to skip: `split_after`
    /// nulled the header CRC, and every demote below was gated on
    /// `tiled`.
    #[test]
    fn split_after_with_oversized_unpacked_size_demotes() {
        let dir = tmpdir("oversize-b");
        let data = payload(4_000, 6);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 8 << 20, &data, false, true)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 700, 4);
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "headers that do not cover the file must demote, got {:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "no sparse output may survive the demote"
        );
        assert!(
            rep.extracted.iter().all(|(n, _)| n != "movie.mkv"),
            "{:?}",
            rep.extracted
        );
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Variant C: the same truncated header set with the output-CRC
    /// gate OFF (NZBFAST_NO_OUTPUT_CRC). The knob buys back the CRC
    /// composition cost, not the structural check - tiling is a pure
    /// header property, and with it skipped a par-less truncated store
    /// set shipped its preallocated size as a silent success.
    #[test]
    fn oversized_unpacked_size_demotes_even_with_output_crc_off() {
        let dir = tmpdir("oversize-nocrc");
        let data = payload(4_000, 6);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 8 << 20, &data, false, true)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_verify_output_crc(false);
        feed(&ex, 0, "v.rar", &vol, 700, 4);
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "the tiling check must run with the CRC gate off, got {:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "no sparse output may survive the demote"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The regression that matters most: a REAL multi-volume split set
    /// (per-volume `data_len` well under the declared whole-file
    /// `unpacked_size`, stored CRCs, out-of-order arrival) must still go
    /// through the one-pass path untouched - no demote, byte-exact
    /// output, no volume files left behind.
    #[test]
    fn legitimate_split_set_still_extracts_one_pass() {
        let dir = tmpdir("split-legit");
        let total = payload(500_000, 8);
        let cut = |r: std::ops::Range<usize>| crc32fast::hash(&total[r]);
        let vols = [
            fixtures::rar5_volume_n_crc(
                &[(
                    "film.mkv",
                    500_000,
                    &total[..200_000],
                    false,
                    true,
                    Some(cut(0..200_000)),
                )],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[(
                    "film.mkv",
                    500_000,
                    &total[200_000..400_000],
                    true,
                    true,
                    Some(cut(200_000..400_000)),
                )],
                1,
            ),
            // Last piece carries the WHOLE-file CRC, the way real
            // archivers write it - so the composed gate actually runs.
            fixtures::rar5_volume_n_crc(
                &[(
                    "film.mkv",
                    500_000,
                    &total[400_000..],
                    true,
                    false,
                    Some(cut(0..500_000)),
                )],
                2,
            ),
        ];
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 31);
        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 32);
        feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 33);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert!(!dir.join("x.part1.rar").exists());
        assert!(!dir.join("x.part3.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn obfuscated_names_group_by_inner_file() {
        let dir = tmpdir("obf");
        let total = payload(300_000, 5);
        let v1 =
            fixtures::rar5_volume_n(&[("real.mkv", 300_000, &total[..150_000], false, true)], 0);
        let v2 =
            fixtures::rar5_volume_n(&[("real.mkv", 300_000, &total[150_000..], true, false)], 1);
        let ex = Extractor::new(&dir, 2, true);
        // Hash-garbage yEnc names; sorted order of names is WRONG (b < a).
        feed(&ex, 0, "bbbb1234.bin", &v1, 8000, 7);
        feed(&ex, 1, "aaaa9999.bin", &v2, 8000, 8);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("real.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO §7 #1 regression: a store set carrying MORE THAN ONE inner
    /// file, with a file boundary inside a middle volume. Volumes group
    /// by their first inner name, so the E02-only continuation volumes
    /// formed a separate group that could never base-resolve; at finish()
    /// that group fell back and deleted E02.mkv - including the head
    /// bytes the healthy group had extracted (its volumes were never
    /// materialized), i.e. deterministic whole-file loss at exit 0.
    #[test]
    fn multi_file_store_set_extracts_across_file_boundary() {
        let dir = tmpdir("multifile");
        let e01 = payload(350_000, 21);
        let e02 = payload(250_000, 22);
        let vols = [
            fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[..200_000], false, true)], 0),
            fixtures::rar5_volume_n(
                &[
                    ("E01.mkv", 350_000, &e01[200_000..], true, false),
                    ("E02.mkv", 250_000, &e02[..50_000], false, true),
                ],
                1,
            ),
            fixtures::rar5_volume_n(&[("E02.mkv", 250_000, &e02[50_000..], true, false)], 2),
        ];
        // Obfuscated volume names; feed the continuation-only volume FIRST
        // so its group forms before the boundary volume can link it.
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 2, "ccc.bin", &vols[2], 9000, 51);
        feed(&ex, 0, "bbb.bin", &vols[0], 9000, 52);
        feed(&ex, 1, "aaa.bin", &vols[1], 9000, 53);
        let rep = ex.finish().unwrap();
        // Multi-file sets live and die on the CHAIN path: the arithmetic
        // gate must never have placed beyond it here.
        assert!(
            ex.arith_engaged_groups().is_empty(),
            "{:?}",
            ex.arith_engaged_groups()
        );
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(
            rep.extracted,
            vec![
                ("E01.mkv".to_string(), 350_000),
                ("E02.mkv".to_string(), 250_000)
            ]
        );
        assert_eq!(std::fs::read(dir.join("E01.mkv")).unwrap(), e01);
        assert_eq!(std::fs::read(dir.join("E02.mkv")).unwrap(), e02);
        for n in ["bbb.bin", "aaa.bin", "ccc.bin"] {
            assert!(!dir.join(n).exists(), "volume {n} materialized");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding 14: two DISTINCT inner entries whose names sanitize to the
    /// same on-disk name ("a/b.txt" -> "a_b.txt" collides with a literal
    /// "a_b.txt") must each get their own output. Keyed on the sanitized
    /// name they shared one writer and the second silently overwrote the
    /// first; keyed on the raw name they land as two disambiguated files.
    #[test]
    fn distinct_names_that_sanitize_alike_dont_share_output() {
        let dir = tmpdir("sanitize-collide");
        let a = payload(120_000, 61);
        let b = payload(90_000, 62);
        let vol = fixtures::rar5_volume(&[
            ("a/b.txt", 120_000, &a, false, false),
            ("a_b.txt", 90_000, &b, false, false),
        ]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 63);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        // Both payloads must survive intact on disk under two distinct names,
        // never one truncated/interleaved file.
        let landed: Vec<Vec<u8>> = dir_files(&dir)
            .into_iter()
            .map(|n| std::fs::read(dir.join(n)).unwrap())
            .collect();
        assert!(landed.iter().any(|f| f == &a), "first entry's bytes lost");
        assert!(landed.iter().any(|f| f == &b), "second entry's bytes lost");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding 15: on a case-insensitive default volume (macOS/Windows)
    /// "README" and "readme" name one filesystem object, so the second
    /// output would truncate the first. The claim key folds case there, so
    /// the second disambiguates and both payloads survive. (On case-
    /// sensitive Linux they are distinct files already; either way both
    /// payloads land intact.)
    #[test]
    fn case_only_name_collision_keeps_both_outputs() {
        let dir = tmpdir("case-collide");
        let a = payload(120_000, 71);
        let b = payload(90_000, 72);
        let vol = fixtures::rar5_volume(&[
            ("README", 120_000, &a, false, false),
            ("readme", 90_000, &b, false, false),
        ]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 73);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        let landed: Vec<Vec<u8>> = dir_files(&dir)
            .into_iter()
            .map(|n| std::fs::read(dir.join(n)).unwrap())
            .collect();
        assert!(landed.iter().any(|f| f == &a), "README bytes lost");
        assert!(landed.iter().any(|f| f == &b), "readme bytes lost");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Same layout at season-pack scale - six volumes, boundary inside
    /// v3 - driven through every linking path: sequential (the
    /// deterministic-loss order), continuations first (the group forms
    /// before its head volume exists), and boundary volume first (the
    /// alias exists before either neighbor group).
    #[test]
    fn multi_file_store_set_survives_all_feed_orders() {
        let e01 = payload(350_000, 21);
        let e02 = payload(250_000, 22);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[..100_000], false, true)], 0),
            fixtures::rar5_volume_n(
                &[("E01.mkv", 350_000, &e01[100_000..200_000], true, true)],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("E01.mkv", 350_000, &e01[200_000..300_000], true, true)],
                2,
            ),
            fixtures::rar5_volume_n(
                &[
                    ("E01.mkv", 350_000, &e01[300_000..], true, false),
                    ("E02.mkv", 250_000, &e02[..50_000], false, true),
                ],
                3,
            ),
            fixtures::rar5_volume_n(
                &[("E02.mkv", 250_000, &e02[50_000..150_000], true, true)],
                4,
            ),
            fixtures::rar5_volume_n(&[("E02.mkv", 250_000, &e02[150_000..], true, false)], 5),
        ];
        for (t, order) in [
            [0usize, 1, 2, 3, 4, 5],
            [4, 5, 0, 1, 2, 3],
            [3, 4, 5, 2, 1, 0],
        ]
        .iter()
        .enumerate()
        {
            let dir = tmpdir(&format!("multifile{t}"));
            let ex = Extractor::new(&dir, 6, true);
            for &vi in order {
                let name = format!("obf{:02x}.bin", (vi as u8) ^ 0x5a);
                feed(&ex, vi, &name, &vols[vi], 7000, 40 + vi as u64);
            }
            let rep = ex.finish().unwrap();
            // No engagement assert here (unlike the §7 test above): when
            // the boundary volume's E01-tail parses alone, it is a lone
            // FINAL piece and the gate may transiently place it at
            // `total - data_len` - which is the true base of any split
            // file's final piece, so the chain confirms it and the
            // one-pass outcome below is what actually matters.
            assert!(
                rep.fallbacks.is_empty(),
                "order {order:?}: {:?}",
                rep.fallbacks
            );
            assert_eq!(
                rep.extracted,
                vec![
                    ("E01.mkv".to_string(), 350_000),
                    ("E02.mkv".to_string(), 250_000)
                ],
                "order {order:?}"
            );
            assert_eq!(
                std::fs::read(dir.join("E01.mkv")).unwrap(),
                e01,
                "order {order:?}"
            );
            assert_eq!(
                std::fs::read(dir.join("E02.mkv")).unwrap(),
                e02,
                "order {order:?}"
            );
            // One-pass: no volume file may exist.
            let files: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            assert_eq!(files.len(), 2, "order {order:?}: {files:?}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// SPEC Part A acceptance 1 + 7: a 45-volume uniform single-file
    /// store set with dotless obfuscated names, fed in a shuffled order
    /// that keeps the chain short for the whole download, extracts
    /// one-pass under a tight holds budget - the arithmetic gate places
    /// every volume the moment its own headers parse. This exact fixture
    /// demotes with "held-bytes cap" without the gate (the ~13 MB of
    /// unplaceable spans overrun the 8 MB floor).
    #[test]
    fn obfuscated_uniform_store_set_streams_one_pass_any_order() {
        let dir = tmpdir("arith-onepass");
        let inner = "qCNsampBzXuv9m9z.mkv";
        let (data, vols, names) = uniform_store_set(inner, 300_000, 44, 200_000, 31);
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_holds_cap(8 << 20);
        // Volume 0 arrives LAST, and the set's final volume early. Either
        // one is enough: volume 0 proves the file starts where the
        // arithmetic assumes, and the final piece proves the same thing
        // through the closure identity (and separately seeds the chain's
        // backward walk). One of the two is all a set needs to place
        // every other volume off its own headers.
        let mut order = shuffled_zero_last(vols.len(), 0xC0FFEE);
        let tail = vols.len() - 1;
        let at = order.iter().position(|&v| v == tail).unwrap();
        order.remove(at);
        order.insert(0, tail);
        for vi in order {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 60 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.extracted, vec![(inner.to_string(), data.len() as u64)]);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
        assert!(
            !ex.arith_engaged_groups().is_empty(),
            "the gate never engaged"
        );
        // Memory acceptance: holds never accumulated the set - only the
        // in-flight volume's pre-parse spans.
        assert!(
            ex.holds_peak() < data.len() / 2,
            "holds peak {}",
            ex.holds_peak()
        );
        for n in &names {
            assert!(!dir.join(n).exists(), "volume {n} materialized");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The honest limit of the same shape: when NEITHER the file's first
    /// nor its last volume has parsed, no offset is derivable from any
    /// header, so the bytes must be held. (The offsets are only knowable
    /// relative to one of those two ends - anything else would be placing
    /// on an unproven premise, which is exactly what mis-placed a season
    /// pack's continuation volumes.) A production-sized holds budget
    /// absorbs that window and the set still one-passes; a budget smaller
    /// than the window demotes, correctly.
    #[test]
    fn a_set_with_neither_end_parsed_holds_then_places() {
        let inner = "late.mkv";
        let (data, vols, names) = uniform_store_set(inner, 300_000, 44, 200_000, 31);
        // Feed order that keeps both ends late: this is the case the
        // arithmetic gate used to guess its way through.
        let mut order = shuffled_zero_last(vols.len(), 0xC0FFEE);
        let tail = vols.len() - 1;
        let at = order.iter().position(|&v| v == tail).unwrap();
        order.remove(at);
        order.insert(order.len() - 1, tail);

        // Budget above the window: one-pass, byte-exact.
        let dir = tmpdir("arith-lateends-ok");
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_holds_cap(64 << 20);
        for &vi in &order {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 70 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();

        // Budget below it: demotes on the holds cap, and every volume
        // still reconstructs byte-exact for the disk path. Paging OFF -
        // with it on (the default) this window pages to scratch and the
        // set one-passes instead (pinned separately below); this leg
        // keeps the demote plumbing itself honest.
        let dir = tmpdir("arith-lateends-tight");
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_holds_cap(8 << 20);
        ex.set_holds_paging(false);
        for &vi in &order {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 70 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap")),
            "{:?}",
            rep.fallbacks
        );
        for (vi, vol) in vols.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(&names[vi])).unwrap(),
                vol,
                "volume {vi}"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SPEC Part A acceptance 2: the same shape with ONE mid-set volume
    /// declaring a different `data_len`. The gate engages on the uniform
    /// majority; the odd volume's parse contradicts the premise while
    /// unconfirmed placements exist, so the WHOLE group demotes with the
    /// distinct reason - and every volume reconstructs byte-exact (the
    /// unrar path's input), with no half-extracted inner file left.
    #[test]
    fn uniform_store_set_with_odd_mid_volume_demotes_whole() {
        let dir = tmpdir("arith-nonuniform");
        let inner = "inner.bin";
        let dl = 60_000usize;
        let n_full = 44usize;
        let tail = 40_000usize;
        let total = ((dl + 1) + (n_full - 1) * dl + tail) as u64; // as declared; vol 20 lies
        let data = payload((dl + 1) + (n_full - 1) * dl + tail, 33);
        let mut vols: Vec<Vec<u8>> = Vec::new();
        let mut pos = 0usize;
        for k in 0..n_full {
            let len = if k == 0 {
                dl + 1
            } else if k == 20 {
                30_000 // the odd one out
            } else {
                dl
            };
            let piece = &data[pos..pos + len];
            pos += len;
            vols.push(fixtures::rar5_volume_n_crc(
                &[(
                    inner,
                    total,
                    piece,
                    k > 0,
                    true,
                    Some(crc32fast::hash(piece)),
                )],
                k as u64,
            ));
        }
        vols.push(fixtures::rar5_volume_n_crc(
            &[(
                inner,
                total,
                &data[pos..pos + tail],
                true,
                false,
                Some(crc32fast::hash(&data)),
            )],
            n_full as u64,
        ));
        let ex = Extractor::new(&dir, vols.len(), true);
        // Everything but the odd volume first (volume 0 late, so the
        // gate engages with provisional placements), the odd one last.
        let mut order: Vec<usize> = (1..=19).chain(21..=44).chain([0, 20]).collect();
        assert_eq!(order.len(), vols.len());
        for vi in order.drain(..) {
            feed(
                &ex,
                vi,
                &format!("g{vi:02}NoDot"),
                &vols[vi],
                9000,
                80 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert_eq!(
            rep.fallbacks,
            vec![(inner.to_string(), "non-uniform store set".to_string())]
        );
        for (vi, vol) in vols.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("g{vi:02}NoDot"))).unwrap(),
                vol,
                "volume {vi} must reconstruct byte-exact"
            );
        }
        assert!(
            !dir.join(inner).exists(),
            "no partial inner file may survive"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SPEC Part A acceptance 4: an encrypted uniform single-file set
    /// must never engage the arithmetic gate - in-stream decryption was
    /// built and verified against chained placement, and behavior stays
    /// exactly as before (this set still one-passes: it completes, so
    /// the chain closes at the end).
    #[test]
    fn encrypted_uniform_store_set_stays_on_chain_path() {
        let dir = tmpdir("arith-enc");
        let plain = payload(900_000, 35);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let n = f.cipher.len();
        let (a, b) = (300_000, 600_000);
        // Uniform piece sizes on purpose: were encryption not excluded,
        // this shape would qualify.
        let vols = [
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.set_password("hunter2");
        feed(&ex, 2, "zzNoDot", &vols[2], 8000, 91);
        feed(&ex, 0, "aaNoDot", &vols[0], 8000, 92);
        feed(&ex, 1, "mmNoDot", &vols[1], 8000, 93);
        let rep = ex.finish().unwrap();
        assert!(
            ex.arith_engaged_groups().is_empty(),
            "arithmetic gate engaged on an encrypted set"
        );
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The gate's bet is right for a multi-file set's FIRST file (it
    /// really does start at volume 0, offset 0): continuation volumes
    /// arriving early engage provisionally, the chain confirms each
    /// placement as the head volumes fill in, and the boundary volume
    /// then reveals the multi-file truth WITHOUT a demote - both files
    /// extract one-pass.
    #[test]
    fn provisional_placements_confirmed_by_chain_survive_multifile_reveal() {
        let dir = tmpdir("arith-confirm");
        // WinRAR-true: volume 0 carries one byte more (see uniform_store_set).
        let a = payload(450_001, 41); // spans vols 0..=4, boundary in vol 4
        let b = payload(120_000, 42); // head 50k in vol 4, final 70k in vol 5
        let vols = [
            fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[..100_001], false, true)], 0),
            fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[100_001..200_001], true, true)], 1),
            fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[200_001..300_001], true, true)], 2),
            fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[300_001..400_001], true, true)], 3),
            fixtures::rar5_volume_n(
                &[
                    ("A.mkv", 450_001, &a[400_001..], true, false),
                    ("B.mkv", 120_000, &b[..50_000], false, true),
                ],
                4,
            ),
            fixtures::rar5_volume_n(&[("B.mkv", 120_000, &b[50_000..], true, false)], 5),
        ];
        let ex = Extractor::new(&dir, 6, true);
        for vi in [2usize, 3, 5, 0, 1, 4] {
            feed(
                &ex,
                vi,
                &format!("c{vi}NoDot"),
                &vols[vi],
                9000,
                70 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(
            !ex.arith_engaged_groups().is_empty(),
            "vols 2+3 arriving first must have engaged the gate"
        );
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("A.mkv")).unwrap(), a);
        assert_eq!(std::fs::read(dir.join("B.mkv")).unwrap(), b);
        for vi in 0..6 {
            assert!(
                !dir.join(format!("c{vi}NoDot")).exists(),
                "volume {vi} materialized"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The shape that USED to expose a wrong bet: a big second file
    /// behind a small first one. Its continuation volumes look
    /// arithmetically plausible (the file is large, so `volnum * data_len`
    /// fits inside it) but the true bases are shifted by the first file's
    /// share of volume 0.
    ///
    /// The gate no longer bets on it at all: with neither a volume 0 that
    /// starts this file nor a closure identity that holds, the premise is
    /// unproven and the group goes to chain resolution - which places it
    /// correctly. So the set now extracts ONE-PASS where it previously
    /// wrote bytes at wrong offsets and demoted to recover. The old
    /// demote-and-reconstruct path is still exercised by
    /// `uniform_store_set_with_odd_mid_volume_demotes_whole`.
    #[test]
    fn a_big_second_file_now_places_instead_of_mis_betting() {
        let dir = tmpdir("arith-contradict");
        let f1 = payload(30_000, 43); // wholly inside vol 0
        let f2 = payload(520_000, 44); // 50k in vol 0, then 4 x 100k, tail 70k
        let vols = [
            fixtures::rar5_volume_n(
                &[
                    ("f1.bin", 30_000, &f1, false, false),
                    ("f2.bin", 520_000, &f2[..50_000], false, true),
                ],
                0,
            ),
            fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[50_000..150_000], true, true)], 1),
            fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[150_000..250_000], true, true)], 2),
            fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[250_000..350_000], true, true)], 3),
            fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[350_000..450_000], true, true)], 4),
            fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[450_000..], true, false)], 5),
        ];
        let ex = Extractor::new(&dir, 6, true);
        // Vols 3+4 first: the gate engages and places them at 300k/400k
        // (true bases 250k/350k). Vol 0 reveals the second entry; the
        // chain then reaches vol 3 when vols 1+2 parse and contradicts.
        for vi in [3usize, 4, 0, 1, 2, 5] {
            feed(
                &ex,
                vi,
                &format!("x{vi}NoDot"),
                &vols[vi],
                9000,
                50 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
        assert_eq!(std::fs::read(dir.join("f2.bin")).unwrap(), f2);
        for vi in 0..vols.len() {
            assert!(
                !dir.join(format!("x{vi}NoDot")).exists(),
                "volume {vi} materialized"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A volume missing from the NZB entirely: the gate placed the rest
    /// arithmetically (no holds, mappers complete), so only the closure
    /// ruling at settle can notice the set never proved itself - it must
    /// demote rather than ship a file with a silent hole.
    #[test]
    fn unclosed_arithmetic_set_demotes_at_finish() {
        let dir = tmpdir("arith-unclosed");
        let inner = "gap.bin";
        let (_data, vols, names) = uniform_store_set(inner, 60_000, 9, 40_000, 37);
        let ex = Extractor::new(&dir, vols.len(), true);
        // Volume 4 never arrives; 0 arrives last among those that do.
        for vi in [7usize, 2, 9, 5, 1, 8, 3, 6, 0] {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 40 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        assert_eq!(
            rep.fallbacks,
            vec![(inner.to_string(), "non-uniform store set".to_string())]
        );
        assert!(!dir.join(inner).exists(), "no holed inner file may survive");
        for vi in [7usize, 2, 9, 5, 1, 8, 3, 6, 0] {
            assert_eq!(
                &std::fs::read(dir.join(&names[vi])).unwrap(),
                &vols[vi],
                "volume {vi} must reconstruct byte-exact"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The failure the first LIVE run of the gate exposed (Ant-Man, 134
    /// volumes): the volume-number vint in the main header grows a byte
    /// at volume 128, and real archivers keep the VOLUME size constant,
    /// so the data area shrinks by that byte - `data_len` is NOT
    /// uniform. A >127-volume set must still qualify and place every
    /// band correctly (vol 0: D bytes; 1..127: D-1; 128+: D-2).
    #[test]
    fn store_set_crossing_the_volnum_vint_band_still_one_passes() {
        let dir = tmpdir("arith-band");
        let inner = "band.mkv";
        let d = 5_001usize; // vol 0's data bytes
        let n_full = 131usize; // vols 0..=130 non-final, 131 final
        let tail = 3_000usize;
        let total = d + 127 * (d - 1) + 3 * (d - 2) + tail;
        let data = payload(total, 39);
        let mut vols: Vec<Vec<u8>> = Vec::new();
        let mut pos = 0usize;
        for k in 0..n_full {
            let len = if k == 0 {
                d
            } else if k < 128 {
                d - 1
            } else {
                d - 2
            };
            let piece = &data[pos..pos + len];
            pos += len;
            vols.push(fixtures::rar5_volume_n_crc(
                &[(
                    inner,
                    total as u64,
                    piece,
                    k > 0,
                    true,
                    Some(crc32fast::hash(piece)),
                )],
                k as u64,
            ));
        }
        vols.push(fixtures::rar5_volume_n_crc(
            &[(
                inner,
                total as u64,
                &data[pos..],
                true,
                false,
                Some(crc32fast::hash(&data)),
            )],
            n_full as u64,
        ));
        let names: Vec<String> = (0..vols.len()).map(|k| format!("bx{k:03}NoDot")).collect();
        let ex = Extractor::new(&dir, vols.len(), true);
        for vi in shuffled_zero_last(vols.len(), 0xBAD5EED) {
            feed(&ex, vi, &names[vi], &vols[vi], 1_500, 30 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert!(
            !ex.arith_engaged_groups().is_empty(),
            "the gate never engaged"
        );
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        for n in &names {
            assert!(!dir.join(n).exists(), "volume {n} materialized");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// PLAN-multifile acceptance 1: a season-pack-shaped store set - six
    /// inner files across 60 volumes, boundaries mid-volume, dotless
    /// obfuscated names - fed in a shuffled order with volume 0 arriving
    /// LAST, extracts one-pass under a tight holds budget.
    ///
    /// This is the 25%-of-multivol-bytes shape the census found (92% of
    /// bytes above 60 GB). Before tail anchoring it demoted: forward-only
    /// resolution could place nothing until volume 0 parsed, so the
    /// unplaceable spans overran the cap.
    #[test]
    fn obfuscated_season_pack_streams_one_pass_with_volume_zero_last() {
        let dir = tmpdir("multifile-pack");
        // Six episodes, each spanning several volumes, boundaries landing
        // mid-volume so volumes carry two entries.
        let eps: Vec<Vec<u8>> = (0..6)
            .map(|k| payload(1_400_000 + k * 9_000, 40 + k as u8))
            .collect();
        // Lay the episodes end to end, then cut at a fixed volume size:
        // exactly how a real archiver fills volumes.
        let mut stream: Vec<(usize, usize)> = Vec::new(); // (episode, byte)
        for (i, e) in eps.iter().enumerate() {
            for b in 0..e.len() {
                stream.push((i, b));
            }
        }
        const VOL: usize = 150_000;
        let mut vols: Vec<Vec<u8>> = Vec::new();
        let mut at = 0usize;
        let mut vol_no = 0u64;
        while at < stream.len() {
            let end = (at + VOL).min(stream.len());
            // Which episodes does this volume touch, and how much of each?
            let mut pieces: Vec<(usize, usize, usize)> = Vec::new(); // (ep, from, to)
            let mut i = at;
            while i < end {
                let (ep, off) = stream[i];
                let run_end = (i..end).take_while(|&j| stream[j].0 == ep).count() + i;
                pieces.push((ep, off, off + (run_end - i)));
                i = run_end;
            }
            let specs: Vec<(String, u64, Vec<u8>, bool, bool)> = pieces
                .iter()
                .map(|&(ep, from, to)| {
                    (
                        format!("Show.S01E{:02}.mkv", ep + 1),
                        eps[ep].len() as u64,
                        eps[ep][from..to].to_vec(),
                        from > 0,
                        to < eps[ep].len(),
                    )
                })
                .collect();
            let refs: Vec<(&str, u64, &[u8], bool, bool)> = specs
                .iter()
                .map(|(n, t, d, b, a)| (n.as_str(), *t, d.as_slice(), *b, *a))
                .collect();
            vols.push(fixtures::rar5_volume_n(&refs, vol_no));
            vol_no += 1;
            at = end;
        }
        assert!(
            vols.len() >= 55,
            "expected a season-pack-scale set, got {}",
            vols.len()
        );
        let names: Vec<String> = (0..vols.len())
            .map(|k| format!("{:06x}SeasonNoDot{k}", (k as u64 * 2654435761) & 0xffffff))
            .collect();

        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_holds_cap(8 << 20);
        for vi in shuffled_zero_last(vols.len(), 0x5EA5_0DE7) {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 100 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        for (i, e) in eps.iter().enumerate() {
            let p = dir.join(format!("Show.S01E{:02}.mkv", i + 1));
            assert_eq!(&std::fs::read(&p).unwrap(), e, "episode {} differs", i + 1);
        }
        for n in &names {
            assert!(!dir.join(n).exists(), "volume {n} materialized");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// PLAN-multifile acceptance 2: an ISLAND of volumes away from volume
    /// 0 places its pieces. Each inner file needs a parsed run containing
    /// its own head or tail, not one reaching back to the start of the
    /// set - that is the whole point of the tail seed.
    #[test]
    fn a_mid_set_island_resolves_without_volume_zero() {
        let dir = tmpdir("multifile-island");
        let a = payload(400_000, 61);
        let b = payload(300_000, 62);
        // A ends in volume 3; B starts there and ends in volume 5.
        let vols = [
            fixtures::rar5_volume_n(&[("A.mkv", 400_000, &a[..100_000], false, true)], 0),
            fixtures::rar5_volume_n(&[("A.mkv", 400_000, &a[100_000..200_000], true, true)], 1),
            fixtures::rar5_volume_n(&[("A.mkv", 400_000, &a[200_000..300_000], true, true)], 2),
            fixtures::rar5_volume_n(
                &[
                    ("A.mkv", 400_000, &a[300_000..], true, false),
                    ("B.mkv", 300_000, &b[..50_000], false, true),
                ],
                3,
            ),
            fixtures::rar5_volume_n(&[("B.mkv", 300_000, &b[50_000..150_000], true, true)], 4),
            fixtures::rar5_volume_n(&[("B.mkv", 300_000, &b[150_000..], true, false)], 5),
        ];
        // Feed ONLY volumes 3-5: an island with no path back to volume 0.
        let ex = Extractor::new(&dir, 6, true);
        for vi in [4usize, 5, 3] {
            feed(
                &ex,
                vi,
                &format!("isl{vi}NoDot"),
                &vols[vi],
                9000,
                10 + vi as u64,
            );
        }
        // Before finish, B's pieces are PLACED: volume 3 starts B (base
        // 0) and volume 5 ends it (base = total - data_len), so the whole
        // island resolves with no path back to volume 0. Forward-only
        // resolution placed nothing here.
        assert!(ex.bases_known(&["B.mkv"]), "island pieces must be placed");
        let rep = ex.finish().unwrap();
        // The SET is still incomplete - A's head never arrived - so the
        // group demotes at settle and its partial output is removed. The
        // point of this test is the placement above, not the verdict.
        assert!(!rep.fallbacks.is_empty(), "an incomplete set still demotes");
        assert!(
            !dir.join("B.mkv").exists(),
            "a demote removes partial output"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// PLAN-multifile acceptance 5: headers that disagree with THEMSELVES.
    /// The middle volume claims a piece that does not fit the gap its two
    /// neighbours leave, so the piece resolves to different offsets from
    /// each side. No offset here is trustworthy, so the group demotes
    /// with its own reason - and every volume still reconstructs
    /// byte-exact for the disk path.
    #[test]
    fn a_self_contradictory_chain_demotes_with_its_own_reason() {
        let dir = tmpdir("chain-contradict");
        let f = payload(300_000, 71);
        let vols = [
            fixtures::rar5_volume_n(&[("f.bin", 300_000, &f[..100_000], false, true)], 0),
            // Overlaps: claims 150 KB where 100 KB fits.
            fixtures::rar5_volume_n(&[("f.bin", 300_000, &f[..150_000], true, true)], 1),
            fixtures::rar5_volume_n(&[("f.bin", 300_000, &f[200_000..], true, false)], 2),
        ];
        let ex = Extractor::new(&dir, 3, true);
        for vi in [0usize, 1, 2] {
            feed(
                &ex,
                vi,
                &format!("cc{vi}NoDot"),
                &vols[vi],
                9000,
                80 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w == "inconsistent volume chain"),
            "{:?}",
            rep.fallbacks
        );
        for (vi, vol) in vols.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("cc{vi}NoDot"))).unwrap(),
                vol,
                "volume {vi} must reconstruct byte-exact"
            );
        }
        assert!(!dir.join("f.bin").exists(), "no partial output may survive");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SPEC Part A trap: under protect_sources (offline `nzbfast
    /// extract`), an arithmetic demote must DISCARD like the chain path
    /// does - never materialize a "volume" over the source file it is
    /// reading.
    #[test]
    fn protect_sources_arithmetic_demote_discards() {
        let dir = tmpdir("arith-protect");
        let inner = "film.mkv";
        let dl = 60_000usize;
        let total = ((dl + 1) + 4 * dl + 40_000) as u64; // declared; vol 3 lies
        let data = payload((dl + 1) + 4 * dl + 40_000, 45);
        let mut vols: Vec<Vec<u8>> = Vec::new();
        let mut pos = 0usize;
        for k in 0..5usize {
            let len = if k == 0 {
                dl + 1
            } else if k == 3 {
                30_000
            } else {
                dl
            };
            let piece = &data[pos..pos + len];
            pos += len;
            vols.push(fixtures::rar5_volume_n(
                &[(inner, total, piece, k > 0, true)],
                k as u64,
            ));
        }
        vols.push(fixtures::rar5_volume_n(
            &[(inner, total, &data[pos..pos + 40_000], true, false)],
            5,
        ));
        let names: Vec<String> = (0..6).map(|k| format!("src{k}NoDot")).collect();
        for (n, v) in names.iter().zip(&vols) {
            std::fs::write(dir.join(n), v).unwrap();
        }
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_protect_sources();
        // Engage on the uniform majority (vol 0 late), then the odd
        // volume contradicts and the whole group demotes - to Discard.
        for vi in [1usize, 2, 4, 5, 0, 3] {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 20 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, why)| why == "non-uniform store set"),
            "{:?}",
            rep.fallbacks
        );
        // Sources byte-identical, and no output was left behind.
        for (n, v) in names.iter().zip(&vols) {
            assert_eq!(
                &std::fs::read(dir.join(n)).unwrap(),
                v,
                "source {n} touched"
            );
        }
        assert!(!dir.join(inner).exists(), "partial output must not survive");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two archives in one NZB that reuse an inner filename must not
    /// share a writer (conflicting-offset interleave, silent since inner
    /// files aren't PAR2-covered) - and must NOT be merged into one group
    /// (the shared name is wholly contained, not split: no archive-chain
    /// evidence).
    #[test]
    fn same_inner_name_across_archives_gets_own_files() {
        let dir = tmpdir("namecollide");
        let film_a = payload(120_000, 31);
        let film_b = payload(140_000, 32);
        let samp_a = payload(30_000, 33);
        let samp_b = payload(40_000, 34);
        let va = fixtures::rar5_volume(&[
            ("filmA.mkv", 120_000, &film_a, false, false),
            ("sample.mkv", 30_000, &samp_a, false, false),
        ]);
        let vb = fixtures::rar5_volume(&[
            ("filmB.mkv", 140_000, &film_b, false, false),
            ("sample.mkv", 40_000, &samp_b, false, false),
        ]);
        let ex = Extractor::new(&dir, 2, true);
        feed(&ex, 0, "a.rar", &va, 8000, 61);
        feed(&ex, 1, "b.rar", &vb, 8000, 62);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("filmA.mkv")).unwrap(), film_a);
        assert_eq!(std::fs::read(dir.join("filmB.mkv")).unwrap(), film_b);
        // One sample per archive, the second under a disambiguated name.
        let mut samples: Vec<Vec<u8>> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with("sample.mkv"))
            .map(|e| std::fs::read(e.path()).unwrap())
            .collect();
        samples.sort_by_key(|s| s.len());
        assert_eq!(samples.len(), 2, "each archive keeps its own sample");
        assert_eq!(samples[0], samp_a);
        assert_eq!(samples[1], samp_b);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plain_files_still_work() {
        let dir = tmpdir("plain");
        let data = payload(50_000, 9);
        let ex = Extractor::new(&dir, 1, true);
        // Not a rar - offset-0 article sniffs plain. Feed out of order.
        ex.write(0, "doc.iso", 50_000, 30_000, &data[30_000..])
            .unwrap();
        ex.write(0, "doc.iso", 50_000, 0, &data[..30_000]).unwrap();
        ex.finish().unwrap();
        assert_eq!(std::fs::read(dir.join("doc.iso")).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypted_headers_fall_back_to_materialized_volume() {
        let dir = tmpdir("enc");
        // Signature + encryption block type 4 (valid CRC).
        let mut vol = Vec::new();
        vol.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
        let hdr = [0x04u8, 0x00]; // type 4, flags 0
        vol.extend_from_slice(&crc32fast::hash(&hdr).to_le_bytes());
        vol.push(2); // header size vint
        vol.extend_from_slice(&hdr);
        vol.extend_from_slice(&payload(5000, 6)); // opaque encrypted stuff
        let ex = Extractor::new(&dir, 1, true);
        let n = vol.len();
        ex.write(0, "sec.rar", n as u64, 0, &vol[..2000]).unwrap();
        ex.write(0, "sec.rar", n as u64, 2000, &vol[2000..])
            .unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.extracted.is_empty());
        // Volume materialized byte-exactly for a future unrar-with-password.
        assert_eq!(std::fs::read(dir.join("sec.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn protect_sources_happy_path_extracts_normally() {
        let dir = tmpdir("protect-ok");
        let total = payload(300_000, 12);
        let vols = [
            fixtures::rar5_volume_n(&[("film.mkv", 300_000, &total[..150_000], false, true)], 0),
            fixtures::rar5_volume_n(&[("film.mkv", 300_000, &total[150_000..], true, false)], 1),
        ];
        let ex = Extractor::new(&dir, 2, true);
        ex.set_protect_sources();
        feed(&ex, 0, "x.part1.rar", &vols[0], 8000, 41);
        feed(&ex, 1, "x.part2.rar", &vols[1], 8000, 42);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The 2026-07 damaged-post bench corruption: re-extraction fed
    /// volumes off disk, hit the holds cap, and the fallback materialized
    /// "volumes" over the very files being read (FileWriter::create
    /// truncates). Protect-sources mode must leave the source files
    /// byte-identical, never create slot writers, and delete any partial
    /// inner file.
    #[test]
    fn protect_sources_fallback_never_touches_source_files() {
        let dir = tmpdir("protect-fb");
        // THREE volumes, unequal, and the MIDDLE one is fed first. A
        // middle piece is neither its file's head nor its tail, so it
        // has no seed of its own and cannot resolve until a neighbour
        // parses - the only remaining shape that piles up holds now that
        // tail anchoring places final pieces on sight. (The arithmetic
        // gate also stays out: the sizes are not uniform.)
        let total = payload(30_000_000, 13);
        let vols = [
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[(
                    "film.mkv",
                    30_000_000,
                    &total[7_000_000..22_000_000],
                    true,
                    true,
                )],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
                2,
            ),
        ];
        // The volume files exist on disk, as in reextract_dir.
        std::fs::write(dir.join("x.part1.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.part2.rar"), &vols[1]).unwrap();
        std::fs::write(dir.join("x.part3.rar"), &vols[2]).unwrap();

        let ex = Extractor::new(&dir, 3, true);
        ex.set_protect_sources();
        ex.set_holds_cap(1); // floors at 8 MB - part2's data area exceeds it
        // Paging OFF: with it on this window pages and the set
        // re-extracts one-pass; the subject here is the fallback
        // discipline under budget pressure, so force the breach.
        ex.set_holds_paging(false);
        let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
            for (i, chunk) in vol.chunks(65_000).enumerate() {
                ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                    .unwrap();
            }
        };
        feed_seq(1, "x.part2.rar", &vols[1]);
        feed_seq(0, "x.part1.rar", &vols[0]);
        feed_seq(2, "x.part3.rar", &vols[2]);
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "expected a holds-cap fallback");

        // Source volumes byte-identical - NOT truncated/rewritten.
        assert_eq!(std::fs::read(dir.join("x.part1.rar")).unwrap(), vols[0]);
        assert_eq!(std::fs::read(dir.join("x.part2.rar")).unwrap(), vols[1]);
        assert_eq!(std::fs::read(dir.join("x.part3.rar")).unwrap(), vols[2]);
        // No slot writers, no half-written inner file masquerading as output.
        assert!(ex.slot_path(0).is_none());
        assert!(ex.slot_path(1).is_none());
        assert!(ex.slot_path(2).is_none());
        assert!(!dir.join("film.mkv").exists());
        let extra: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n != "x.part1.rar" && n != "x.part2.rar" && n != "x.part3.rar")
            .collect();
        assert!(extra.is_empty(), "unexpected files: {extra:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same shape with paging ON (the default): the re-extraction
    /// that used to DISCARD on the holds cap - a real failure mode, the
    /// 2026-07 damaged-post bench ran into exactly this - now pages the
    /// middle volume's window to scratch and completes one-pass, sources
    /// untouched and no scratch left behind.
    #[test]
    fn protect_sources_paged_holds_reextract_one_pass() {
        let dir = tmpdir("protect-paged");
        let total = payload(30_000_000, 13);
        let vols = [
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[(
                    "film.mkv",
                    30_000_000,
                    &total[7_000_000..22_000_000],
                    true,
                    true,
                )],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
                2,
            ),
        ];
        std::fs::write(dir.join("x.part1.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.part2.rar"), &vols[1]).unwrap();
        std::fs::write(dir.join("x.part3.rar"), &vols[2]).unwrap();
        let ex = Extractor::new(&dir, 3, true);
        ex.set_protect_sources();
        ex.set_holds_cap(1); // floors at 8 MB - part2's data area exceeds it
        let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
            for (i, chunk) in vol.chunks(65_000).enumerate() {
                ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                    .unwrap();
            }
        };
        feed_seq(1, "x.part2.rar", &vols[1]);
        feed_seq(0, "x.part1.rar", &vols[0]);
        feed_seq(2, "x.part3.rar", &vols[2]);
        let rep = ex.finish().unwrap();
        assert!(ex.holds_paged_total() > 0, "paging never engaged");
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        // Sources byte-identical, and nothing else in the directory -
        // in particular no scratch outliving finish. Handle closed
        // first (delete-pending filesystems keep the unlinked name
        // listed until last close).
        drop(ex);
        assert_eq!(std::fs::read(dir.join("x.part1.rar")).unwrap(), vols[0]);
        assert_eq!(std::fs::read(dir.join("x.part2.rar")).unwrap(), vols[1]);
        assert_eq!(std::fs::read(dir.join("x.part3.rar")).unwrap(), vols[2]);
        assert_eq!(
            dir_files(&dir),
            vec![
                "film.mkv".to_string(),
                "x.part1.rar".to_string(),
                "x.part2.rar".to_string(),
                "x.part3.rar".to_string()
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn protect_sources_non_rar_sniff_discards() {
        let dir = tmpdir("protect-plain");
        let data = payload(50_000, 14);
        std::fs::write(dir.join("doc.bin"), &data).unwrap();
        let ex = Extractor::new(&dir, 1, true);
        ex.set_protect_sources();
        ex.write(0, "doc.bin", 50_000, 0, &data[..30_000]).unwrap();
        ex.write(0, "doc.bin", 50_000, 30_000, &data[30_000..])
            .unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.iter().any(|(_, w)| w.contains("not a RAR")));
        // Source untouched - a plain writer would have truncated it.
        assert_eq!(std::fs::read(dir.join("doc.bin")).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Volume bytes that belong to no data area - service blocks (a RAR
    /// recovery record) and anything past the end-of-archive marker - go
    /// to the header stash, and once the mapper is complete that is EVERY
    /// remaining byte of the volume. Uncharged, a crafted volume (a tiny
    /// archive plus gigabytes of trailing junk) pinned all of it in RAM
    /// with no spill and no demote. The stash charges the holds budget,
    /// so the volume materializes instead.
    #[test]
    fn trailing_bytes_past_archive_end_are_capped() {
        let dir = tmpdir("hdrcap");
        let data = payload(1_000, 12);
        let mut vol = fixtures::rar5_volume(&[("a.bin", 1_000, &data, false, false)]);
        let archive_end = vol.len();
        vol.extend(payload(12 << 20, 3)); // junk past the end block
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(1); // floors at 8 MB
        // Paging OFF: with it on the junk pages to scratch and the tiny
        // archive extracts one-pass (bounded by the scratch ceiling,
        // pinned separately) - this test keeps the charge-and-demote
        // plumbing itself honest.
        ex.set_holds_paging(false);
        let art = 64_000;
        let mut s = 0usize;
        while s < vol.len() {
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
            s = e;
        }
        assert!(
            ex.holds_peak() <= (8 << 20) + art + archive_end,
            "stash peaked at {} - the junk was never charged",
            ex.holds_peak()
        );
        let rep = ex.finish().unwrap();
        // The reason must be one the caller ROUTES: a level-0 demote it
        // does not recognize means loose volumes, no payload, exit 0.
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap") && !w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        // Demoting is not losing: the volume is byte-identical on disk.
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // -- archive shape (the live badge's facts) --

    #[test]
    fn shape_is_empty_until_something_archive_shaped_parses() {
        let dir = tmpdir("shape-none");
        let ex = Extractor::new(&dir, 1, true);
        assert!(ex.archive_shape().is_none(), "nothing fed yet");
        // A loose file is not an archive and must never grow a badge.
        let data = payload(50_000, 9);
        feed(&ex, 0, "notes.txt", &data, 7000, 3);
        ex.finish().unwrap();
        assert!(ex.archive_shape().is_none(), "{:?}", shape_of(&ex));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_rar5_store_one_pass() {
        let dir = tmpdir("shape-store");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        // Known DURING the download, not just at finish - that is the
        // whole point of the live badge.
        assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
        ex.finish().unwrap();
        assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
        assert_eq!(
            ex.archive_shape().unwrap().display(),
            "RAR5 · stored · one-pass"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The naming oracle's key (Tier C item 4): the inner file's stated
    /// CRC32, latched off the same header parse the shape badge uses.
    /// Available DURING the download for the same reason the badge is.
    #[test]
    fn the_inner_file_crc_is_latched_for_the_naming_oracle() {
        let dir = tmpdir("crc-latch");
        let data = payload(200_000, 1);
        let want = crc32fast::hash(&data);
        // With the data CRC the way a real archiver always writes it.
        let vol = fixtures::rar5_volume_n_crc(
            &[("movie.mkv", 200_000, &data, false, false, Some(want))],
            0,
        );
        let ex = Extractor::new(&dir, 1, true);
        assert_eq!(ex.inner_crc(), None, "nothing fed yet");
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        assert_eq!(ex.inner_crc(), Some(("movie.mkv".to_string(), want)));
        ex.finish().unwrap();
        assert_eq!(ex.inner_crc(), Some(("movie.mkv".to_string(), want)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A header-encrypted set is the case the oracle cannot serve, and
    /// it must say so rather than offering a CRC of something else: the
    /// headers never parse, so there is no entry and no key. This is the
    /// `-hp` floor, pinned.
    #[test]
    fn a_header_encrypted_set_yields_no_crc_key() {
        let dir = tmpdir("crc-hdr");
        // Encrypted headers and no password: nothing parses, exactly as
        // for an obfuscated `-hp` post nobody has the key to.
        let vol = fixtures::rar4_encrypted_headers(200_000);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        assert!(shape_of(&ex).contains(&"encrypted"), "{:?}", shape_of(&ex));
        assert_eq!(ex.inner_crc(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_rar4() {
        let dir = tmpdir("shape-rar4");
        let data = payload(120_000, 4);
        let vol = fixtures::rar4_volume(&[("movie.mkv", 120_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        assert_eq!(shape_of(&ex)[0], "rar4", "{:?}", shape_of(&ex));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_compressed_set_as_unpacked_on_disk() {
        let dir = tmpdir("shape-comp");
        let data = payload(120_000, 2);
        // A compressed entry cannot be mapped at the top level: the
        // volume materializes and the badge has to say so.
        let vol = rar5_compressed_volume("movie.mkv", &data);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        let sh = shape_of(&ex);
        assert_eq!(sh[0], "rar5", "{sh:?}");
        assert!(sh.contains(&"compressed"), "{sh:?}");
        assert!(sh.contains(&"on-disk"), "{sh:?}");
        assert!(!sh.contains(&"one-pass"), "{sh:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_says_one_pass_when_an_encrypted_set_decrypts_in_stream() {
        let dir = tmpdir("shape-enc");
        let plain = payload(200_003, 41);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        // Plaintext-once: nothing is ever stored locked, so this is an
        // ordinary one-pass set that happens to be encrypted.
        assert_eq!(shape_of(&ex), ["rar5", "store", "encrypted", "one-pass"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_says_unlocked_at_the_end_on_the_legacy_encrypted_path() {
        let dir = tmpdir("shape-enc-legacy");
        let plain = payload(200_003, 41);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        // Ciphertext assembled at store offsets, unlocked by the finish
        // pass - the shape must distinguish it from plaintext-once.
        ex.set_instream_decrypt(false);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(
            shape_of(&ex),
            ["rar5", "store", "encrypted", "unlock-at-end"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The badge a RAR4 encrypted set earns. "unlock-at-end" is the
    /// honest token for it and always will be: RAR4 can never take the
    /// plaintext-once route (no password check to gate on), so it always
    /// assembles ciphertext and unlocks in the finish pass. The user-facing
    /// difference from before this landed is "one-pass at all" - it used to
    /// materialize every volume and read "on-disk".
    #[test]
    fn shape_says_rar4_encrypted_unlocks_at_the_end() {
        let dir = tmpdir("shape-enc4");
        let plain = payload(120_007, 43);
        let f = fixtures::encrypt_file_v4("hunter2", &plain, 51);
        let vol = fixtures::rar4_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(
            shape_of(&ex),
            ["rar4", "store", "encrypted", "unlock-at-end"],
            "RAR4 must not be badged as materialized any more"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_says_encrypted_when_the_headers_are_locked() {
        let dir = tmpdir("shape-hdr");
        // Encrypted headers with no password: nothing parses, so the
        // blocker is the only place the fact can come from.
        let vol = fixtures::rar4_encrypted_headers(200_000);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        let sh = shape_of(&ex);
        assert!(sh.contains(&"encrypted"), "{sh:?}");
        assert!(sh.contains(&"on-disk"), "{sh:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_a_top_level_7z_as_unpacked_on_disk() {
        let dir = tmpdir("shape-7z");
        // A top-level .7z the chase cannot take - here the start header
        // fails its own CRC, so `sevenz_start_header` declines before the
        // depth question even arises - lands on disk for the post-pass.
        // Without the signature sniff the badge would say nothing at all
        // about a 7z release. (A well-formed one streams instead: see
        // `sevenz_top_level_extracts_one_pass`.)
        let mut vol = b"7z\xbc\xaf\x27\x1c".to_vec();
        vol.extend_from_slice(&payload(80_000, 6));
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "release.7z", &vol, 7000, 3);
        ex.finish().unwrap();
        assert_eq!(shape_of(&ex), ["7z", "on-disk"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_tag_round_trips_through_the_wire_form() {
        let dir = tmpdir("shape-tag");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        // The daemon persists exactly this string and the dashboard
        // splits it back apart on whitespace.
        let tag = ex.archive_shape().unwrap().tag();
        assert_eq!(tag, "rar5 store one-pass");
        assert_eq!(
            tag.split(' ').map(shape_word).collect::<Vec<_>>(),
            ["RAR5", "stored", "one-pass"]
        );
        // An unknown token from a newer daemon still reads as itself.
        assert_eq!(shape_word("rar9"), "rar9");
    }

    // -- encrypted RAR5 store sets (native AES decryption) --

    // -- nested one-pass: store-in-store via the recursive child --

    /// Outer store volumes wrapping a store archive wrapping the final
    /// files: both layers map in one pass - the final files land
    /// byte-exact and NEITHER the outer volumes NOR the intermediate
    /// archive ever exist on disk. Driven across three feed orders
    /// (mirroring `multi_file_store_set_survives_all_feed_orders`).
    #[test]
    fn two_level_store_set_extracts_one_pass() {
        let a = payload(300_000, 81);
        let b = payload(150_000, 82);
        let inner_arch = fixtures::rar5_volume(&[
            ("A.mkv", 300_000, &a, false, false),
            ("B.mkv", 150_000, &b, false, false),
        ]);
        let n = inner_arch.len();
        // WinRAR-true: vol 0's piece is one byte longer than vol 1's.
        let (c1, c2) = (n / 3 + 1, n / 3 + 1 + n / 3);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[..c1], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[c1..c2], true, true)],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[c2..], true, false)],
                2,
            ),
        ];
        for (t, order) in [[0usize, 1, 2], [2, 1, 0], [1, 2, 0]].iter().enumerate() {
            let dir = tmpdir(&format!("nested2l{t}"));
            let ex = Extractor::new(&dir, 3, true);
            for &vi in order {
                let name = format!("obf{:02x}.bin", (vi as u8) ^ 0x3c);
                feed(&ex, vi, &name, &vols[vi], 7000, 70 + vi as u64);
            }
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks.is_empty(),
                "order {order:?}: {:?}",
                rep.fallbacks
            );
            assert_eq!(
                rep.extracted,
                vec![
                    ("A.mkv".to_string(), 300_000),
                    ("B.mkv".to_string(), 150_000)
                ],
                "order {order:?}"
            );
            assert_eq!(
                std::fs::read(dir.join("A.mkv")).unwrap(),
                a,
                "order {order:?}"
            );
            assert_eq!(
                std::fs::read(dir.join("B.mkv")).unwrap(),
                b,
                "order {order:?}"
            );
            // One pass: no outer volume, no intermediate archive.
            assert_eq!(
                dir_files(&dir),
                vec!["A.mkv".to_string(), "B.mkv".to_string()],
                "order {order:?}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// An INNER volume boundary spanning two OUTER volumes: the child's
    /// base for the final file's continuation piece resolves through the
    /// composed cum-chain, with the level-1 volume's bytes arriving via
    /// two different parent slots.
    #[test]
    fn nested_split_chain() {
        let f = payload(400_000, 83);
        let iv1 = fixtures::rar5_volume_n(&[("F.mkv", 400_000, &f[..200_000], false, true)], 0);
        let iv2 = fixtures::rar5_volume_n(&[("F.mkv", 400_000, &f[200_000..], true, false)], 1);
        let cut = iv2.len() / 2;
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(
                &[
                    ("inner.part1.rar", iv1.len() as u64, &iv1, false, false),
                    (
                        "inner.part2.rar",
                        iv2.len() as u64,
                        &iv2[..cut],
                        false,
                        true,
                    ),
                ],
                0,
            ),
            fixtures::rar5_volume_n(
                &[(
                    "inner.part2.rar",
                    iv2.len() as u64,
                    &iv2[cut..],
                    true,
                    false,
                )],
                1,
            ),
        ];
        for (t, order) in [[0usize, 1], [1, 0]].iter().enumerate() {
            let dir = tmpdir(&format!("nestedsplit{t}"));
            let ex = Extractor::new(&dir, 2, true);
            for &vi in order {
                feed(
                    &ex,
                    vi,
                    &format!("zz{vi}.bin"),
                    &vols[vi],
                    8000,
                    90 + vi as u64,
                );
            }
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks.is_empty(),
                "order {order:?}: {:?}",
                rep.fallbacks
            );
            assert_eq!(
                rep.extracted,
                vec![("F.mkv".to_string(), 400_000)],
                "order {order:?}"
            );
            assert_eq!(
                std::fs::read(dir.join("F.mkv")).unwrap(),
                f,
                "order {order:?}"
            );
            assert_eq!(
                dir_files(&dir),
                vec!["F.mkv".to_string()],
                "order {order:?}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Reusing the verified article CRC must compose to exactly what
    /// hashing the routed bytes composes: a clean nested store set still
    /// one-passes with no demotion, in every feed order.
    #[test]
    fn a_reused_article_crc_extracts_the_same_as_hashing() {
        let f = payload(400_000, 86);
        let whole = crc32fast::hash(&f);
        let iv = [
            // WinRAR-true geometry: volume 0 carries one byte more (its
            // main header has no volume-number field).
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[..150_001],
                    false,
                    true,
                    Some(crc32fast::hash(&f[..150_001])),
                )],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[150_001..300_001],
                    true,
                    true,
                    Some(crc32fast::hash(&f[150_001..300_001])),
                )],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
                2,
            ),
        ];
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        for seed in [11u64, 12, 13] {
            let dir = tmpdir(&format!("reusecrc{seed}"));
            let ex = Extractor::new(&dir, 1, true);
            feed_verified(&ex, 0, "o.rar", &outer, 7000, seed, 0);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "seed {seed}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f, "seed {seed}");
            assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()], "seed {seed}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The reused value must actually REACH the composition, and be the
    /// thing the finish gate judges. A single-level store volume whose
    /// entry carries a real header CRC is the case where the composed
    /// value is actually compared: hand over article CRCs that do not
    /// describe the bytes and the gate has to demote. The payload itself
    /// is intact, so nothing but the passed-in CRC can cause that - and
    /// if the run came out clean, the caller's CRC was being ignored and
    /// the fast path would be vouching for nothing.
    #[test]
    fn a_wrong_article_crc_is_not_taken_on_trust() {
        let f = payload(300_000, 88);
        let vol = fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                300_000,
                &f,
                false,
                false,
                Some(crc32fast::hash(&f)),
            )],
            0,
        );

        // Truthful CRCs: extracts, no demotion.
        let dir = tmpdir("reusecrcok1");
        let ex = Extractor::new(&dir, 1, true);
        feed_verified(&ex, 0, "v.rar", &vol, 7000, 11, 0);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "clean set demoted: {:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        std::fs::remove_dir_all(&dir).unwrap();

        // Same bytes, CRCs that describe nothing: must NOT pass the gate.
        let dir = tmpdir("reusecrcbad");
        let ex = Extractor::new(&dir, 1, true);
        feed_verified(&ex, 0, "v.rar", &vol, 7000, 11, 0x5AA5_5AA5);
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "a CRC that describes nothing was accepted as proof the payload is good"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Store inner volumes carrying real header CRCs (last piece = whole
    /// file, earlier pieces = their own bytes, like real archivers write):
    /// intact data one-pass extracts with NO demotion in any feed order -
    /// the in-stream CRC gate must never false-positive on clean sets.
    #[test]
    fn nested_store_with_crcs_extracts_clean() {
        let f = payload(400_000, 86);
        let whole = crc32fast::hash(&f);
        let iv = [
            // WinRAR-true geometry: volume 0 carries one byte more (its
            // main header has no volume-number field).
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[..150_001],
                    false,
                    true,
                    Some(crc32fast::hash(&f[..150_001])),
                )],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[150_001..300_001],
                    true,
                    true,
                    Some(crc32fast::hash(&f[150_001..300_001])),
                )],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
                2,
            ),
        ];
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        for seed in [11u64, 12, 13] {
            let dir = tmpdir(&format!("nestcrcok{seed}"));
            let ex = Extractor::new(&dir, 1, true);
            feed(&ex, 0, "o.rar", &outer, 7000, seed);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "seed {seed}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f, "seed {seed}");
            assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()], "seed {seed}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The residual gauntlet gap: a store inner set whose DATA was
    /// damaged before packing (headers intact, header CRCs computed over
    /// the original bytes). Mapping succeeds, so without the CRC gate the
    /// corrupt payload would ship silently with rc=0. The gate must
    /// demote the nested level to materialized volumes - byte-exact as
    /// packed, damage included, where a par2 set can reach them - and
    /// delete the corrupt extracted output.
    #[test]
    fn nested_store_data_damage_demotes_on_crc() {
        let f = payload(400_000, 87);
        let whole = crc32fast::hash(&f);
        let mut iv = [
            // WinRAR-true geometry: volume 0 carries one byte more (its
            // main header has no volume-number field).
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[..150_001],
                    false,
                    true,
                    Some(crc32fast::hash(&f[..150_001])),
                )],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[150_001..300_001],
                    true,
                    true,
                    Some(crc32fast::hash(&f[150_001..300_001])),
                )],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
                2,
            ),
        ];
        // Poster damage: flip bytes in the middle of i.part2.rar - deep
        // inside its 150 KB data area, nowhere near the headers.
        let mid = iv[1].len() / 2;
        for b in &mut iv[1][mid..mid + 64] {
            *b ^= 0xA5;
        }
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        let dir = tmpdir("nestcrcbad");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &outer, 7000, 21);
        let rep = ex.finish().unwrap();
        let nested: Vec<_> = rep
            .fallbacks
            .iter()
            .filter(|(_, w)| w.starts_with("nested fallback:"))
            .collect();
        assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            nested[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        for (_, w) in &rep.fallbacks {
            assert!(
                !w.contains("compressed")
                    && !w.contains("encrypted")
                    && !w.contains("password")
                    && !w.contains("held-bytes cap")
                    && !w.contains("incomplete mapping"),
                "nested reason leaks a volume-remediation trigger: {w}"
            );
        }
        // The corrupt payload must not masquerade as output; the volumes
        // materialize byte-exact AS PACKED (damage included) so a
        // recovery set can verify and repair them.
        assert!(!dir.join("F.mkv").exists(), "corrupt output survived");
        for (i, v) in iv.iter().enumerate() {
            let p = dir.join(format!("i.part{}.rar", i + 1));
            assert_eq!(
                &std::fs::read(&p).unwrap(),
                v,
                "volume {} not byte-exact",
                i + 1
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A nested RAR4 store file now verifies IN-STREAM (finding 9): the v4
    /// parser retains the header CRC, so clean inner data extracts on the
    /// fast path (no demote to a materialized level-1 archive), and
    /// damaged-before-packing data is caught by the composed CRC and
    /// demoted honestly instead of shipping with rc=0.
    #[test]
    fn nested_rar4_store_verifies_in_stream() {
        // Clean inner RAR4: composed CRC matches, one-pass extract, no demote.
        let dir = tmpdir("nest-rar4-gate");
        let data = payload(60_000, 71);
        let v4 = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        let outer = fixtures::rar5_volume(&[("inner.rar", v4.len() as u64, &v4, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 5000, 17);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("old.avi")).unwrap(), data);
        assert!(
            !dir.join("inner.rar").exists(),
            "clean inner RAR4 should not materialize"
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // Damaged inner RAR4: header CRC over pristine bytes, data area
        // flipped - the gate must demote, never ship the corrupt payload.
        let dir = tmpdir("nest-rar4-gate-bad");
        let mut v4b = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        let off = {
            let mut m = crate::rar::VolumeMapper::new(v4b.len() as u64);
            m.feed(0, &v4b);
            m.entries[0].data_off as usize
        };
        for b in &mut v4b[off + 30_000..off + 30_064] {
            *b ^= 0x5A;
        }
        let outer = fixtures::rar5_volume(&[("inner.rar", v4b.len() as u64, &v4b, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 5000, 29);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("failed its stored CRC")),
            "{:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("old.avi").exists(),
            "corrupt inner RAR4 payload shipped"
        );
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), v4b);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Compressed inner archive: the child demotes and materializes the
    /// level-1 file intact - exactly the single-level output the disk
    /// post-pass expects - reported as a nested fallback whose wording
    /// must never pattern-match the caller's volume-level remediation
    /// branches. The job itself succeeds.
    #[test]
    fn nested_compressed_inner_demotes() {
        let dir = tmpdir("nestedcomp");
        let junk = payload(120_000, 84);
        let inner_arch = rar5_compressed_volume("F.bin", &junk);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 9);
        let rep = ex.finish().unwrap();
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
        assert!(!dir.join("v.rar").exists(), "one-pass: no outer volume");
        assert!(
            rep.extracted
                .iter()
                .any(|(n, s)| n == "inner.rar" && *s == inner_arch.len() as u64),
            "{:?}",
            rep.extracted
        );
        let nested: Vec<_> = rep
            .fallbacks
            .iter()
            .filter(|(_, w)| w.starts_with("nested fallback:"))
            .collect();
        assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
        for (_, w) in &rep.fallbacks {
            assert!(
                !w.contains("compressed")
                    && !w.contains("encrypted")
                    && !w.contains("password")
                    && !w.contains("held-bytes cap")
                    && !w.contains("incomplete mapping"),
                "nested reason leaks a volume-remediation trigger: {w}"
            );
        }
        assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b): the prevalence tally reflects a known nested fixture. A
    /// store-in-store (outer -> inner.rar -> movie.mkv) streams the inner
    /// payload entirely in RAM, so the depth-1 child logs one in-stream
    /// `rar-store` level and bumps `in_stream` + `rar_store`. Depth 0 (the
    /// outer set) is never counted. The tally is process-global under the
    /// parallel runner, so the assertions are lower-bound deltas, not
    /// absolutes.
    #[test]
    fn nested_prevalence_counts_in_stream_store() {
        let before = nested_prevalence();
        let dir = tmpdir("nestprev");
        let data = payload(90_000, 91);
        let inner_arch =
            fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 41);
        let rep = ex.finish().unwrap();
        // In-stream store-in-store: the inner payload is produced directly,
        // no volume ever materialized, no fallback.
        assert_eq!(
            rep.extracted,
            vec![("movie.mkv".to_string(), data.len() as u64)]
        );
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        let after = nested_prevalence();
        assert!(
            after.in_stream > before.in_stream,
            "in_stream did not advance ({} -> {})",
            before.in_stream,
            after.in_stream
        );
        assert!(
            after.rar_store > before.rar_store,
            "rar_store did not advance ({} -> {})",
            before.rar_store,
            after.rar_store
        );
        assert!(
            after.levels > before.levels,
            "levels did not advance ({} -> {})",
            before.levels,
            after.levels
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b) false-positive guard: `slot_inner_kind` names only the
    /// three nested-archive modes and stays silent (`None`) for a plain
    /// file, an unclassified span, or an already-demoted slot - so a
    /// demoting non-archive can never emit a `demoted` line and bias the
    /// tally. Deterministic (no counter, no fixture): the whole risk is
    /// this classifier saying "archive" for a non-archive.
    #[test]
    fn slot_inner_kind_ignores_non_archive_slots() {
        let dir = tmpdir("slotkind");
        let ex = Extractor::new(&dir, 1, true);
        let mut g = ex.inner.lock().unwrap();
        let base = g.slots.len();
        for m in [
            SlotMode::Plain,
            SlotMode::Unknown,
            SlotMode::RarFallback,
            SlotMode::Discard,
            SlotMode::SevenZ,
        ] {
            let mut s = Extractor::new_slot();
            s.mode = m;
            g.slots.push(s);
        }
        assert_eq!(Extractor::slot_inner_kind(&g, base), None, "Plain");
        assert_eq!(Extractor::slot_inner_kind(&g, base + 1), None, "Unknown");
        assert_eq!(
            Extractor::slot_inner_kind(&g, base + 2),
            None,
            "RarFallback"
        );
        assert_eq!(Extractor::slot_inner_kind(&g, base + 3), None, "Discard");
        assert_eq!(
            Extractor::slot_inner_kind(&g, base + 4),
            Some("7z"),
            "SevenZ"
        );
        drop(g);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b): a group-less nested inner that DEMOTES (an encrypted 7z
    /// with no password) emits the `demoted` diagnostic at the demote site
    /// - so `demoted` advances while `levels`/`in_stream` do NOT (the
    /// materialized .7z is counted under `disk` by the disk post-pass, not
    /// here). Lower-bound deltas: the tally is process-global.
    #[test]
    fn nested_prevalence_counts_demoted_sevenz() {
        let before = nested_prevalence();
        let f = payload(120_000, 173);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![
                sevenz_rust2::encoder_options::AesEncoderOptions::new(
                    sevenz_rust2::Password::from("secret"),
                )
                .into(),
            ]),
            false,
        );
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("prev-7z-demote");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 51);
        let rep = ex.finish().unwrap();
        // The 7z demoted to a materialized volume, as its own test proves.
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        let after = nested_prevalence();
        assert!(
            after.demoted > before.demoted,
            "demoted did not advance ({} -> {})",
            before.demoted,
            after.demoted
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b): the GROUPED demote topology (a multi-volume store set
    /// whose data is CRC-damaged demotes the whole group via the finish-time
    /// CRC gate -> fallback_group) also bumps `demoted` - but through
    /// `report_nested_prevalence`'s groups loop, NOT the demote site. This
    /// is the double-emit-safe counterpart to the group-less 7z demote test
    /// above: the two demote topologies take structurally different emit
    /// paths, and both must count. Lower-bound delta (process-global tally).
    #[test]
    fn nested_prevalence_counts_grouped_demote() {
        let before = nested_prevalence();
        let f = payload(400_000, 177);
        let whole = crc32fast::hash(&f);
        let mut iv = [
            // WinRAR-true geometry: volume 0 carries one byte more (its
            // main header has no volume-number field).
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[..150_001],
                    false,
                    true,
                    Some(crc32fast::hash(&f[..150_001])),
                )],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[(
                    "F.mkv",
                    400_000,
                    &f[150_001..300_001],
                    true,
                    true,
                    Some(crc32fast::hash(&f[150_001..300_001])),
                )],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
                2,
            ),
        ];
        // Poster damage deep in volume 2's data area -> the CRC gate demotes
        // the whole store group at finish.
        let mid = iv[1].len() / 2;
        for b in &mut iv[1][mid..mid + 64] {
            *b ^= 0xA5;
        }
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        let dir = tmpdir("prev-grouped-demote");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &outer, 7000, 57);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        let after = nested_prevalence();
        assert!(
            after.demoted > before.demoted,
            "grouped demoted did not advance ({} -> {})",
            before.demoted,
            after.demoted
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A 6-deep store chain: levels 0-4 map through the child chain; the
    /// child AT the depth cap is created disabled, so the level-5 archive
    /// materializes as an ordinary file. No error, no fallback noise. The
    /// cap is a per-chain setting: at a cap of 3 the level-3 archive is
    /// the one left materialized, proving the deepest layer materializes
    /// wherever the cap lands - it is never a hard failure.
    #[test]
    fn nested_depth_cap_materializes() {
        let data = payload(50_000, 85);
        let wrap = |name: &str, inner: &[u8]| {
            fixtures::rar5_volume(&[(name, inner.len() as u64, inner, false, false)])
        };
        // A 6-deep store chain: outer(a1) < a2 < a3 < a4 < a5 < payload.
        // Extracting akN yields ak(N+1); the archive produced AT the cap
        // is the one left materialized.
        let payload_rar = wrap("payload.bin", &data);
        let c5 = wrap("a5.rar", &payload_rar);
        let c4 = wrap("a4.rar", &c5);
        let c3 = wrap("a3.rar", &c4);
        let c2 = wrap("a2.rar", &c3);
        let outer = wrap("a1.rar", &c2);

        // Default cap (5): the level-5 extraction yields a5.rar, whose own
        // (depth-5) child is disabled, so a5.rar = payload_rar materializes.
        let dir = tmpdir("nesteddepth");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "outer.rar", &outer, 7000, 12);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(
            rep.extracted,
            vec![("a5.rar".to_string(), payload_rar.len() as u64)]
        );
        assert_eq!(std::fs::read(dir.join("a5.rar")).unwrap(), payload_rar);
        assert_eq!(dir_files(&dir), vec!["a5.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();

        // Configured shallower cap (3): the SAME chain now leaves a3.rar
        // (= c4) materialized - the cap is honoured, still no failure.
        let dir3 = tmpdir("nesteddepth3");
        let ex3 = Extractor::new(&dir3, 1, true);
        ex3.set_nested_max_depth(3);
        feed(&ex3, 0, "outer.rar", &outer, 7000, 12);
        let rep3 = ex3.finish().unwrap();
        assert!(rep3.fallbacks.is_empty(), "{:?}", rep3.fallbacks);
        assert_eq!(
            rep3.extracted,
            vec![("a3.rar".to_string(), c4.len() as u64)]
        );
        assert_eq!(std::fs::read(dir3.join("a3.rar")).unwrap(), c4);
        assert_eq!(dir_files(&dir3), vec!["a3.rar".to_string()]);
        std::fs::remove_dir_all(&dir3).unwrap();
    }

    /// The rollout gates: NZBFAST_NO_NESTED_ONEPASS=1 turns routing off
    /// at construction, and the runtime setter drives the same
    /// `nested_on` flag. With routing off the level-1 archive
    /// materializes exactly as before the nested path existed. The env
    /// PARSE is asserted on the pure helper - actually setting the
    /// process env here would flip the gate for every extractor other
    /// tests construct in the window (process-global state under the
    /// parallel runner), so the behavioral half runs through the setter,
    /// which gates the very same routing decision.
    #[test]
    fn nested_disabled_by_env() {
        // Env latch parse: "1" disables, anything else leaves routing on.
        assert!(nested_env_off_value(Some("1")));
        assert!(!nested_env_off_value(Some("0")));
        assert!(!nested_env_off_value(None));
        let dir = tmpdir("nestedenv");
        let ex = Extractor::new(&dir, 1, true);
        assert!(ex.inner.lock().unwrap().nested_on, "gate must default on");
        ex.set_nested_one_pass(false);

        let data = payload(90_000, 86);
        let inner_arch =
            fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        feed(&ex, 0, "v.rar", &outer, 7000, 5);
        let rep = ex.finish().unwrap();
        assert_eq!(
            rep.extracted,
            vec![("inner.rar".to_string(), inner_arch.len() as u64)]
        );
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
        assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();

        // Same behavior through the runtime setter (daemon rollout knob).
        let dir2 = tmpdir("nestedenv2");
        let ex2 = Extractor::new(&dir2, 1, true);
        ex2.set_nested_one_pass(false);
        feed(&ex2, 0, "v.rar", &outer, 7000, 6);
        let rep2 = ex2.finish().unwrap();
        assert_eq!(
            rep2.extracted,
            vec![("inner.rar".to_string(), inner_arch.len() as u64)]
        );
        assert_eq!(std::fs::read(dir2.join("inner.rar")).unwrap(), inner_arch);
        std::fs::remove_dir_all(&dir2).unwrap();
    }

    // -- nested one-pass phase 2: the chasing decompressor --

    // -- nested one-pass: extreme shapes + depth memory accounting --

    /// Every level of a 4-deep store chain carries a required sibling
    /// data file next to the deeper archive: level k holds "docs_k.txt"
    /// plus the level-(k+1) archive, the innermost holding the final
    /// payload. All four siblings and the payload land byte-exact in the
    /// output dir; no archive at ANY level and no volume ever touch
    /// disk. Driven forward and reverse (offset 0 last: every level
    /// classifies off drained holds).
    #[test]
    fn nested_mixed_payload_every_level() {
        let docs: Vec<Vec<u8>> = (0..4u8)
            .map(|k| payload(30_000 + k as usize * 1_000, 0xA0 + k))
            .collect();
        let final_pay = payload(200_000, 0xB1);
        let a3 = fixtures::rar5_volume(&[
            ("docs_3.txt", docs[3].len() as u64, &docs[3], false, false),
            (
                "payload.bin",
                final_pay.len() as u64,
                &final_pay,
                false,
                false,
            ),
        ]);
        let a2 = fixtures::rar5_volume(&[
            ("docs_2.txt", docs[2].len() as u64, &docs[2], false, false),
            ("a3.rar", a3.len() as u64, &a3, false, false),
        ]);
        let a1 = fixtures::rar5_volume(&[
            ("docs_1.txt", docs[1].len() as u64, &docs[1], false, false),
            ("a2.rar", a2.len() as u64, &a2, false, false),
        ]);
        let outer = fixtures::rar5_volume(&[
            ("docs_0.txt", docs[0].len() as u64, &docs[0], false, false),
            ("a1.rar", a1.len() as u64, &a1, false, false),
        ]);
        let want: Vec<(String, u64)> = vec![
            ("docs_0.txt".to_string(), docs[0].len() as u64),
            ("docs_1.txt".to_string(), docs[1].len() as u64),
            ("docs_2.txt".to_string(), docs[2].len() as u64),
            ("docs_3.txt".to_string(), docs[3].len() as u64),
            ("payload.bin".to_string(), final_pay.len() as u64),
        ];
        for rev in [false, true] {
            let dir = tmpdir(&format!("nestedmix{}", rev as u8));
            let ex = Extractor::new(&dir, 1, true);
            let art = 7000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if rev {
                (0..n_arts).rev().collect()
            } else {
                (0..n_arts).collect()
            };
            for i in order {
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
            assert_eq!(rep.extracted, want, "rev={rev}");
            for (k, d) in docs.iter().enumerate() {
                assert_eq!(
                    &std::fs::read(dir.join(format!("docs_{k}.txt"))).unwrap(),
                    d,
                    "rev={rev} docs_{k}"
                );
            }
            assert_eq!(
                std::fs::read(dir.join("payload.bin")).unwrap(),
                final_pay,
                "rev={rev}"
            );
            assert_eq!(
                dir_files(&dir),
                vec![
                    "docs_0.txt".to_string(),
                    "docs_1.txt".to_string(),
                    "docs_2.txt".to_string(),
                    "docs_3.txt".to_string(),
                    "payload.bin".to_string(),
                ],
                "rev={rev}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Same shape with the level-3 archive COMPRESSED (the chase engages
    /// at depth): it carries its own sibling plus a STORE archive whose
    /// payload keeps streaming below the chase. Store-level siblings,
    /// the chased sibling, and the deepest payload all land byte-exact;
    /// no archive at any level materializes.
    #[test]
    fn nested_mixed_payload_chase_at_depth() {
        let docs: Vec<Vec<u8>> = (0..4u8)
            .map(|k| payload(28_000 + k as usize * 1_000, 0x60 + k))
            .collect();
        let g = payload(150_000, 0x71);
        let deep = fixtures::rar5_volume(&[("G.bin", g.len() as u64, &g, false, false)]);
        let a3 = rars_compressed_volume(&[("docs_3.txt", &docs[3]), ("deep.rar", &deep)]);
        assert_not_store(&a3);
        let a2 = fixtures::rar5_volume(&[
            ("docs_2.txt", docs[2].len() as u64, &docs[2], false, false),
            ("a3.rar", a3.len() as u64, &a3, false, false),
        ]);
        let a1 = fixtures::rar5_volume(&[
            ("docs_1.txt", docs[1].len() as u64, &docs[1], false, false),
            ("a2.rar", a2.len() as u64, &a2, false, false),
        ]);
        let outer = fixtures::rar5_volume(&[
            ("docs_0.txt", docs[0].len() as u64, &docs[0], false, false),
            ("a1.rar", a1.len() as u64, &a1, false, false),
        ]);
        let dir = tmpdir("nestedmixchase");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 17);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        for (k, d) in docs.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("docs_{k}.txt"))).unwrap(),
                d,
                "docs_{k}"
            );
        }
        assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
        assert_eq!(
            dir_files(&dir),
            vec![
                "G.bin".to_string(),
                "docs_0.txt".to_string(),
                "docs_1.txt".to_string(),
                "docs_2.txt".to_string(),
                "docs_3.txt".to_string(),
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One nested level fanning WIDE: a level-1 archive split across
    /// three outer volumes carries EIGHT sibling files around one deeper
    /// archive - the out_names/name-claim machinery holds up with many
    /// concurrent child slots at depth. Two volume feed orders.
    #[test]
    fn nested_many_siblings_wide() {
        let sibs: Vec<Vec<u8>> = (0..8u8)
            .map(|i| payload(40_000 + i as usize * 3_000, 0xC0 + i))
            .collect();
        let names: Vec<String> = (0..8).map(|i| format!("sib_{i}.dat")).collect();
        let fpay = payload(180_000, 0xD5);
        let deep = fixtures::rar5_volume(&[("final.bin", fpay.len() as u64, &fpay, false, false)]);
        let mut entries: Vec<(&str, u64, &[u8], bool, bool)> = Vec::new();
        for i in 0..4 {
            entries.push((
                names[i].as_str(),
                sibs[i].len() as u64,
                &sibs[i],
                false,
                false,
            ));
        }
        entries.push(("deep.rar", deep.len() as u64, &deep, false, false));
        for i in 4..8 {
            entries.push((
                names[i].as_str(),
                sibs[i].len() as u64,
                &sibs[i],
                false,
                false,
            ));
        }
        let inner1 = fixtures::rar5_volume(&entries);
        let n = inner1.len();
        let (c1, c2) = (n / 3, 2 * n / 3);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(&[("inner1.rar", n as u64, &inner1[..c1], false, true)], 0),
            fixtures::rar5_volume_n(&[("inner1.rar", n as u64, &inner1[c1..c2], true, true)], 1),
            fixtures::rar5_volume_n(&[("inner1.rar", n as u64, &inner1[c2..], true, false)], 2),
        ];
        for (t, order) in [[0usize, 1, 2], [2, 0, 1]].iter().enumerate() {
            let dir = tmpdir(&format!("nestedwide{t}"));
            let ex = Extractor::new(&dir, 3, true);
            for &vi in order {
                feed(
                    &ex,
                    vi,
                    &format!("w{vi}.bin"),
                    &vols[vi],
                    8000,
                    120 + vi as u64,
                );
            }
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks.is_empty(),
                "order {order:?}: {:?}",
                rep.fallbacks
            );
            for (i, s) in sibs.iter().enumerate() {
                assert_eq!(
                    &std::fs::read(dir.join(&names[i])).unwrap(),
                    s,
                    "order {order:?} sib {i}"
                );
            }
            assert_eq!(
                std::fs::read(dir.join("final.bin")).unwrap(),
                fpay,
                "order {order:?}"
            );
            let mut want = names.clone();
            want.push("final.bin".to_string());
            want.sort();
            assert_eq!(dir_files(&dir), want, "order {order:?}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Depth memory accounting: an 8 MB payload wrapped 1..5 store
    /// levels deep, fed in order - the chain-wide HoldsBudget peak must
    /// stay far under the cap and must NOT grow with depth (each level
    /// is an offset remap, not a buffered copy). A chased compressed
    /// inner at the same scale reports alongside: its frontier retention
    /// charges the same budget and stays bounded by it, not by the
    /// archive size.
    #[test]
    fn nested_depth_holds_peak_bounded() {
        let data = payload(8 << 20, 0x55);
        let art = 65_536usize;
        let mut rows: Vec<(String, usize)> = Vec::new();
        let mut store_peaks: Vec<usize> = Vec::new();
        for depth in 1..=5usize {
            let mut cur =
                fixtures::rar5_volume(&[("payload.bin", data.len() as u64, &data, false, false)]);
            for k in (1..depth).rev() {
                let name = format!("a{k}.rar");
                cur =
                    fixtures::rar5_volume(&[(name.as_str(), cur.len() as u64, &cur, false, false)]);
            }
            // In-order (the honest-post shape) and shuffled (out-of-order
            // arrival forces real held spans at every level).
            for shuffled in [false, true] {
                let dir = tmpdir(&format!("nestedmem{depth}{}", shuffled as u8));
                let ex = Extractor::new(&dir, 1, true);
                if shuffled {
                    feed(&ex, 0, "outer.rar", &cur, art, 200 + depth as u64);
                } else {
                    for (i, chunk) in cur.chunks(art).enumerate() {
                        ex.write(0, "outer.rar", cur.len() as u64, (i * art) as u64, chunk)
                            .unwrap();
                    }
                }
                let rep = ex.finish().unwrap();
                assert!(
                    rep.fallbacks.is_empty(),
                    "depth {depth}: {:?}",
                    rep.fallbacks
                );
                assert_eq!(
                    std::fs::read(dir.join("payload.bin")).unwrap(),
                    data,
                    "depth {depth}"
                );
                let peak = ex.holds_peak();
                if shuffled {
                    store_peaks.push(peak);
                    rows.push((format!("store x{depth} shuf"), peak));
                } else {
                    rows.push((format!("store x{depth} seq"), peak));
                }
                std::fs::remove_dir_all(&dir).unwrap();
            }
        }
        // Chased compressed inner at the same scale (~8 MB unpacked,
        // half-entropy input keeps the packed stream near half size).
        {
            let f = noisy(8 << 20, 0x99);
            let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
            assert_not_store(&inner_arch);
            let outer = fixtures::rar5_volume(&[(
                "inner.rar",
                inner_arch.len() as u64,
                &inner_arch,
                false,
                false,
            )]);
            let dir = tmpdir("nestedmemchase");
            let ex = Extractor::new(&dir, 1, true);
            for (i, chunk) in outer.chunks(art).enumerate() {
                ex.write(0, "outer.rar", outer.len() as u64, (i * art) as u64, chunk)
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
            rows.push(("chase 8 MB".to_string(), ex.holds_peak()));
            std::fs::remove_dir_all(&dir).unwrap();
        }
        println!("shape          holds_peak (bytes)");
        for (tag, p) in &rows {
            println!("{tag:<14} {p:>10}");
        }
        for (tag, p) in &rows {
            assert!(*p < 64 << 20, "{tag}: holds peak {p} breaches 64 MB");
        }
        // Not linear in depth: five levels must not retain per-level
        // copies (linear scaling would add ~8 MB of held payload per
        // extra level; the allowance covers shuffle variance only).
        assert!(
            store_peaks[4] <= store_peaks[0] + (2 << 20),
            "peak grows with depth: {store_peaks:?}"
        );
    }

    // -- nested one-pass phase 3: 7z inner archives via tail prefetch --

    // -- TODO 37 step 1: the SAME chase, one level up (posted .7z) --

    // -- one-pass zip (phase 2): the SAME chase, zip parser --

    // -- one-pass zip, byte-split `.zip.001` sets --

    // -- TODO 37 step 3: `.7z.001` split sets --

    // -- TODO 37 step 2: drop-behind trimming --
}

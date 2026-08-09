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

/// The other half of the [`DecryptBarrier`] handshake: the plaintext for
/// this output is verified AND renamed into place, and here are its
/// crypt facts (`E`/`K`/`T` [`CryptoJournalEvent`]s, gathered from the
/// ciphertext before the rename destroyed it). The daemon wires it to
/// `Journal::record_decrypted`, which republishes the placements the
/// barrier retired as `D` records - so a retry after a LATER failure in
/// the same job re-encrypts the local plaintext instead of refetching
/// the whole set (TODO 100). Optional and advisory: unwired, or skipped
/// when the facts cannot be gathered (RAR4's 8-byte salt does not fit an
/// `E` line, a check-less set cannot prove the password on resume), the
/// retirement simply stands and the retry refetches - the pre-existing,
/// always-correct behaviour.
pub type DecryptPublish = Arc<dyn Fn(&str, &[CryptoJournalEvent]) + Send + Sync>;

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
/// refetches. Header bytes retained in memory and discarded spans
/// return `No`.
///
/// `Held` means bytes of THIS span were parked for a later re-feed
/// (pre-classification hold, unresolved split base, beyond the mapped
/// window) - the article is not on disk yet, but may become so when the
/// holds drain. It carries the span's partial plain placements (may be
/// empty); the caller parks the article and completes its journal
/// record from [`Extractor::drain_late_placements`] once the drained
/// writes cover the rest. Without this, an article that arrived before
/// the offset-0 sniff established the store mapper was fully written by
/// the drain yet never journaled, so every crash/ENOSPC resume
/// refetched it for no reason.
pub enum Persist {
    No,
    Placed(Vec<Frag>),
    PlacedCrypto(Vec<Frag>),
    Held(Vec<Frag>),
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
    /// Queued by a held-span re-feed: no caller composes this job's
    /// child Persist into an article record, so `deliver_fwd` surfaces
    /// a Placed result through `late_placements` instead.
    refeed: bool,
}

/// Translation window for a forward whose child write returned `Held`:
/// the child parked (some of) the bytes and will write them inside its
/// OWN drain, where only child-space placements exist. The window maps
/// a child placement `(child_slot, child vol range)` back to the parent
/// slot's volume address space so `drain_late_placements` can report it
/// against the article that carried the bytes.
struct FwdWindow {
    parent_slot: usize,
    parent_vol_off: u64,
    child_slot: usize,
    child_off: u64,
    len: u64,
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
    /// §94 B: verified-block watermark handle. Set only on the ROOT
    /// extractor (nested levels' bytes are outside the PAR2 set, so
    /// child chases stay ungated), and only when the run opted in
    /// (env-gated in get.rs while the feature soaks). Chase frontier
    /// buffers created while this is Some are gated on it.
    verify_gate: Option<Arc<crate::live::VerifyGate>>,
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
    /// Post-rename decrypt publish notification, inherited like the
    /// barrier. See [`DecryptPublish`].
    decrypt_publish: Option<DecryptPublish>,
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
    /// True while [`Extractor::drain_holds`] is re-feeding held spans.
    /// The under-lock write sites capture their placements into
    /// `late_placements` only in this state, and the hold-push sites
    /// leave `span_held` alone (a re-held subrange belongs to an
    /// article that was already reported `Held` when it arrived).
    refeed_active: bool,
    /// Plain (non-crypto) writes performed by held-span re-feeds, in
    /// volume address space, drained by
    /// [`Extractor::drain_late_placements`]. The journal writer joins
    /// these against the articles it parked on a `Held` return - a
    /// held-then-drained article's bytes are durably on disk the moment
    /// the entry lands here (the re-feed writes run under the routing
    /// lock, before the drain call returns).
    late_placements: Vec<(usize, Frag)>,
    /// Set when the CURRENT top-level write parked bytes of its own
    /// span in `holds` (reset at write entry; re-feed pushes are
    /// excluded via `refeed_active`). Read by the write tail to return
    /// `Persist::Held` instead of `No`.
    span_held: bool,
    /// Child-to-parent translation windows for forwards the child
    /// parked (see [`FwdWindow`]). Grows only while a child is holding
    /// spans; never pruned - bounded by the count of held forwards.
    fwd_windows: Vec<FwdWindow>,
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
                decrypt_publish: None,
                verify_gate: None,
                // Plaintext-once gate: on for a live (enabled, fresh)
                // extractor unless the env kill-switch restores the
                // legacy ciphertext-then-finish-decrypt path. Tied to
                // `enabled` alone: the old `!resume` term was redundant
                // (every resume caller passed enabled=false too), and the
                // §94 A replay path resumes with the extractor ENABLED,
                // where in-stream decrypt must run - restore() put the
                // volumes back in ciphertext form, so the replay re-derives
                // keys from replayed headers exactly as the wire would.
                instream_decrypt: enabled
                    && std::env::var("NZBFAST_NO_INSTREAM_DECRYPT").map_or(true, |v| v != "1"),
                crypto_files: HashMap::new(),
                crypto_events: Arc::new(Mutex::new(Vec::new())),
                pw_probe: None,
                pw_probe_due: false,
                pw_probe_last: None,
                refeed_active: false,
                late_placements: Vec::new(),
                span_held: false,
                fwd_windows: Vec::new(),
            }),
        }
    }

    /// Drain the placements held-span re-feeds performed since the last
    /// call: `(slot, frag)` pairs for plain (non-crypto) writes that
    /// landed while `drain_holds` replayed parked spans, in THIS
    /// level's slot/volume address space. A nested child's drained
    /// holds are folded in, translated back through the forward windows
    /// recorded when the child parked them ([`FwdWindow`]); a child
    /// placement with no window (structurally unexpected) is dropped,
    /// which errs toward a refetch on resume. The journal writer joins
    /// these against articles parked on a [`Persist::Held`] return; the
    /// bytes are already durably written when an entry appears here.
    pub fn drain_late_placements(&self) -> Vec<(usize, Frag)> {
        let (mut out, child) = {
            let mut inner = self.inner.lock_ok();
            (
                std::mem::take(&mut inner.late_placements),
                inner.child.clone(),
            )
        };
        if let Some(c) = child {
            // Child lock inside its own call, ours re-taken after -
            // parent and child locks stay unnested, in either order.
            let child_placed = c.drain_late_placements();
            if !child_placed.is_empty() {
                let inner = self.inner.lock_ok();
                for (cslot, cf) in child_placed {
                    // A child hold is a subrange of exactly one
                    // forwarded write, so one containing window is the
                    // translation (duplicated windows carry identical
                    // mappings - routing is deterministic).
                    if let Some(w) = inner.fwd_windows.iter().find(|w| {
                        w.child_slot == cslot
                            && cf.vol_off >= w.child_off
                            && cf.vol_off + cf.len <= w.child_off + w.len
                    }) {
                        out.push((
                            w.parent_slot,
                            Frag {
                                vol_off: w.parent_vol_off + (cf.vol_off - w.child_off),
                                ..cf
                            },
                        ));
                    }
                }
            }
        }
        out
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
                ci.decrypt_publish = inner.decrypt_publish.clone();
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
        let span_held;
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            inner.span_held = false;
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
                        // Whole span parked pre-classification: the
                        // caller keeps the article's identity and joins
                        // it with drain_late_placements once the sniff
                        // establishes a mode and the drain writes it.
                        return Ok(Persist::Held(Vec::new()));
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
            span_held = inner.span_held;
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
        // A child that parked a forwarded piece writes it inside ITS
        // OWN drain later: the article must be parked exactly like a
        // parent-level hold, or the late placement it eventually
        // surfaces has no article to join.
        let child_held = fwd_persist.iter().any(|p| matches!(p, Persist::Held(_)));
        let span_held = span_held || child_held;
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
        // The partial view a `Held` return carries: plain fragments
        // only. Crypto fragments are deliberately left out - the caller
        // completes a held article into a plain `R` record, and an `R`
        // must never describe plaintext-once bytes; a held span with a
        // crypto part simply never completes and refetches on resume.
        let mut plain_frags: Vec<Frag> = if span_held {
            jobs.iter()
                .filter(|j| j.crypto.is_none())
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
                .collect()
        } else {
            Vec::new()
        };
        let held = |mut pf: Vec<Frag>| {
            pf.sort_by_key(|f| f.vol_off);
            Persist::Held(pf)
        };
        // Fold the child placements in: a child frag names a child-level
        // output file (already final for the journal); its vol_off is in
        // the CHILD slot's address space, translated back through the
        // affine forward window. Any child part not fully placed makes
        // the whole article refetch on resume (a child's OWN held spans
        // are not tracked across levels - only this level's drain
        // reports late placements).
        let mut crypto_span = crypto_span;
        for (f, p) in fwd.iter().zip(fwd_persist) {
            let (cfrags, child_plain) = match p {
                Persist::No | Persist::Held(_) => {
                    return Ok(if span_held {
                        held(plain_frags)
                    } else {
                        Persist::No
                    });
                }
                Persist::Placed(cfrags) => (cfrags, true),
                // A nested plaintext-once output: the whole article's
                // record must be a D line, since at least one fragment
                // can only restore by re-encryption.
                Persist::PlacedCrypto(cfrags) => {
                    crypto_span = true;
                    (cfrags, false)
                }
            };
            for cf in cfrags {
                let nf = Frag {
                    file: cf.file,
                    file_off: cf.file_off,
                    vol_off: offset + f.src_start as u64 + (cf.vol_off - f.file_off),
                    len: cf.len,
                };
                if span_held && child_plain {
                    plain_frags.push(nf.clone());
                }
                frags.push(nf);
            }
        }
        frags.sort_by_key(|f| f.vol_off);
        let mut covered_to = offset;
        for f in &frags {
            if f.vol_off > covered_to {
                return Ok(if span_held {
                    held(plain_frags)
                } else {
                    Persist::No
                });
            }
            covered_to = covered_to.max(f.vol_off + f.len);
        }
        if !frags.is_empty() && covered_to >= offset + data.len() as u64 {
            Ok(if crypto_span {
                Persist::PlacedCrypto(frags)
            } else {
                Persist::Placed(frags)
            })
        } else if span_held {
            Ok(held(plain_frags))
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
        w.write_at(offset, data)?;
        // A drained held span landing plain (spill/overflow/fallback
        // during a drain): file offset == volume offset by definition.
        // Direct-path fallback rewrites run with refeed_active false and
        // stay unreported, keeping their deliberate refetch-on-resume.
        if inner.refeed_active {
            inner.late_placements.push((
                slot,
                Frag {
                    file: w
                        .path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    file_off: offset,
                    vol_off: offset,
                    len: data.len() as u64,
                },
            ));
        }
        Ok(())
    }

    /// Deliver queued child forwards. Never called with the routing lock
    /// held - each job re-resolves its destination in
    /// [`Self::deliver_routed`], so a slot that fell back (or a child
    /// slot a merge displaced) in any window still gets its bytes.
    fn deliver_fwd(&self, pending: Vec<FwdJob>) -> io::Result<()> {
        for j in pending {
            let p = self.deliver_routed(
                j.parent_slot,
                j.vol_off,
                &j.name,
                j.size,
                j.file_off,
                &j.bytes,
                j.repair,
            )?;
            // A re-fed (drained-hold) forward has no caller composing
            // its Persist into an article record - surface a Placed
            // result so the article that parked these bytes can still
            // journal. PlacedCrypto stays unreported: a held article
            // must never complete into an `R` record over
            // plaintext-once bytes.
            if j.refeed
                && let Persist::Placed(cfrags) = p
            {
                let mut inner = self.inner.lock_ok();
                for cf in cfrags {
                    inner.late_placements.push((
                        j.parent_slot,
                        Frag {
                            file: cf.file,
                            file_off: cf.file_off,
                            vol_off: j.vol_off + (cf.vol_off - j.file_off),
                            len: cf.len,
                        },
                    ));
                }
            }
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
                                // The child parked (some of) this forward
                                // and will write it inside ITS drain,
                                // where only child-space placements
                                // exist: record the translation window
                                // now, and surface any partial child
                                // placements (already on disk) so the
                                // parked article can complete.
                                if let Persist::Held(cfrags) = &p {
                                    inner.fwd_windows.push(FwdWindow {
                                        parent_slot,
                                        parent_vol_off: vol_off,
                                        child_slot: cs,
                                        child_off: file_off,
                                        len: bytes.len() as u64,
                                    });
                                    for cf in cfrags {
                                        inner.late_placements.push((
                                            parent_slot,
                                            Frag {
                                                file: cf.file.clone(),
                                                file_off: cf.file_off,
                                                vol_off: vol_off + (cf.vol_off - file_off),
                                                len: cf.len,
                                            },
                                        ));
                                    }
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
                    if !inner.refeed_active {
                        inner.span_held = true;
                    }
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
                                if !inner.refeed_active {
                                    inner.span_held = true;
                                }
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
                                None => {
                                    w.write_at(base + piece_off, part)?;
                                    // A drained held span landing in an
                                    // inner file: report it, so the
                                    // article that parked these bytes
                                    // (Persist::Held) still journals.
                                    // Plain writes only - a crypto
                                    // placement must never complete
                                    // into an `R` record.
                                    if inner.refeed_active {
                                        inner.late_placements.push((
                                            slot,
                                            Frag {
                                                file: w
                                                    .path
                                                    .file_name()
                                                    .unwrap_or_default()
                                                    .to_string_lossy()
                                                    .into_owned(),
                                                file_off: base + piece_off,
                                                vol_off: offset + span_off,
                                                len,
                                            },
                                        ));
                                    }
                                }
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
                            refeed: inner.refeed_active,
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
            if !inner.refeed_active {
                inner.span_held = true;
            }
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

// The inline `mod tests` was 3,018 lines - moved out bodily (TODO 106) and
// split at its own nested-one-pass banner, since either half alone would
// otherwise want a size-gate entry.
#[cfg(test)]
mod mod_tests;

#[cfg(test)]
mod nested_tests;

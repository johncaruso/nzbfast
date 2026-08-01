//! Article-level download journal (design: M4, placement since the
//! crash-resume round): crash/kill resume.
//!
//! A header binds the journal to its NZB (md5 of the NZB bytes). On
//! restart with a matching header, recorded articles are skipped instead
//! of refetched. Two line shapes follow the header:
//!
//! - `<message-id>` - the v1 form: the article's bytes sit at their final
//!   offsets in the slot's own plain file (kept for journals written by
//!   older binaries; par2-main articles still record this way).
//! - Placement lines - `S`/`F`/`R` - record WHERE an article's bytes
//!   physically went, so direct-extracted articles (whose bytes live in
//!   the extracted inner file, not in any volume file) survive a crash
//!   too. [`restore`] copies those fragments back into the volume files
//!   the resume run works with; the live verifier then hashes every
//!   restored byte against the PAR2 block map before it is trusted.
//!
//!   ```text
//!   S <slot> <size> <volume-file-name>     restore destination for a slot
//!   F <idx> <file-name>                    file table (append-ordered;
//!                                          later runs may redefine idx)
//!   R <slot> <fidx>:<file_off>:<vol_off>:<len>[,…] <message-id>
//!   X <file-name>                          the journal's claim over this
//!                                          file is retired (see
//!                                          [`Journal::invalidate`])
//!   ```
//!
//! - Crypto lines - `E`/`K`/`T`/`D` - the plaintext-once records: an
//!   in-stream decrypted (encrypted store) output holds PLAINTEXT, so
//!   its placements cannot be copied back as posted bytes. `D` is `R`'s
//!   grammar under another letter, and [`restore`] honors it by
//!   RE-ENCRYPTING the on-disk plaintext (CBC is deterministic) using
//!   the facts the other three record. The name rides last so it may
//!   contain spaces; binary values are lowercase hex.
//!
//!   ```text
//!   E <salt> <lg2> <iv> <unp> <check|-> <name>  crypt params + password
//!                                          check of one output
//!   K <cipher-off> <block> <name>          chain checkpoint (one/MiB)
//!   T <pad|-> <name>                       final-block padding beyond unp
//!   D <slot> <fidx>:<file_off>:<vol_off>:<len>[,…] <message-id>
//!   ```
//!
//! Appends are one `write(2)` per line (no fsync): a killed process
//! loses nothing (the kernel has the data); only power loss can cost the
//! tail, and PAR2 verification catches that too. `X` is the exception -
//! it fsyncs, because something is about to mutate a file these records
//! describe and the retirement has to be on disk first. Older binaries
//! reading a placement journal see the S/F/R/X (and E/K/T/D) lines as
//! unknown message-ids and simply refetch - safe in both directions, and
//! in particular a DOWNGRADE resume of a plaintext-once journal refetches
//! encrypted files instead of copying plaintext into volume files.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::disk::sanitize_filename;
use crate::extract::{CryptoJournalEvent, Frag};

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn from_hex16(s: &str) -> Option<[u8; 16]> {
    from_hex(s)?.try_into().ok()
}

struct WriteState {
    file: File,
    /// Slots whose `S` line is already emitted this run.
    slots_emitted: HashSet<usize>,
    /// File name → index in this run's `F` table.
    files: HashMap<String, usize>,
    /// Destination names already claimed by an `S` line this run.
    used_names: HashSet<String>,
}

pub struct Journal {
    state: Mutex<WriteState>,
    pub path: PathBuf,
}

/// One journaled article: every fragment must restore for the article
/// to count as completed. `crypto` marks a `D` record; `crypto_frag`
/// says per fragment whether it restores by re-encryption (plaintext-
/// once file) or by ordinary copy (a plain neighbor the span straddled
/// into). Empty for `R` records.
pub struct Article {
    pub id: String,
    pub frags: Vec<Frag>,
    pub crypto_frag: Vec<bool>,
    pub crypto: bool,
}

/// Per-slot placement parsed from a journal.
pub struct SlotPlacement {
    pub name: String,
    pub size: u64,
    pub articles: Vec<Article>,
}

/// Crypt facts for one plaintext-once output (`E`/`K`/`T` records).
#[derive(Default, Clone)]
pub struct CryptoFileMeta {
    pub salt: [u8; 16],
    pub lg2: u8,
    pub iv: [u8; 16],
    pub unp: u64,
    /// Stored password check: a resume derives keys and PROVES the
    /// password against it before re-encrypting a single byte. Absent
    /// (archiver wrote none) means the password cannot be proven, so
    /// nothing restores and the articles refetch.
    pub check: Option<[u8; 12]>,
    /// Final-block plaintext beyond `unp` (`T` record; None until the
    /// tail block decrypted in the recorded run). Fragments touching the
    /// last cipher block are unrestorable without it.
    pub pad: Option<Vec<u8>>,
    /// Chain checkpoints: cipher offset -> cipher block [off-16, off).
    pub checkpoints: HashMap<u64, [u8; 16]>,
}

/// Everything a resume run learns from an existing journal.
#[derive(Default)]
pub struct ResumeState {
    /// v1-form articles: bytes trusted at final offsets in the slot's own
    /// file (includes par2-main records, which resume ignores anyway).
    pub completed: HashSet<String>,
    /// Placement-form articles, grouped by slot.
    pub slots: HashMap<usize, SlotPlacement>,
    /// Plaintext-once outputs by name (`E`/`K`/`T` facts).
    pub crypto_files: HashMap<String, CryptoFileMeta>,
}

/// What [`restore`] managed to rebuild from a placement journal.
#[derive(Default)]
pub struct Restored {
    /// Articles whose every fragment restored - skip refetching these.
    pub ids: HashSet<String>,
    /// Per-slot seeds for the extractor/verifier: the volume file to
    /// adopt and the (offset, len) spans now on disk in it.
    pub seeds: Vec<SlotSeed>,
}

pub struct SlotSeed {
    pub slot: usize,
    pub name: String,
    pub size: u64,
    pub spans: Vec<(u64, u64)>,
}

impl Journal {
    /// Open (or create) the journal for an NZB. Returns the journal and
    /// the resume state parsed from it (empty on a fresh run or when the
    /// existing journal belongs to a different NZB).
    pub fn open(dir: &Path, nzb_bytes: &[u8]) -> std::io::Result<(Journal, ResumeState)> {
        use md5::{Digest, Md5};
        let fp = format!("{:x}", Md5::digest(nzb_bytes));
        let path = dir.join(".nzbfast.journal");
        std::fs::create_dir_all(dir)?;

        let mut resume = ResumeState::default();
        let mut valid = false;
        if let Ok(f) = File::open(&path) {
            let mut lines = std::io::BufReader::new(f).lines();
            if let Some(Ok(header)) = lines.next() {
                if header.strip_prefix("nzbfast-journal v1 ") == Some(fp.as_str()) {
                    valid = true;
                    parse_lines(lines.map_while(Result::ok), &mut resume);
                }
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if !valid {
            // Fresh or mismatched: restart the journal.
            drop(file);
            file = File::create(&path)?;
            writeln!(file, "nzbfast-journal v1 {fp}")?;
            resume = ResumeState::default();
        }
        // The leading dot is invisible to Windows, where this file sits
        // in the user's own download folder looking like junk we forgot
        // to clean up. It is not junk - a failed job keeps it so a retry
        // fetches only what is missing - so hide it rather than drop it.
        crate::disk::hide_from_user(&path);
        Ok((
            Journal {
                state: Mutex::new(WriteState {
                    file,
                    slots_emitted: HashSet::new(),
                    files: HashMap::new(),
                    used_names: HashSet::new(),
                }),
                path,
            },
            resume,
        ))
    }

    /// Record one terminal article the v1 way (bytes at final offsets in
    /// the slot's own file) - used for par2-main slots.
    pub fn record(&self, id: &str) {
        let mut line = String::with_capacity(id.len() + 1);
        line.push_str(id);
        line.push('\n');
        let mut st = self.state.lock().unwrap();
        let _ = st.file.write_all(line.as_bytes());
    }

    /// Record one terminal article with its physical placement.
    /// `slot_file` is the slot's on-disk (name, size) when a writer
    /// exists; otherwise `name`/`size` (the yEnc header values) predict
    /// what a resume run will create.
    pub fn record_placed(
        &self,
        slot: usize,
        id: &str,
        slot_file: Option<(String, u64)>,
        name: &str,
        size: u64,
        frags: &[Frag],
    ) {
        self.record_letter('R', slot, id, slot_file, name, size, frags, None);
    }

    /// Record a plaintext-once placement: `R`'s grammar under the `D`
    /// letter with a per-fragment crypto marker (`:1` = restores by
    /// re-encryption, `:0` = ordinary copy of a plain neighbor), so
    /// [`restore`] re-encrypts instead of copying and an old binary
    /// refetches instead of copying plaintext into volume files.
    #[allow(clippy::too_many_arguments)]
    pub fn record_placed_crypto(
        &self,
        slot: usize,
        id: &str,
        slot_file: Option<(String, u64)>,
        name: &str,
        size: u64,
        frags: &[Frag],
        crypto_mask: &[bool],
    ) {
        self.record_letter('D', slot, id, slot_file, name, size, frags, Some(crypto_mask));
    }

    #[allow(clippy::too_many_arguments)]
    fn record_letter(
        &self,
        letter: char,
        slot: usize,
        id: &str,
        slot_file: Option<(String, u64)>,
        name: &str,
        size: u64,
        frags: &[Frag],
        crypto_mask: Option<&[bool]>,
    ) {
        if frags.is_empty() {
            return;
        }
        // Compose the record's lines (S table entry, new F entries, the
        // placement itself) into ONE buffer and land them with ONE
        // write(2): the kill-safety contract is per-record, and writeln!
        // on a raw File issues a syscall per format fragment - several
        // per article, all inside this mutex the decoders share.
        use std::fmt::Write as _;
        let mut out = String::new();
        let mut st = self.state.lock().unwrap();
        if !st.slots_emitted.contains(&slot) {
            let (dest, dsize) = match slot_file {
                Some((n, s)) => (n, s),
                None => {
                    let mut n = sanitize_filename(name);
                    if st.used_names.contains(&n) {
                        n = format!("{slot:03}-{n}");
                    }
                    (n, size)
                }
            };
            st.used_names.insert(dest.clone());
            st.slots_emitted.insert(slot);
            let _ = writeln!(out, "S {slot} {dsize} {dest}");
        }
        let mut list = String::new();
        for (i, f) in frags.iter().enumerate() {
            let fidx = match st.files.get(&f.file) {
                Some(&i) => i,
                None => {
                    let i = st.files.len();
                    st.files.insert(f.file.clone(), i);
                    let _ = writeln!(out, "F {i} {}", f.file);
                    i
                }
            };
            if !list.is_empty() {
                list.push(',');
            }
            list.push_str(&format!("{fidx}:{}:{}:{}", f.file_off, f.vol_off, f.len));
            if let Some(mask) = crypto_mask {
                list.push_str(if mask.get(i).copied().unwrap_or(true) { ":1" } else { ":0" });
            }
        }
        let _ = writeln!(out, "{letter} {slot} {list} {id}");
        let _ = st.file.write_all(out.as_bytes());
    }

    /// Write the drained [`CryptoJournalEvent`]s as `E`/`K`/`T` lines.
    pub fn record_crypto_events(&self, events: &[CryptoJournalEvent]) {
        if events.is_empty() {
            return;
        }
        // Formatted entirely outside the lock (nothing here reads the
        // write state), landed as one write.
        use std::fmt::Write as _;
        let mut out = String::new();
        for ev in events {
            match ev {
                CryptoJournalEvent::Params { name, salt, lg2, iv, unp, check } => {
                    let ck = check.map(|c| to_hex(&c)).unwrap_or_else(|| "-".into());
                    let _ = writeln!(
                        out,
                        "E {} {lg2} {} {unp} {ck} {name}",
                        to_hex(salt),
                        to_hex(iv)
                    );
                }
                CryptoJournalEvent::Checkpoint { name, off, block } => {
                    let _ = writeln!(out, "K {off} {} {name}", to_hex(block));
                }
                CryptoJournalEvent::TailPad { name, pad } => {
                    let p = if pad.is_empty() { "-".to_string() } else { to_hex(pad) };
                    let _ = writeln!(out, "T {p} {name}");
                }
            }
        }
        let mut st = self.state.lock().unwrap();
        let _ = st.file.write_all(out.as_bytes());
    }

    /// Retire this journal's claim over `files` - call it BEFORE their
    /// bytes stop being a faithful copy of what the `R` lines recorded,
    /// and only trust it once it returns `Ok`.
    ///
    /// The finish decrypt is the case that needs it: it replaces an
    /// encrypted RAR5 store output with its plaintext, and that output is
    /// exactly the file the placement records point INTO. Left claimed, a
    /// resume run would copy translated fragments out of the mutated file
    /// into the volume files and mark those message ids restored - so the
    /// articles are skipped instead of refetched, and without PAR2 the
    /// retry grinds on poisoned local bytes forever while the provider
    /// still holds every original article.
    ///
    /// Ordering is the whole point, so this is durable before it returns
    /// (one write, then fsync): a crash on either side of the call leaves
    /// a consistent pair. Before it, the file still IS the recorded bytes
    /// and the claim still stands (resume locally, no refetch); after it,
    /// the claim is gone whether or not the mutation ever landed (refetch,
    /// conservative but always correct).
    ///
    /// Retirement is positional, not global: it drops the placements
    /// recorded EARLIER in the journal, so a later run that refetches
    /// those articles and re-records them is trusted again.
    pub fn invalidate(&self, files: &[String]) -> std::io::Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        // One buffer, one write: a power cut can then only lose the whole
        // batch (nothing was published yet, so the claim is still true) -
        // never tear a name into a line that retires the wrong file.
        let mut buf = String::new();
        for f in files {
            // Names can't carry a newline - `sanitize_filename` maps every
            // control character - so one line per file stays unambiguous.
            buf.push_str("X ");
            buf.push_str(f);
            buf.push('\n');
        }
        let mut st = self.state.lock().unwrap();
        st.file.write_all(buf.as_bytes())?;
        st.file.sync_data()
    }

    /// Download finished and verified - the journal has served its purpose.
    pub fn remove(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn parse_lines(lines: impl Iterator<Item = String>, resume: &mut ResumeState) {
    // File table + per-id placements resolve in stream order: a later run
    // appends its own F table (reusing indexes) and its R lines must bind
    // to ITS definitions, so fidx→name is resolved per line, not at the end.
    let mut ftable: HashMap<usize, String> = HashMap::new();
    let mut placed: HashMap<String, (usize, Vec<Frag>, Vec<bool>, bool)> = HashMap::new();
    let mut slot_meta: HashMap<usize, (String, u64)> = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("E ") {
            // E <salt> <lg2> <iv> <unp> <check|-> <name>
            let mut it = rest.splitn(6, ' ');
            if let (Some(salt), Some(lg2), Some(iv), Some(unp), Some(ck), Some(name)) =
                (it.next(), it.next(), it.next(), it.next(), it.next(), it.next())
                && let (Some(salt), Ok(lg2), Some(iv), Ok(unp)) = (
                    from_hex16(salt),
                    lg2.parse::<u8>(),
                    from_hex16(iv),
                    unp.parse::<u64>(),
                )
                && !name.is_empty()
            {
                let check: Option<[u8; 12]> = match ck {
                    "-" => None,
                    _ => match from_hex(ck).and_then(|v| v.try_into().ok()) {
                        Some(c) => Some(c),
                        None => continue, // malformed check: drop the record
                    },
                };
                let name = sanitize_filename(name);
                let m = resume.crypto_files.entry(name).or_default();
                (m.salt, m.lg2, m.iv, m.unp, m.check) = (salt, lg2, iv, unp, check);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("K ") {
            // K <cipher-off> <block> <name>
            let mut it = rest.splitn(3, ' ');
            if let (Some(off), Some(block), Some(name)) = (it.next(), it.next(), it.next())
                && let (Ok(off), Some(block)) = (off.parse::<u64>(), from_hex16(block))
                && !name.is_empty()
            {
                resume
                    .crypto_files
                    .entry(sanitize_filename(name))
                    .or_default()
                    .checkpoints
                    .insert(off, block);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("T ") {
            // T <pad|-> <name>
            let mut it = rest.splitn(2, ' ');
            if let (Some(pad), Some(name)) = (it.next(), it.next())
                && !name.is_empty()
            {
                let pad = if pad == "-" { Some(Vec::new()) } else { from_hex(pad) };
                if let Some(pad) = pad {
                    resume
                        .crypto_files
                        .entry(sanitize_filename(name))
                        .or_default()
                        .pad = Some(pad);
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("F ") {
            if let Some((idx, name)) = rest.split_once(' ') {
                if let Ok(idx) = idx.parse::<usize>() {
                    if !name.is_empty() {
                        ftable.insert(idx, sanitize_filename(name));
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("S ") {
            let mut it = rest.splitn(3, ' ');
            if let (Some(slot), Some(size), Some(name)) = (it.next(), it.next(), it.next()) {
                if let (Ok(slot), Ok(size)) = (slot.parse::<usize>(), size.parse::<u64>()) {
                    if !name.is_empty() {
                        // Last S wins - a later run knows the actual file.
                        slot_meta.insert(slot, (sanitize_filename(name), size));
                    }
                }
            }
        } else if let Some((rest, crypto)) = line
            .strip_prefix("R ")
            .map(|r| (r, false))
            .or_else(|| line.strip_prefix("D ").map(|r| (r, true)))
        {
            let mut it = rest.splitn(3, ' ');
            let (Some(slot), Some(list), Some(id)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            let Ok(slot) = slot.parse::<usize>() else { continue };
            if id.is_empty() {
                continue;
            }
            let mut frags: Vec<Frag> = Vec::new();
            let mut crypto_frag: Vec<bool> = Vec::new();
            let mut ok = true;
            for part in list.split(',') {
                let mut nums = part.split(':');
                let (Some(fi), Some(fo), Some(vo), Some(ln)) =
                    (nums.next(), nums.next(), nums.next(), nums.next())
                else {
                    ok = false;
                    break;
                };
                let (Ok(fi), Ok(fo), Ok(vo), Ok(ln)) = (
                    fi.parse::<usize>(),
                    fo.parse::<u64>(),
                    vo.parse::<u64>(),
                    ln.parse::<u64>(),
                ) else {
                    ok = false;
                    break;
                };
                let Some(file) = ftable.get(&fi) else {
                    ok = false;
                    break;
                };
                // D fragments carry a 5th field marking how they restore
                // (missing = conservative crypto). R fragments never do.
                let cf = if crypto {
                    match nums.next() {
                        Some("0") => false,
                        Some("1") | None => true,
                        Some(_) => {
                            ok = false;
                            break;
                        }
                    }
                } else {
                    false
                };
                if ln == 0 || nums.next().is_some() {
                    ok = false;
                    break;
                }
                frags.push(Frag {
                    file: file.clone(),
                    file_off: fo,
                    vol_off: vo,
                    len: ln,
                });
                crypto_frag.push(cf);
            }
            if ok && !frags.is_empty() {
                // Last R/D wins (a failed restore refetches, re-records).
                placed.insert(id.to_string(), (slot, frags, crypto_frag, crypto));
            }
        } else if let Some(name) = line.strip_prefix("X ") {
            // Claim retired ([`Journal::invalidate`]): from here on this
            // file is no longer the bytes the records above describe, so
            // every placement with a fragment naming it - as a copy source,
            // or as its own identity destination - is dropped and those
            // articles refetch. Positional by construction: R lines after
            // this point describe the file as it is now and still count.
            if name.is_empty() {
                continue;
            }
            let name = sanitize_filename(name);
            placed.retain(|_, (_, frags, _, _)| !frags.iter().any(|f| f.file == name));
        } else {
            resume.completed.insert(line);
        }
    }
    for (id, (slot, frags, crypto_frag, crypto)) in placed {
        let Some((name, size)) = slot_meta.get(&slot) else { continue };
        resume
            .slots
            .entry(slot)
            .or_insert_with(|| SlotPlacement {
                name: name.clone(),
                size: *size,
                articles: Vec::new(),
            })
            .articles
            .push(Article { id, frags, crypto_frag, crypto });
    }
}

/// One plaintext-once fragment restore job for [`restore_crypto`]:
/// re-encrypt plaintext `[file_off, file_off+len)` of `file` and write
/// the resulting posted bytes at `vol_off` of the slot's volume file.
struct CryptoRestoreJob {
    article: usize, // index into a per-run article table
    file_off: u64,
    vol_off: u64,
    len: u64,
    dest: PathBuf,
    dest_size: u64,
}

/// Re-encrypt plaintext-once fragments back into volume files. Returns
/// per-article success (indexed like the caller's table). Walks each
/// file once in offset order with a rolling CBC chain, reseeding from
/// the journaled checkpoints across coverage holes and CROSS-VERIFYING
/// the rolling chain against every checkpoint it passes - a mismatch
/// (plaintext holes read as zeros, a truncated file) fails the fragment
/// and reseeds, so at most one checkpoint stride of garbage can ever be
/// written, and the resume run's full-hash verification catches even
/// that (restored bytes are never trusted unhashed).
fn restore_crypto(
    out_dir: &Path,
    resume: &ResumeState,
    password: Option<&str>,
    jobs_by_file: HashMap<&str, Vec<CryptoRestoreJob>>,
    article_ok: &mut [bool],
) {
    let Some(pw) = password else {
        for jobs in jobs_by_file.values() {
            for j in jobs {
                article_ok[j.article] = false;
            }
        }
        return;
    };
    for (fname, mut jobs) in jobs_by_file {
        let Some(meta) = resume.crypto_files.get(fname) else {
            for j in &jobs {
                article_ok[j.article] = false;
            }
            continue;
        };
        let fail_all = |jobs: &[CryptoRestoreJob], article_ok: &mut [bool]| {
            for j in jobs {
                article_ok[j.article] = false;
            }
        };
        let Some(keys) = crate::rarcrypt::derive_keys(pw, &meta.salt, meta.lg2) else {
            fail_all(&jobs, article_ok);
            continue;
        };
        // Prove the password before re-encrypting a single byte: a wrong
        // key would faithfully rebuild GARBAGE posted bytes for every
        // fragment, which the full-hash pass then damages wholesale. No
        // stored check means no proof - refetch instead of guessing.
        match meta.check {
            Some(stored) if crate::rarcrypt::make_check(&keys) == stored => {}
            _ => {
                fail_all(&jobs, article_ok);
                continue;
            }
        }
        let Ok(src) = File::open(out_dir.join(fname)) else {
            fail_all(&jobs, article_ok);
            continue;
        };
        let src_len = src.metadata().map(|m| m.len()).unwrap_or(0);
        let cipher_len = crate::rarcrypt::align16(meta.unp);
        let mut ckpts: Vec<(u64, [u8; 16])> =
            meta.checkpoints.iter().map(|(&o, &b)| (o, b)).collect();
        ckpts.sort_unstable();
        jobs.sort_by_key(|j| j.file_off);
        let mut dests: HashMap<PathBuf, Option<File>> = HashMap::new();
        // Rolling chain state: cipher block [cpos-16, cpos).
        let (mut cpos, mut chain): (u64, [u8; 16]) = (0, meta.iv);
        let mut walk = vec![0u8; 64 << 10];
        // Advance the rolling chain to `target` (16-aligned) by
        // encrypting the plaintext between, reseeding from the best
        // anchor at or below it; verify against every checkpoint passed.
        // Returns false when the stretch cannot be walked faithfully.
        let mut chain_to = |cpos: &mut u64, chain: &mut [u8; 16], target: u64| -> bool {
            if *cpos == target {
                return true;
            }
            // Best anchor at or below the target: the rolling state or
            // the nearest checkpoint, whichever is CLOSER. Every
            // decrypted region begins at a journaled K (the writer emits
            // one per decrypt boundary), so the nearest anchor is always
            // inside the target's own region and the walk can never
            // cross a coverage hole - the shape that used to re-encrypt
            // zero-filled plaintext into garbage posted bytes. The
            // password itself is proven against the stored check before
            // any of this runs.
            let (mut at, mut c) = (0u64, meta.iv);
            if *cpos <= target {
                (at, c) = (*cpos, *chain);
            }
            let below = ckpts.partition_point(|&(ko, _)| ko <= target);
            if let Some(&(ko, kb)) = ckpts[..below].iter().rev().find(|&&(ko, _)| ko > at) {
                (at, c) = (ko, kb);
            }
            let mut next_ck = ckpts.partition_point(|&(ko, _)| ko <= at);
            while at < target {
                let n = walk.len().min((target - at) as usize);
                if at + (n as u64) > src_len
                    || crate::disk::read_exact_at(&src, &mut walk[..n], at).is_err()
                {
                    return false;
                }
                let mut enc = crate::rarcrypt::CbcEncStream::new(&keys.aes(), &c);
                enc.encrypt(&mut walk[..n]);
                c = walk[n - 16..n].try_into().unwrap();
                at += n as u64;
                // Cross-verify each checkpoint the walk passes.
                while next_ck < ckpts.len() && ckpts[next_ck].0 <= at {
                    let (ko, kb) = ckpts[next_ck];
                    if ko > 0 && ko <= at {
                        let s = (n as u64 - (at - ko)) as usize;
                        let got: [u8; 16] = if s >= 16 {
                            walk[s - 16..s].try_into().unwrap()
                        } else {
                            c // ko == at edge: the rolling block
                        };
                        if got != kb {
                            return false;
                        }
                    }
                    next_ck += 1;
                }
            }
            (*cpos, *chain) = (at, c);
            true
        };
        for j in jobs {
            let lo = j.file_off & !15;
            let hi = (j.file_off + j.len).next_multiple_of(16).min(cipher_len);
            if hi <= lo || j.file_off + j.len > cipher_len {
                article_ok[j.article] = false;
                continue;
            }
            if !chain_to(&mut cpos, &mut chain, lo) {
                article_ok[j.article] = false;
                // Reseed for the next job from scratch.
                (cpos, chain) = (0, meta.iv);
                continue;
            }
            // Encrypt [lo, hi): plaintext from disk below unp, the
            // journaled padding beyond it.
            let n = (hi - lo) as usize;
            let mut buf = vec![0u8; n];
            let disk_end = hi.min(meta.unp);
            let mut ok = disk_end <= src_len;
            if ok && disk_end > lo {
                ok = crate::disk::read_exact_at(&src, &mut buf[..(disk_end - lo) as usize], lo)
                    .is_ok();
            }
            if ok && hi > meta.unp {
                match &meta.pad {
                    Some(pad) if pad.len() as u64 >= hi - meta.unp => {
                        let a = (meta.unp - lo) as usize;
                        buf[a..].copy_from_slice(&pad[..(hi - meta.unp) as usize]);
                    }
                    _ => ok = false,
                }
            }
            if !ok {
                article_ok[j.article] = false;
                continue;
            }
            let mut enc = crate::rarcrypt::CbcEncStream::new(&keys.aes(), &chain);
            enc.encrypt(&mut buf);
            let new_chain: [u8; 16] = buf[n - 16..].try_into().unwrap();
            let dest = dests.entry(j.dest.clone()).or_insert_with(|| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&j.dest)
                    .ok()
                    .inspect(|d| {
                        let cur = d.metadata().map(|m| m.len()).unwrap_or(0);
                        if j.dest_size > cur {
                            let _ = d.set_len(j.dest_size);
                        }
                    })
            });
            let Some(dest) = dest.as_ref() else {
                article_ok[j.article] = false;
                continue;
            };
            let a = (j.file_off - lo) as usize;
            if crate::disk::write_all_at(dest, &buf[a..a + j.len as usize], j.vol_off).is_err() {
                article_ok[j.article] = false;
                continue;
            }
            (cpos, chain) = (hi, new_chain);
        }
    }
}

/// Rebuild the volume files a resume run works with from a placement
/// journal: identity fragments (bytes already at their final offsets in
/// the destination) are trusted in place; translated fragments (bytes in
/// an extracted inner file) are COPIED back into the volume file - a
/// local disk copy instead of a network refetch - and plaintext-once
/// fragments (`D` records) are RE-ENCRYPTED back into posted bytes via
/// [`restore_crypto`]. An article counts as restored only when every
/// fragment succeeds; anything else refetches. Never fails: a missing
/// source file just drops its articles.
pub fn restore(out_dir: &Path, resume: &ResumeState, password: Option<&str>) -> Restored {
    let mut out = Restored::default();
    let mut buf = vec![0u8; 4 << 20];
    // Phase A: the crypto fragments, per file in offset order.
    let mut article_ids: Vec<(usize, &str)> = Vec::new(); // (slot, id)
    let mut jobs_by_file: HashMap<&str, Vec<CryptoRestoreJob>> = HashMap::new();
    let mut meta_missing: Vec<usize> = Vec::new();
    for (&slot, rec) in &resume.slots {
        if rec.name.is_empty() {
            continue;
        }
        for a in &rec.articles {
            if !a.crypto {
                continue;
            }
            let article = article_ids.len();
            article_ids.push((slot, &a.id));
            for (i, f) in a.frags.iter().enumerate() {
                if !a.crypto_frag.get(i).copied().unwrap_or(true) {
                    continue; // plain neighbor: phase B copies it
                }
                // A crypto fragment whose E facts are missing can only
                // refetch - falling through to a copy would put
                // PLAINTEXT into a volume file.
                if resume.crypto_files.contains_key(f.file.as_str()) {
                    jobs_by_file.entry(f.file.as_str()).or_default().push(CryptoRestoreJob {
                        article,
                        file_off: f.file_off,
                        vol_off: f.vol_off,
                        len: f.len,
                        dest: out_dir.join(&rec.name),
                        dest_size: rec.size,
                    });
                } else {
                    meta_missing.push(article);
                }
            }
        }
    }
    let mut article_ok = vec![true; article_ids.len()];
    for a in meta_missing {
        article_ok[a] = false;
    }
    // Which destinations already existed, taken BEFORE phase A: phase A
    // opens every crypto slot's destination with `create(true)` + `set_len`,
    // so a file that was deleted between runs (user cleanup, or a spent-
    // volume sweep) is recreated as a hole and phase B's `dest_existed`
    // probe then reads true. Its identity fragments - "the bytes are already
    // where the resume expects them" - are zeros, and they are accepted
    // instead of refetched, so with no PAR2 behind the job those zeros ship.
    // `identity_without_existing_file_refetches` is the test for the intent.
    let pre_existing: std::collections::HashSet<&str> = resume
        .slots
        .values()
        .filter(|r| !r.name.is_empty() && out_dir.join(&r.name).exists())
        .map(|r| r.name.as_str())
        .collect();
    restore_crypto(out_dir, resume, password, jobs_by_file, &mut article_ok);
    let crypto_verdict: HashMap<(usize, &str), bool> = article_ids
        .iter()
        .zip(&article_ok)
        .map(|(&(slot, id), &ok)| ((slot, id), ok))
        .collect();
    // Phase B: per-article accounting + the plain copies.
    for (&slot, rec) in &resume.slots {
        if rec.name.is_empty() {
            continue;
        }
        let dest_path = out_dir.join(&rec.name);
        let dest_existed = pre_existing.contains(rec.name.as_str());
        let mut dest: Option<File> = None; // opened lazily, only for copies
        let mut srcs: HashMap<&str, Option<File>> = HashMap::new();
        let mut spans: Vec<(u64, u64)> = Vec::new();
        let mut restored_here = false;
        for Article { id, frags, crypto_frag, crypto } in &rec.articles {
            if *crypto && crypto_verdict.get(&(slot, id.as_str())) != Some(&true) {
                continue;
            }
            let mut all_ok = true;
            for (fi, f) in frags.iter().enumerate() {
                // A crypto article's plaintext-once fragments were
                // written in phase A; only its plain-file fragments (a
                // span straddling into a neighboring unencrypted output)
                // still need the copy below.
                if *crypto && crypto_frag.get(fi).copied().unwrap_or(true) {
                    continue;
                }
                let identity = f.file == rec.name && f.file_off == f.vol_off;
                if identity {
                    // Bytes are already where the resume run expects them
                    // - nothing to move, but only if the file predates us.
                    if !dest_existed {
                        all_ok = false;
                        break;
                    }
                    continue;
                }
                let src = srcs
                    .entry(f.file.as_str())
                    .or_insert_with(|| File::open(out_dir.join(&f.file)).ok());
                let Some(src) = src.as_ref() else {
                    all_ok = false;
                    break;
                };
                if dest.is_none() {
                    dest = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open(&dest_path)
                        .ok()
                        .inspect(|d| {
                            let cur = d.metadata().map(|m| m.len()).unwrap_or(0);
                            if rec.size > cur {
                                let _ = d.set_len(rec.size);
                            }
                        });
                }
                let Some(dest) = dest.as_ref() else {
                    all_ok = false;
                    break;
                };
                let (mut done, mut ok) = (0u64, true);
                while done < f.len {
                    let n = ((f.len - done) as usize).min(buf.len());
                    if crate::disk::read_exact_at(src, &mut buf[..n], f.file_off + done).is_err() {
                        ok = false;
                        break;
                    }
                    if crate::disk::write_all_at(dest, &buf[..n], f.vol_off + done).is_err() {
                        ok = false;
                        break;
                    }
                    done += n as u64;
                }
                if !ok {
                    all_ok = false;
                    break;
                }
            }
            if all_ok {
                out.ids.insert(id.clone());
                for f in frags {
                    spans.push((f.vol_off, f.len));
                }
                restored_here = true;
            }
        }
        if restored_here {
            out.seeds.push(SlotSeed {
                slot,
                name: rec.name.clone(),
                size: rec.size,
                spans,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_roundtrip_and_fingerprint() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let nzb = b"<nzb>fake</nzb>";
        let (j, resume) = Journal::open(&dir, nzb).unwrap();
        assert!(resume.completed.is_empty());
        j.record("<a@x>");
        j.record("<b@x>");
        drop(j);

        // Same NZB: completed ids come back.
        let (j2, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.completed.len(), 2);
        assert!(resume.completed.contains("<a@x>"));
        j2.record("<c@x>");
        drop(j2);
        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.completed.len(), 3);

        // Different NZB: journal resets.
        let (_j4, resume) = Journal::open(&dir, b"<nzb>other</nzb>").unwrap();
        assert!(resume.completed.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn frag(file: &str, file_off: u64, vol_off: u64, len: u64) -> Frag {
        Frag {
            file: file.to_string(),
            file_off,
            vol_off,
            len,
        }
    }

    #[test]
    fn placement_roundtrip_restore_and_copyback() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-v2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // "Run 1": inner.bin carries a direct-extracted article's bytes at
        // a translated offset; plain.bin holds an identity article.
        let inner: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("inner.bin"), &inner).unwrap();
        let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 13) as u8).collect();
        std::fs::write(dir.join("plain.bin"), &plain).unwrap();

        let nzb = b"<nzb>v2</nzb>";
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        // Direct-extracted: volume bytes [5000, 15000) live in inner.bin
        // at [10000, 20000).
        j.record_placed(
            0,
            "<vol@x>",
            None,
            "vol.part1.rar",
            25_000,
            &[frag("inner.bin", 10_000, 5_000, 10_000)],
        );
        // Identity (plain slot, writer existed).
        j.record_placed(
            1,
            "<pl@x>",
            Some(("plain.bin".to_string(), 30_000)),
            "ignored",
            0,
            &[frag("plain.bin", 2_000, 2_000, 4_000)],
        );
        // Fragment pointing at a file that will not exist → must drop.
        j.record_placed(
            2,
            "<gone@x>",
            None,
            "ghost.rar",
            9_000,
            &[frag("deleted.bin", 0, 0, 100)],
        );
        drop(j);

        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        assert_eq!(resume.slots.len(), 3);
        let restored = restore(&dir, &resume, None);
        assert!(restored.ids.contains("<vol@x>"), "copy-back article restored");
        assert!(restored.ids.contains("<pl@x>"), "identity article restored");
        assert!(!restored.ids.contains("<gone@x>"), "missing source must drop");

        // The copied bytes really moved: vol.part1.rar[5000..15000] ==
        // inner.bin[10000..20000], and the file spans the recorded size.
        let vol = std::fs::read(dir.join("vol.part1.rar")).unwrap();
        assert_eq!(vol.len(), 25_000);
        assert_eq!(&vol[5_000..15_000], &inner[10_000..20_000]);

        let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
        assert_eq!(seed.name, "vol.part1.rar");
        assert_eq!(seed.spans, vec![(5_000, 10_000)]);
        // Identity slot seeds too (its spans are trusted in place).
        assert!(restored.seeds.iter().any(|s| s.slot == 1));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding A8, the restart half. A run that publishes decrypted
    /// plaintext over an encrypted store output stops that file from being
    /// the ciphertext its placement records describe. The next run must
    /// refetch those articles from the provider rather than copy the
    /// mutated bytes into the volume files and call them restored - which
    /// is what poisoned the retry loop, since without PAR2 nothing was
    /// ever going to notice.
    #[test]
    fn retired_claim_refetches_instead_of_restoring_mutated_bytes() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-x-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>retire</nzb>";

        // Run 1 direct-extracts two articles into movie.mkv (ciphertext at
        // store offsets) and one into an untouched sibling.
        let cipher: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("movie.mkv"), &cipher).unwrap();
        std::fs::write(dir.join("extra.bin"), &cipher).unwrap();
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        for (id, off) in [("<a@x>", 0u64), ("<b@x>", 10_000)] {
            j.record_placed(0, id, None, "v.part1.rar", 30_000, &[frag("movie.mkv", off, off, 10_000)]);
        }
        j.record_placed(1, "<c@x>", None, "v.part2.rar", 30_000, &[frag("extra.bin", 0, 0, 10_000)]);

        // Without the barrier those all come back - the intact-ciphertext
        // resume, the fast path a crash before the publish still gets.
        {
            let (_j, resume) = Journal::open(&dir, nzb).unwrap();
            let r = restore(&dir, &resume, None);
            assert!(r.ids.contains("<a@x>") && r.ids.contains("<b@x>") && r.ids.contains("<c@x>"));
            // Clear that probe's copy-back so the run below measures only
            // what the retirement allows.
            std::fs::remove_file(dir.join("v.part1.rar")).unwrap();
            std::fs::remove_file(dir.join("v.part2.rar")).unwrap();
        }

        // Now the decrypt publishes: the claim over movie.mkv is retired,
        // and only then do its bytes change.
        j.invalidate(&["movie.mkv".to_string()]).unwrap();
        let plaintext: Vec<u8> = (0..40_000u32).map(|i| (i % 97) as u8).collect();
        std::fs::write(dir.join("movie.mkv"), &plaintext).unwrap();
        drop(j);

        let (j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            !restored.ids.contains("<a@x>") && !restored.ids.contains("<b@x>"),
            "articles recorded into a mutated file were treated as restored"
        );
        assert!(
            restored.ids.contains("<c@x>"),
            "retiring one file must not cost every other file its resume"
        );
        // Nothing was copied out of the mutated file either.
        assert!(!dir.join("v.part1.rar").exists());

        // Retirement is positional: the refetched articles re-record and
        // are trusted again, so a second crash still resumes locally.
        j2.record_placed(0, "<a@x>", None, "v.part1.rar", 30_000, &[frag("movie.mkv", 0, 0, 10_000)]);
        drop(j2);
        let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(
            restored.ids.contains("<a@x>"),
            "a placement recorded AFTER the retirement must still count"
        );
        assert!(!restored.ids.contains("<b@x>"), "the stale one stays retired");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An older binary reading a journal that carries retirement lines
    /// must not mistake them for message ids (it refetches everything,
    /// which is safe in both directions - the journal's forward/backward
    /// compatibility contract).
    #[test]
    fn retirement_lines_are_never_read_as_message_ids() {
        let mut resume = ResumeState::default();
        parse_lines(
            ["X movie.mkv".to_string(), "<real@id>".to_string()].into_iter(),
            &mut resume,
        );
        assert_eq!(resume.completed.len(), 1);
        assert!(resume.completed.contains("<real@id>"));
    }

    #[test]
    fn identity_without_existing_file_refetches() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>id</nzb>";
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record_placed(
            0,
            "<a@x>",
            Some(("data.bin".to_string(), 1_000)),
            "",
            0,
            &[frag("data.bin", 0, 0, 1_000)],
        );
        drop(j);
        // data.bin was deleted between runs (user cleanup): the identity
        // fragment must NOT be trusted against a file we'd create fresh.
        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let restored = restore(&dir, &resume, None);
        assert!(restored.ids.is_empty());
        assert!(!dir.join("data.bin").exists(), "restore must not create it");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_and_torn_lines_are_ignored() {
        let dir = std::env::temp_dir().join(format!("nzbfast-journal-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nzb = b"<nzb>torn</nzb>";
        {
            let (j, _) = Journal::open(&dir, nzb).unwrap();
            j.record("<good@x>");
            drop(j);
        }
        // Simulate a torn tail + garbage placement lines.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join(".nzbfast.journal"))
                .unwrap();
            write!(f, "R 0 0:1:2:3 <no-ftable@x>\nS x y\nR 1 junk\nF 0\n<torn@").unwrap();
        }
        let (_j, resume) = Journal::open(&dir, nzb).unwrap();
        assert!(resume.completed.contains("<good@x>"));
        assert!(resume.slots.is_empty());
        // The torn bare line parses as a (harmless, never-matching) id.
        assert!(resume.completed.contains("<torn@"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

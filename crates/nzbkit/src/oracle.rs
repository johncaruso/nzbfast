//! M29 availability oracle v1: learn which BACKBONES still carry which
//! posts, keyed by (backbone, group family, age bucket), and predict a
//! release's completability before a byte is downloaded.
//!
//! Data sources (both free or near-free):
//! - every real download's per-article outcomes (a 222/223 is a labeled
//!   "backbone had it", a 430/423 a labeled "backbone lost it") - the
//!   pool feeds an [`OracleSink`] which is flushed to the ledger per job;
//! - an idle STAT sampler in the daemon probing indexed releases on
//!   spare connections (throttled; the daemon owns the schedule).
//!
//! Availability clusters by backbone, not provider brand, so even a
//! single user's traffic learns fast: one Omicron reseller's 430 pattern
//! predicts every Omicron reseller.

use crate::sync::MutexExt;
use std::collections::HashMap;
use std::sync::Mutex;

// The ledger persistence below is the module's only sqlite; everything
// else (buckets, backbone/family naming, the in-memory sink, Snapshot
// math) compiles in slim builds too - the core download path uses it.
#[cfg(feature = "indexer")]
use rusqlite::Connection;

/// Age buckets (days → bucket index). Availability changes with post age
/// (retention limits, takedown waves hit recent posts), so the ledger
/// never mixes a 2-day-old sample with a 2-year-old one.
/// 0: 0-1d, 1: 1-7d, 2: 7-30d, 3: 30-90d, 4: 90-365d, 5: 1-3y, 6: 3y+.
pub const N_BUCKETS: u8 = 7;

pub fn age_bucket(age_days: u32) -> u8 {
    match age_days {
        0..=1 => 0,
        2..=7 => 1,
        8..=30 => 2,
        31..=90 => 3,
        91..=365 => 4,
        366..=1095 => 5,
        _ => 6,
    }
}

/// Human label for a bucket (diagnostics / future UI tooltips).
pub fn bucket_label(b: u8) -> &'static str {
    match b {
        0 => "0-1d",
        1 => "1-7d",
        2 => "7-30d",
        3 => "30-90d",
        4 => "90-365d",
        5 => "1-3y",
        _ => "3y+",
    }
}

/// Known resellers of the major backbones. Keys are the normalized
/// second-level host label (after digit/subdomain stripping); values the
/// backbone the ledger clusters them under. Unlisted hosts key under
/// their own normalized label - still correct, just unclustered.
const BACKBONE_ALIASES: &[(&str, &str)] = &[
    // Omicron Media.
    ("usenetserver", "omicron"),
    ("newshosting", "omicron"),
    ("eweka", "omicron"),
    ("easynews", "omicron"),
    ("tweaknews", "omicron"),
    ("pureusenet", "omicron"),
    ("sunnyusenet", "omicron"),
    ("hitnews", "omicron"),
    // UsenetExpress.
    ("usenetexpress", "usenetexpress"),
    ("viper", "usenetexpress"),
    ("vipernews", "usenetexpress"),
    ("fastusenet", "usenetexpress"),
    ("usenetprime", "usenetexpress"),
    // Abavia.
    ("abavia", "abavia"),
    ("bulknews", "abavia"),
    ("usenetbucket", "abavia"),
    ("cheapnews", "abavia"),
    // Giganews (also powers Supernews).
    ("giganews", "giganews"),
    ("supernews", "giganews"),
    // Independents that are their own backbone (identity entries so a
    // rename here never orphans history).
    ("xsnews", "xsnews"),
    ("blocknews", "blocknews"),
    ("astraweb", "astraweb"),
];

/// Normalize a server host to its backbone key: take the registrable
/// label (skipping TLD-ish tails like "co.uk"), strip digits/dashes
/// (news2, ssl-eu), then apply the reseller alias map.
/// news.eweka.nl → eweka → omicron; news2.blocknews.net → blocknews.
pub fn backbone_of(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or(&host); // strip :port
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    // Walk from the end past TLD-ish labels (short, or common ccTLD
    // second levels like "co"/"com"); the first substantive label is the
    // brand. A bare hostname (tests, LAN) is its own label.
    const TLDISH: &[&str] = &["co", "com", "net", "org", "ac", "gov"];
    let mut base = *labels.last().unwrap_or(&"");
    for (i, l) in labels.iter().enumerate().rev() {
        let last = i + 1 == labels.len();
        if last && (l.len() <= 3 || TLDISH.contains(l)) {
            continue; // TLD
        }
        if !last && TLDISH.contains(l) {
            continue; // second-level TLD (co.uk)
        }
        base = l;
        break;
    }
    let stripped: String = base.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let key = if stripped.is_empty() {
        base.to_string()
    } else {
        stripped
    };
    for (alias, backbone) in BACKBONE_ALIASES {
        if key == *alias {
            return (*backbone).to_string();
        }
    }
    key
}

/// Collapse a newsgroup to its family: strip the "alt.binaries." (or
/// abbreviated "a.b.") prefix and keep the first remaining component -
/// takedown/retention behavior tracks the content family, not the exact
/// group. alt.binaries.hdtv.x264 → hdtv; alt.binaries.teevee → teevee.
pub fn group_family(grp: &str) -> String {
    let g = grp.trim().to_ascii_lowercase();
    let rest = g
        .strip_prefix("alt.binaries.")
        .or_else(|| g.strip_prefix("a.b."))
        .unwrap_or(&g);
    let fam = rest.split('.').next().unwrap_or("").trim();
    if fam.is_empty() {
        "misc".to_string()
    } else {
        fam.to_string()
    }
}

/// One aggregated ledger observation, ready to ingest: `host` is the raw
/// server host (mapped to a backbone at ingest), `bucket` an age-bucket
/// index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub host: String,
    pub family: String,
    pub bucket: u8,
    pub hits: u64,
    pub misses: u64,
}

/// In-memory accumulator the pool's workers feed per article outcome -
/// NEVER a per-article sqlite write. The job runner installs one per
/// download, the pool records into it lock-cheap, and the daemon drains
/// it into the ledger once per job.
#[derive(Default)]
pub struct OracleSink {
    /// Pool server order → host (set once at pool build; the pool only
    /// knows server indices).
    servers: Mutex<Vec<String>>,
    /// Group family of the job's release (one NZB ≈ one family).
    family: Mutex<String>,
    /// (server index, age bucket) → (hits, misses).
    counts: Mutex<HashMap<(usize, u8), (u64, u64)>>,
}

impl OracleSink {
    /// Install the job context: pool server hosts (pool order) and the
    /// release's group family.
    pub fn set_context(&self, hosts: Vec<String>, family: String) {
        *self.servers.lock_ok() = hosts;
        *self.family.lock_ok() = family;
    }

    /// Record one 222 body served by server `si` for an article
    /// `age_days` old (0 = fresh/unknown - bucketed as fresh; NZBs
    /// without dates are rare enough not to matter).
    pub fn hit(&self, si: usize, age_days: u32) {
        let mut c = self.counts.lock_ok();
        c.entry((si, age_bucket(age_days))).or_insert((0, 0)).0 += 1;
    }

    /// Record one 430/423 from server `si`.
    pub fn miss(&self, si: usize, age_days: u32) {
        let mut c = self.counts.lock_ok();
        c.entry((si, age_bucket(age_days))).or_insert((0, 0)).1 += 1;
    }

    /// Empty the accumulator into ingest-ready samples. Counts recorded
    /// for a server index the context never named are dropped (can't
    /// attribute them).
    pub fn drain(&self) -> Vec<Sample> {
        let servers = self.servers.lock_ok().clone();
        let family = self.family.lock_ok().clone();
        let counts = std::mem::take(&mut *self.counts.lock_ok());
        let mut out: Vec<Sample> = counts
            .into_iter()
            .filter_map(|((si, bucket), (hits, misses))| {
                let host = servers.get(si)?.clone();
                Some(Sample {
                    host,
                    family: family.clone(),
                    bucket,
                    hits,
                    misses,
                })
            })
            .collect();
        out.sort_by(|a, b| (&a.host, a.bucket).cmp(&(&b.host, b.bucket)));
        out
    }
}

/// Create the ledger table (idempotent; called from `Index::open`).
#[cfg(feature = "indexer")]
pub fn ensure_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS oracle(
            backbone TEXT NOT NULL,
            family TEXT NOT NULL,
            bucket INTEGER NOT NULL,
            hits INTEGER NOT NULL DEFAULT 0,
            misses INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(backbone, family, bucket));",
    )
}

/// Fold a batch of samples into the ledger (one transaction).
#[cfg(feature = "indexer")]
pub fn ingest(db: &Connection, samples: &[Sample], now: i64) -> rusqlite::Result<()> {
    if samples.is_empty() {
        return Ok(());
    }
    let tx = db.unchecked_transaction()?;
    {
        let mut up = tx.prepare_cached(
            "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(backbone, family, bucket) DO UPDATE SET
               hits = hits + excluded.hits,
               misses = misses + excluded.misses,
               updated_at = excluded.updated_at",
        )?;
        for s in samples {
            if s.hits == 0 && s.misses == 0 {
                continue;
            }
            up.execute(rusqlite::params![
                backbone_of(&s.host),
                s.family,
                s.bucket as i64,
                s.hits as i64,
                s.misses as i64,
                now
            ])?;
        }
    }
    tx.commit()
}

/// The whole ledger in memory - it is tiny by construction (backbones ×
/// families × 7), so verdict computation loads it once per request.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    /// (backbone, family, bucket) → (hits, misses).
    cells: HashMap<(String, String, u8), (u64, u64)>,
}

impl Snapshot {
    #[cfg(feature = "indexer")]
    pub fn load(db: &Connection) -> rusqlite::Result<Snapshot> {
        let mut stmt = db.prepare("SELECT backbone, family, bucket, hits, misses FROM oracle")?;
        let cells = stmt
            .query_map([], |r| {
                Ok((
                    (r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u8),
                    (r.get::<_, i64>(3)? as u64, r.get::<_, i64>(4)? as u64),
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Snapshot { cells })
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Test/seed helper.
    pub fn insert(&mut self, backbone: &str, family: &str, bucket: u8, hits: u64, misses: u64) {
        self.cells
            .insert((backbone.into(), family.into(), bucket), (hits, misses));
    }

    /// (hits, misses) evidence for one backbone × release: the exact
    /// (family, bucket) cell when it holds enough samples, else the
    /// backbone's whole-bucket aggregate across families (retention and
    /// takedown waves are mostly family-agnostic; the fallback keeps
    /// verdicts usable while family cells are thin).
    fn evidence(&self, backbone: &str, family: &str, bucket: u8) -> (u64, u64) {
        let exact = self
            .cells
            .get(&(backbone.to_string(), family.to_string(), bucket))
            .copied()
            .unwrap_or((0, 0));
        if exact.0 + exact.1 >= MIN_SAMPLES {
            return exact;
        }
        let mut agg = (0u64, 0u64);
        for ((b, _f, k), (h, m)) in &self.cells {
            if b == backbone && *k == bucket {
                agg.0 += h;
                agg.1 += m;
            }
        }
        agg
    }

    /// M29 3d takedown fingerprint: content families whose FRESH posts
    /// (≤7 days) are confidently unavailable on the user's backbones.
    ///
    /// Retention can't expire a week-old post, so "fresh AND gone" is the
    /// signature of an active takedown wave reaping a group - as opposed
    /// to the slow, age-driven loss that retention limits cause on old
    /// posts. The wall surfaces these as "this group is being reaped".
    ///
    /// Deliberately uses EXACT (backbone, family, fresh-bucket) cells,
    /// never the cross-family aggregate fallback: a single heavily-reaped
    /// family must not drag its neighbours' verdicts down. Evidence is
    /// summed across the enabled backbones - if fresh posts of a family
    /// are gone everywhere the user can reach, it is being reaped. Sorted
    /// most-reaped (by miss weight) first.
    pub fn reaped_families(&self, backbones: &[String]) -> Vec<Reaped> {
        if backbones.is_empty() {
            return Vec::new();
        }
        // Distinct families present in the ledger.
        let mut fams: Vec<&str> = self.cells.keys().map(|(_, f, _)| f.as_str()).collect();
        fams.sort_unstable();
        fams.dedup();
        let mut out: Vec<Reaped> = Vec::new();
        for fam in fams {
            // Fresh buckets only (0 = 0-1d, 1 = 1-7d).
            let mut best: Option<Reaped> = None;
            for b in [0u8, 1u8] {
                let (mut h, mut m) = (0u64, 0u64);
                for bb in backbones {
                    if let Some((hh, mm)) = self.cells.get(&(bb.clone(), fam.to_string(), b)) {
                        h += *hh;
                        m += *mm;
                    }
                }
                let n = h + m;
                if n < MIN_SAMPLES {
                    continue; // too thin to call a reap
                }
                let (_lo, hi) = wilson(h, n);
                if hi <= RED_HIGH {
                    // Confidently gone. Keep the bucket with the most
                    // misses (the strongest evidence of the wave).
                    let cand = Reaped {
                        family: fam.to_string(),
                        bucket: b,
                        hits: h,
                        misses: m,
                    };
                    if best
                        .as_ref()
                        .map(|r| cand.misses > r.misses)
                        .unwrap_or(true)
                    {
                        best = Some(cand);
                    }
                }
            }
            if let Some(r) = best {
                out.push(r);
            }
        }
        out.sort_by(|a, b| b.misses.cmp(&a.misses).then(a.family.cmp(&b.family)));
        out
    }

    /// M29 opt-in routing: is `backbone` confidently unable to serve
    /// `family` at `age_days`? True only when that ONE backbone's EXACT
    /// (backbone, family, bucket) cell is red with confidence (Wilson
    /// upper ≤ [`RED_HIGH`], ≥ [`MIN_SAMPLES`] samples).
    ///
    /// Deliberately NOT the cross-family aggregate fallback `verdict` may
    /// use: routing must never skip a server for a family it might still
    /// carry just because a *different* family is being reaped on that
    /// backbone. A blind spot (thin exact cell) is never "gone" - it is
    /// kept. Powers the daemon's `oracle_route` short-circuit of
    /// known-doomed primary attempts.
    pub fn backbone_gone(&self, backbone: &str, family: &str, age_days: u32) -> bool {
        let bucket = age_bucket(age_days);
        let fam = {
            let f = family.trim();
            if f.is_empty() { "misc" } else { f }
        };
        let (h, m) = self
            .cells
            .get(&(backbone.to_string(), fam.to_string(), bucket))
            .copied()
            .unwrap_or((0, 0));
        let n = h + m;
        if n < MIN_SAMPLES {
            return false; // blind spot - never skip on no evidence
        }
        let (_lo, hi) = wilson(h, n);
        hi <= RED_HIGH
    }

    /// Soft scheduling signal (A8 gap-fill): the measured hit fraction
    /// of this EXACT cell when it holds enough samples. None = a blind
    /// spot - callers must treat it as unknown, never as gone: the
    /// ledger measures BODY availability (STAT), while indexing needs
    /// headers, so this may only ever RANK candidates, not skip them.
    pub fn carry_rate(&self, backbone: &str, family: &str, bucket: u8) -> Option<f64> {
        let (h, m) = self
            .cells
            .get(&(backbone.to_string(), family.to_string(), bucket))
            .copied()
            .unwrap_or((0, 0));
        let n = h + m;
        if n < MIN_SAMPLES {
            return None;
        }
        Some(h as f64 / n as f64)
    }

    /// Predicted verdict for a release in `family`, `age_days` old, given
    /// the user's enabled backbones. None = ledger too thin to say.
    pub fn verdict(&self, backbones: &[String], family: &str, age_days: u32) -> Option<Verdict> {
        if backbones.is_empty() {
            return None;
        }
        let bucket = age_bucket(age_days);
        let fam = {
            let f = family.trim();
            if f.is_empty() { "misc" } else { f }
        };
        let mut informed = 0usize;
        let mut best_low = 0.0f64;
        let mut best_high = 0.0f64;
        for b in backbones {
            let (h, m) = self.evidence(b, fam, bucket);
            let n = h + m;
            if n < MIN_SAMPLES {
                continue; // this backbone is a blind spot
            }
            informed += 1;
            let (low, high) = wilson(h, n);
            best_low = best_low.max(low);
            best_high = best_high.max(high);
        }
        if informed == 0 {
            return None;
        }
        // Green: some enabled backbone is confidently near-complete.
        if best_low >= GREEN_LOW {
            return Some(Verdict::Ok);
        }
        // Red: every enabled backbone is measured, and even the best is
        // confidently poor. Any blind spot demotes to amber, never red -
        // an untested server might still carry the post.
        if informed == backbones.len() && best_high <= RED_HIGH {
            return Some(Verdict::Gone);
        }
        Some(Verdict::Maybe)
    }
}

/// Minimum samples in a cell before it counts as evidence.
const MIN_SAMPLES: u64 = 12;
/// Green requires the Wilson 95% lower bound of the best backbone's
/// hit-rate at or above this (the M29 gate wants ≥95% green precision).
const GREEN_LOW: f64 = 0.95;
/// Red requires the Wilson upper bound of the BEST backbone at or below
/// this - confidently gone everywhere the user can reach.
const RED_HIGH: f64 = 0.60;

/// Wilson 95% score interval for `hits` successes in `n` trials.
fn wilson(hits: u64, n: u64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    const Z: f64 = 1.96;
    let n_f = n as f64;
    let p = hits as f64 / n_f;
    let z2 = Z * Z;
    let denom = 1.0 + z2 / n_f;
    let center = p + z2 / (2.0 * n_f);
    let spread = Z * (p * (1.0 - p) / n_f + z2 / (4.0 * n_f * n_f)).sqrt();
    (
        ((center - spread) / denom).max(0.0),
        ((center + spread) / denom).min(1.0),
    )
}

/// M29 3d: one content family caught in a takedown wave (fresh posts
/// confidently gone). `bucket` is the fresh age-bucket the reap was
/// strongest in; `hits`/`misses` are the summed evidence there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaped {
    pub family: String,
    pub bucket: u8,
    pub hits: u64,
    pub misses: u64,
}

/// Wall verdict: predicted "will this complete on your providers".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Green: predicted complete on ≥1 enabled backbone, high confidence.
    Ok,
    /// Amber: mixed/thin evidence.
    Maybe,
    /// Red: confidently unavailable on every enabled backbone.
    Gone,
}

impl Verdict {
    /// API string ("ok"/"maybe"/"gone") - the wall's JSON vocabulary.
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Maybe => "maybe",
            Verdict::Gone => "gone",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backbone_normalization() {
        // Reseller aliases cluster under the backbone.
        assert_eq!(backbone_of("news.eweka.nl"), "omicron");
        assert_eq!(backbone_of("news.usenetserver.com"), "omicron");
        assert_eq!(backbone_of("news2.newshosting.com"), "omicron");
        assert_eq!(backbone_of("secure.easynews.com"), "omicron");
        assert_eq!(backbone_of("usenetexpress.com"), "usenetexpress");
        assert_eq!(backbone_of("news.fastusenet.org"), "usenetexpress");
        assert_eq!(backbone_of("reader.abavia.com"), "abavia");
        assert_eq!(backbone_of("news.giganews.com"), "giganews");
        assert_eq!(backbone_of("news.supernews.com"), "giganews");
        // Digit/dash stripping on the brand label.
        assert_eq!(backbone_of("news2.blocknews.net"), "blocknews");
        assert_eq!(backbone_of("ssl-eu.astraweb.com"), "astraweb");
        // Unknown host keys under its own normalized label.
        assert_eq!(backbone_of("nntp.futureprovider.io"), "futureprovider");
        // Port and case are irrelevant; two-part TLDs resolve the brand.
        assert_eq!(backbone_of("News.Eweka.NL:563"), "omicron");
        assert_eq!(backbone_of("news.provider.co.uk"), "provider");
        // Bare hostname (mock servers, LAN) is its own key.
        assert_eq!(backbone_of("localhost"), "localhost");
        // IPs degrade to a stable (if opaque) key - mock/LAN only.
        assert_eq!(backbone_of("127.0.0.1"), "0");
    }

    #[test]
    fn family_normalization() {
        assert_eq!(group_family("alt.binaries.teevee"), "teevee");
        assert_eq!(group_family("alt.binaries.hdtv.x264"), "hdtv");
        assert_eq!(group_family("a.b.moovee"), "moovee");
        assert_eq!(group_family("alt.binaries.movies.divx"), "movies");
        assert_eq!(group_family("free.pt"), "free");
        assert_eq!(group_family(""), "misc");
        assert_eq!(group_family("ALT.BINARIES.TEEVEE"), "teevee");
    }

    #[test]
    fn bucket_boundaries() {
        assert_eq!(age_bucket(0), 0);
        assert_eq!(age_bucket(1), 0);
        assert_eq!(age_bucket(2), 1);
        assert_eq!(age_bucket(7), 1);
        assert_eq!(age_bucket(8), 2);
        assert_eq!(age_bucket(30), 2);
        assert_eq!(age_bucket(31), 3);
        assert_eq!(age_bucket(90), 3);
        assert_eq!(age_bucket(91), 4);
        assert_eq!(age_bucket(365), 4);
        assert_eq!(age_bucket(366), 5);
        assert_eq!(age_bucket(1095), 5);
        assert_eq!(age_bucket(1096), 6);
        assert_eq!(age_bucket(u32::MAX), 6);
        for b in 0..N_BUCKETS {
            assert!(!bucket_label(b).is_empty());
        }
    }

    #[test]
    fn sink_accumulates_and_drains() {
        let sink = OracleSink::default();
        sink.set_context(
            vec!["news.eweka.nl".into(), "news.blocknews.net".into()],
            "teevee".into(),
        );
        sink.hit(0, 3); // eweka, bucket 1
        sink.hit(0, 3);
        sink.miss(0, 3);
        sink.miss(1, 400); // blocknews, bucket 5
        sink.hit(9, 3); // unknown server index → dropped
        let mut s = sink.drain();
        s.sort_by(|a, b| a.host.cmp(&b.host));
        assert_eq!(
            s,
            vec![
                Sample {
                    host: "news.blocknews.net".into(),
                    family: "teevee".into(),
                    bucket: 5,
                    hits: 0,
                    misses: 1
                },
                Sample {
                    host: "news.eweka.nl".into(),
                    family: "teevee".into(),
                    bucket: 1,
                    hits: 2,
                    misses: 1
                },
            ]
        );
        // Drain empties.
        assert!(sink.drain().is_empty());
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn ledger_roundtrip_merges_backbones() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        let s = |host: &str, hits, misses| Sample {
            host: host.into(),
            family: "teevee".into(),
            bucket: 1,
            hits,
            misses,
        };
        ingest(&db, &[s("news.eweka.nl", 10, 2)], 100).unwrap();
        // A different Omicron reseller lands in the SAME cell.
        ingest(&db, &[s("news.usenetserver.com", 5, 1)], 200).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(
            snap.cells.get(&("omicron".into(), "teevee".into(), 1)),
            Some(&(15, 3))
        );
        let at: i64 = db
            .query_row("SELECT updated_at FROM oracle", [], |r| r.get(0))
            .unwrap();
        assert_eq!(at, 200);
    }

    #[test]
    fn verdict_math() {
        let bbs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut snap = Snapshot::default();
        // Thin ledger → no verdict.
        assert_eq!(snap.verdict(&bbs(&["omicron"]), "teevee", 3), None);
        snap.insert("omicron", "teevee", 1, 5, 0); // < MIN_SAMPLES
        assert_eq!(snap.verdict(&bbs(&["omicron"]), "teevee", 3), None);
        // Confident green: 200/200 → Wilson low ≈ 0.981.
        snap.insert("omicron", "teevee", 1, 200, 0);
        assert_eq!(
            snap.verdict(&bbs(&["omicron"]), "teevee", 3),
            Some(Verdict::Ok)
        );
        // Mixed → amber.
        snap.insert("omicron", "teevee", 2, 60, 40);
        assert_eq!(
            snap.verdict(&bbs(&["omicron"]), "teevee", 20),
            Some(Verdict::Maybe)
        );
        // Confident red on ALL enabled backbones.
        snap.insert("omicron", "teevee", 6, 2, 98);
        assert_eq!(
            snap.verdict(&bbs(&["omicron"]), "teevee", 2000),
            Some(Verdict::Gone)
        );
        // A blind-spot backbone demotes red to amber (never red).
        assert_eq!(
            snap.verdict(&bbs(&["omicron", "abavia"]), "teevee", 2000),
            Some(Verdict::Maybe)
        );
        // But a blind spot does NOT demote green.
        assert_eq!(
            snap.verdict(&bbs(&["omicron", "abavia"]), "teevee", 3),
            Some(Verdict::Ok)
        );
        // No backbones configured → no verdict.
        assert_eq!(snap.verdict(&[], "teevee", 3), None);
    }

    #[test]
    fn verdict_family_fallback() {
        let mut snap = Snapshot::default();
        // Nothing for "moovee" specifically, but the backbone's bucket
        // aggregate (via another family) is rich - fallback applies.
        snap.insert("omicron", "teevee", 1, 300, 0);
        assert_eq!(
            snap.verdict(&["omicron".to_string()], "moovee", 3),
            Some(Verdict::Ok)
        );
        // An exact family cell with enough samples wins over aggregate.
        snap.insert("omicron", "warez", 1, 3, 30);
        assert_eq!(
            snap.verdict(&["omicron".to_string()], "warez", 3),
            Some(Verdict::Gone)
        );
    }

    #[test]
    fn takedown_fingerprint() {
        let bbs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut snap = Snapshot::default();
        // "teevee" fresh posts (bucket 1) confidently gone → a reap.
        snap.insert("omicron", "teevee", 1, 3, 97);
        // "moovee" fresh posts healthy → not reaped.
        snap.insert("omicron", "moovee", 1, 200, 0);
        // "warez" is only gone in an OLD bucket (5 = 1-3y) → that's
        // retention expiry, NOT a takedown; must not be flagged.
        snap.insert("omicron", "warez", 5, 2, 98);
        // "xxx" fresh misses but too few samples → not enough to call.
        snap.insert("omicron", "xxx", 0, 1, 5);

        let reaped = snap.reaped_families(&bbs(&["omicron"]));
        let fams: Vec<&str> = reaped.iter().map(|r| r.family.as_str()).collect();
        assert_eq!(fams, vec!["teevee"], "{reaped:?}");
        assert_eq!(reaped[0].bucket, 1);
        assert_eq!(reaped[0].misses, 97);

        // A blind spot backbone doesn't manufacture reaps, and an
        // unreachable backbone's evidence isn't summed in.
        assert!(snap.reaped_families(&bbs(&["abavia"])).is_empty());
        // No backbones → nothing.
        assert!(snap.reaped_families(&[]).is_empty());

        // Cross-family fallback must NOT leak: a thin fresh family in a
        // bucket dominated by another family's reap stays unflagged.
        snap.insert("omicron", "thinfam", 1, 0, 2); // < MIN_SAMPLES
        let reaped = snap.reaped_families(&bbs(&["omicron"]));
        assert!(
            reaped.iter().all(|r| r.family != "thinfam"),
            "aggregate fallback must not flag a thin family: {reaped:?}"
        );
    }

    #[test]
    fn backbone_gone_is_exact_and_conservative() {
        let mut snap = Snapshot::default();
        // omicron/teevee/bucket1 confidently gone.
        snap.insert("omicron", "teevee", 1, 3, 97);
        assert!(snap.backbone_gone("omicron", "teevee", 3));
        // A different backbone with no data for this family: NOT gone.
        assert!(!snap.backbone_gone("abavia", "teevee", 3));
        // A different family on the same backbone/bucket: NOT gone (no
        // aggregate-fallback leak - routing must not skip on it).
        assert!(!snap.backbone_gone("omicron", "moovee", 3));
        // A different age bucket: NOT gone.
        assert!(!snap.backbone_gone("omicron", "teevee", 2000));
        // Thin evidence never counts as gone.
        snap.insert("omicron", "warez", 0, 1, 5);
        assert!(!snap.backbone_gone("omicron", "warez", 0));
        // A healthy cell is not gone.
        snap.insert("omicron", "moovee", 1, 200, 0);
        assert!(!snap.backbone_gone("omicron", "moovee", 3));
    }

    /// carry_rate is the A8 ranking signal: exact-cell only, None on a
    /// blind spot (it must rank, never skip), the plain hit fraction
    /// once a cell holds enough samples.
    #[test]
    fn carry_rate_is_exact_cell_only() {
        let mut snap = Snapshot::default();
        assert!(snap.is_empty());
        assert_eq!(snap.carry_rate("omicron", "teevee", 1), None);
        snap.insert("omicron", "teevee", 1, 3, 1); // < MIN_SAMPLES
        assert!(!snap.is_empty());
        assert_eq!(snap.carry_rate("omicron", "teevee", 1), None);
        snap.insert("omicron", "teevee", 1, 75, 25);
        assert_eq!(snap.carry_rate("omicron", "teevee", 1), Some(0.75));
        // No cross-family or cross-bucket leakage.
        assert_eq!(snap.carry_rate("omicron", "moovee", 1), None);
        assert_eq!(snap.carry_rate("omicron", "teevee", 2), None);
        assert_eq!(snap.carry_rate("abavia", "teevee", 1), None);
    }

    /// The wall's JSON vocabulary is a stable three-word contract.
    #[test]
    fn verdict_api_strings() {
        assert_eq!(Verdict::Ok.as_str(), "ok");
        assert_eq!(Verdict::Maybe.as_str(), "maybe");
        assert_eq!(Verdict::Gone.as_str(), "gone");
    }

    /// An empty family string normalizes to "misc" on both verdict
    /// paths, so blank newsgroup metadata still keys a real cell.
    #[test]
    fn blank_family_reads_as_misc() {
        let mut snap = Snapshot::default();
        snap.insert("omicron", "misc", 1, 200, 0);
        assert_eq!(
            snap.verdict(&["omicron".to_string()], "  ", 3),
            Some(Verdict::Ok)
        );
        snap.insert("omicron", "misc", 0, 2, 98);
        assert!(snap.backbone_gone("omicron", "", 0));
    }

    #[test]
    fn wilson_sanity() {
        let (lo, hi) = wilson(0, 0);
        assert_eq!((lo, hi), (0.0, 1.0));
        let (lo, hi) = wilson(100, 100);
        assert!(lo > 0.95 && hi > 0.999, "lo={lo} hi={hi}");
        let (lo, hi) = wilson(0, 100);
        assert!(lo == 0.0 && hi < 0.05, "lo={lo} hi={hi}");
        let (lo, hi) = wilson(50, 100);
        assert!(lo > 0.40 && lo < 0.5 && hi > 0.5 && hi < 0.60);
    }
}

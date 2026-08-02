//! TODO §77: the advisory pre-flight score - the failure diagnostics run
//! backwards.
//!
//! [`crate::diag`] answers "why did this job fail?" from a post-mortem
//! census of a run that already spent the bandwidth. Everything it reads
//! - which servers said 430, how many segments never arrived, how old the
//! post is - can be sampled for a few hundred bytes BEFORE the download
//! starts, and that is all this module is: STAT a handful of articles
//! across every configured server at enqueue, and put the answer on the
//! queue row so "posted four days ago, on none of your three servers"
//! arrives before 60 GB does rather than at 97%.
//!
//! **It is advisory and it must stay that way.** A 430 from every server
//! is not proof a post is dead: a freshly posted article 430s everywhere
//! until it propagates, and at that moment it is indistinguishable from
//! one that was taken down (memory `nzbfast-retry-propagation-trap`, and
//! [`crate::diag::GONE_MIN_AGE_DAYS`], which exists for exactly this).
//! So nothing here may fail a job, block a job, or remove a job from the
//! queue. The strongest thing a red verdict is allowed to do is SINK the
//! job in start order behind healthier ones, and only when the operator
//! has turned that on.
//!
//! The other half of the same rule: a sample of eight articles out of
//! nine thousand cannot measure how complete a post is. It can only ever
//! say "of the ones I asked about, this many were not there", so every
//! surface renders the sampled count beside the verdict and none of them
//! phrases it as a percentage.

use crate::diag::GONE_MIN_AGE_DAYS;

/// Articles sampled per job. Small on purpose: the whole point is that
/// this costs a round trip, not a download, and the marginal article
/// buys very little once the first few have answered - a post that is
/// gone is gone at every offset, and one that is short in one place is
/// exactly what a sample cannot promise to find.
pub(crate) const SAMPLE_K: usize = 8;
/// Sampled on a big job, where the bandwidth a wrong answer costs is
/// worth another handful of STATs.
pub(crate) const SAMPLE_K_LARGE: usize = 16;
/// Jobs at or above this take [`SAMPLE_K_LARGE`].
pub(crate) const LARGE_JOB_BYTES: u64 = 20_000_000_000;

/// Probes one job may ever run: the one at enqueue, and one re-check if
/// it is still sitting in the queue an hour later (a post that was
/// mid-propagation at add time has usually finished by then, and an
/// amber that stays amber is worth knowing about). Bounded so a job
/// parked in a paused queue for a week does not probe forever.
pub(crate) const MAX_PROBES: u32 = 2;
/// How long a queued job must sit before the second probe.
pub(crate) const RECHECK_AFTER_SECS: i64 = 3600;

/// Availability of one article on one server, as the sampler saw it.
/// Mirrors [`nzbkit::preflight::Avail`] - the STAT normalizer there is
/// the one both the `check` command and this share, so provider quirks
/// on "missing" versus "delayed" are decided in exactly one place.
pub(crate) use nzbkit::preflight::Avail;

/// Where a job's post-health verdict falls. Three buckets and no score
/// out of ten: the evidence is a handful of STATs, and any finer grain
/// would be inventing precision the sample does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bucket {
    /// Every sampled article is on at least one server that answered.
    Green,
    /// Sampled articles are missing everywhere, but the post is younger
    /// than propagation explains. Optimistic on purpose.
    Amber,
    /// Sampled articles are missing everywhere and the post is old
    /// enough that propagation is no longer the explanation.
    Red,
}

impl Bucket {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Bucket::Green => "green",
            Bucket::Amber => "amber",
            Bucket::Red => "red",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Bucket> {
        match s {
            "green" => Some(Bucket::Green),
            "amber" => Some(Bucket::Amber),
            "red" => Some(Bucket::Red),
            _ => None,
        }
    }
}

/// What one server said about the sampled articles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerAnswer {
    pub host: String,
    /// `matrix[i]` for sampled article `i`, in sample order.
    pub cells: Vec<Avail>,
}

impl ServerAnswer {
    /// Did this server say anything definite at all? A host that refused
    /// the login, or that we never reached, leaves every cell `Unknown`
    /// and must be dropped from the verdict rather than counted as a
    /// vote either way - see [`score`].
    pub(crate) fn answered(&self) -> bool {
        self.cells.iter().any(|c| *c != Avail::Unknown)
    }

    /// (have, missing) over the cells this server actually answered.
    pub(crate) fn counts(&self) -> (u32, u32) {
        let have = self.cells.iter().filter(|c| **c == Avail::Have).count() as u32;
        let missing = self.cells.iter().filter(|c| **c == Avail::Missing).count() as u32;
        (have, missing)
    }
}

/// A job's pre-flight verdict, as carried on the Job record and rendered
/// on the queue row.
///
/// Every field the UI shows is here in NUMBERS, and `reason` is English
/// wire text: the dashboard composes its own sentence in the user's
/// language from the counts (the same division of labour as
/// [`crate::serve::Job::unpack_blocked_by`]), and `reason` is what the
/// API, the log line and the failure summary use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PostHealth {
    pub bucket: Bucket,
    pub reason: String,
    /// Articles STATed per server.
    pub sampled: u32,
    /// Sampled articles on at least one server that answered.
    pub present: u32,
    /// Sampled articles on NONE of the servers that answered. The number
    /// the buckets turn on, and the one that is never a completeness
    /// percentage - `absent` of `sampled`, always both.
    pub absent: u32,
    /// Servers that gave a definite answer about at least one article.
    pub answered: u32,
    /// Servers the probe tried.
    pub servers: u32,
    /// Per server that answered: (host, present, missing) over the
    /// sample. The census, inverted and run before the download instead
    /// of after it - and the only part of the verdict that separates
    /// "nobody has this" from "the cheap block account does not".
    ///
    /// Numbers, not a sentence, so the dashboard can render it in the
    /// user's own language beside the per-server contribution table it
    /// already draws for the active download.
    pub per_server: Vec<(String, u32, u32)>,
    /// Age in days of the youngest article in the post; 0 for an NZB
    /// with no usable dates, which reads as fresh (unknown is not old).
    pub age_days: u32,
    /// Unix seconds the probe ran.
    pub checked_at: i64,
    /// How many probes this job has had. See [`MAX_PROBES`].
    pub probes: u32,
    /// The user has reordered or re-prioritized this job since the
    /// probe, so the optional auto-defer no longer sinks it.
    ///
    /// The VERDICT survives - it is evidence about the post and the row
    /// keeps saying so - and only the scheduling effect is dropped. Same
    /// rule as the slow-job watchdog, whose `deferred` flag a manual
    /// reorder clears: once the user has asserted an order, a guess made
    /// from eight STATs does not get to argue with it.
    pub waived: bool,
}

impl PostHealth {
    /// Should the optional auto-defer sink this job? Red only: an amber
    /// is a post that is probably still landing, and sinking it is the
    /// one thing that would make the wait longer.
    pub(crate) fn sinks(&self) -> bool {
        self.bucket == Bucket::Red && !self.waived
    }
}

/// Score a completed sample. `None` when nothing was learned - no server
/// answered, or there was nothing to sample - because a badge with no
/// evidence behind it is worse than no badge.
///
/// `age_days` is the age of the YOUNGEST article in the post, the same
/// figure [`crate::diag::LossCauses::post_age_days`] carries and for the
/// same reason: a fill or a repost tops an old NZB up with new articles,
/// and it is the newest posting that decides whether propagation is
/// still a live explanation.
pub(crate) fn score(
    answers: &[ServerAnswer],
    age_days: u32,
    at: i64,
    probes: u32,
) -> Option<PostHealth> {
    let servers = answers.len() as u32;
    // A host that never answered is not a vote. Counting its silence as
    // "has the article" (which is what a plain all-servers union does,
    // since Unknown is deliberately not Missing) means one server with a
    // wrong password paints every post in the queue green; counting it
    // as "missing" would paint them all red. Neither is evidence, so it
    // leaves the room, and `answered` vs `servers` says how many did.
    let voting: Vec<&ServerAnswer> = answers.iter().filter(|a| a.answered()).collect();
    let sampled = voting.first().map_or(0, |a| a.cells.len());
    if voting.is_empty() || sampled == 0 {
        return None;
    }
    // Absent = no server that answered had it. An UNKNOWN cell inside an
    // otherwise-answering server still blocks the verdict for that
    // article: a session that died halfway through the pipeline knows
    // nothing about the ids it never got to, and pre-flight must never
    // manufacture a miss.
    //
    // `get`, not `[i]`: the prober hands every server a row of the same
    // length, but a scoring function that panics on a ragged matrix is
    // one refactor away from taking the daemon down, and a row too short
    // to answer about article `i` is exactly the "did not say" case the
    // line above already handles.
    let absent = (0..sampled)
        .filter(|&i| {
            voting
                .iter()
                .all(|a| a.cells.get(i) == Some(&Avail::Missing))
        })
        .count() as u32;
    let present = sampled as u32 - absent;
    let answered = voting.len() as u32;
    let sampled = sampled as u32;
    // The whole guard, in one line: missing everywhere is only evidence
    // about the POST once the post is older than propagation. Below the
    // threshold - and for a dateless NZB, which reads as age 0 - the
    // optimistic reading stands.
    let bucket = if absent == 0 {
        Bucket::Green
    } else if age_days < GONE_MIN_AGE_DAYS {
        Bucket::Amber
    } else {
        Bucket::Red
    };
    let mut reason = match bucket {
        Bucket::Green => format!(
            "pre-flight: all {sampled} sampled article(s) are on at least one of \
             {answered} server(s)"
        ),
        Bucket::Amber => format!(
            "pre-flight: {absent} of {sampled} sampled article(s) are on none of the \
             {answered} server(s) that answered, but the post is only {age_days} day(s) \
             old - a post still propagating looks exactly like this, so this is a \
             warning and nothing more"
        ),
        Bucket::Red => format!(
            "pre-flight: {absent} of {sampled} sampled article(s) are on none of the \
             {answered} server(s) that answered, and at {age_days} day(s) old the post \
             is past the point where propagation explains it"
        ),
    };
    // The census, inverted: who has what. "Missing everywhere" and
    // "missing on the one server that happens to be cheapest" are very
    // different situations and the counts alone cannot tell them apart -
    // this is the same reasoning that puts the per-server table in the
    // failure diagnostics, run before the download instead of after it.
    if bucket != Bucket::Green {
        let per: Vec<String> = voting
            .iter()
            .map(|a| {
                let (have, _) = a.counts();
                format!("{} ({have}/{sampled} present)", a.host)
            })
            .collect();
        reason.push_str(&format!("; per server: {}", per.join(", ")));
    }
    // Both halves of the honesty clause. The sample size, because
    // "2 of 8" is not "25% of the release is missing" and the row must
    // never read like it is; and any server that stayed silent, because
    // its copy was not consulted and the verdict is thinner than the
    // server count suggests.
    if servers > answered {
        reason.push_str(&format!(
            "; {} of {servers} server(s) did not answer and were not counted",
            servers - answered
        ));
    }
    Some(PostHealth {
        bucket,
        reason,
        per_server: voting
            .iter()
            .map(|a| {
                let (have, missing) = a.counts();
                (a.host.clone(), have, missing)
            })
            .collect(),
        sampled,
        present,
        absent,
        answered,
        servers,
        age_days,
        checked_at: at,
        probes,
        waived: false,
    })
}

/// How many articles to sample for a job of `total_bytes`.
pub(crate) fn sample_size(total_bytes: u64) -> usize {
    if total_bytes >= LARGE_JOB_BYTES {
        SAMPLE_K_LARGE
    } else {
        SAMPLE_K
    }
}

/// The clause a failed job's summary gets when this job was sampled at
/// enqueue: was it already short before a byte was spent, or did it go
/// missing during the download?
///
/// That distinction is not otherwise recoverable after the fact, and it
/// is the one the user (and the indexer failure report) actually wants -
/// "the indexer handed me a dead post" and "the post rotted out from
/// under me mid-download" call for different things. `None` when the
/// sample says nothing useful about it.
pub(crate) fn failure_clause(h: &PostHealth) -> Option<String> {
    if h.absent > 0 {
        Some(format!(
            "; a pre-flight sample when this job was added already found {} of {} sampled \
             article(s) on none of the {} server(s) that answered, so the post was \
             short before the download started",
            h.absent, h.sampled, h.answered
        ))
    } else {
        Some(format!(
            "; a pre-flight sample when this job was added found all {} sampled \
             article(s) present, so whatever went missing did so after that",
            h.sampled
        ))
    }
}

pub(crate) fn health_json(h: &PostHealth) -> serde_json::Value {
    serde_json::json!({
        "bucket": h.bucket.as_str(),
        "reason": h.reason,
        "per_server": h.per_server
            .iter()
            .map(|(host, have, missing)| serde_json::json!({
                "host": host, "have": have, "missing": missing,
            }))
            .collect::<Vec<_>>(),
        "sampled": h.sampled,
        "present": h.present,
        "absent": h.absent,
        "answered": h.answered,
        "servers": h.servers,
        "age_days": h.age_days,
        "checked_at": h.checked_at,
        "probes": h.probes,
        "waived": h.waived,
    })
}

pub(crate) fn health_from_json(v: &serde_json::Value) -> Option<PostHealth> {
    let u = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0) as u32;
    Some(PostHealth {
        bucket: Bucket::from_str(v.get("bucket").and_then(serde_json::Value::as_str)?)?,
        reason: v
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        per_server: v
            .get("per_server")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some((
                            e.get("host")?.as_str()?.to_string(),
                            e.get("have")?.as_u64()? as u32,
                            e.get("missing")?.as_u64()? as u32,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        sampled: u("sampled"),
        present: u("present"),
        absent: u("absent"),
        answered: u("answered"),
        servers: u("servers"),
        age_days: u("age_days"),
        checked_at: v
            .get("checked_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        probes: u("probes").max(1),
        waived: v
            .get("waived")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(host: &str, cells: &[Avail]) -> ServerAnswer {
        ServerAnswer {
            host: host.into(),
            cells: cells.to_vec(),
        }
    }

    const H: Avail = Avail::Have;
    const M: Avail = Avail::Missing;
    const U: Avail = Avail::Unknown;

    #[test]
    fn everything_present_is_green() {
        let s = score(
            &[answer("a", &[H, H, H]), answer("b", &[H, M, H])],
            400,
            0,
            1,
        )
        .unwrap();
        assert_eq!(s.bucket, Bucket::Green);
        assert_eq!((s.present, s.absent, s.sampled), (3, 0, 3));
        // One server missing an article it simply does not carry says
        // nothing: the other one has it, so the download completes.
        assert_eq!(s.answered, 2);
    }

    /// The binding constraint, as a test. A post that 430s on EVERY
    /// server is amber - not red - while it is young enough for
    /// propagation to be the explanation. This is the trap that has been
    /// walked into twice (memory `nzbfast-retry-propagation-trap`).
    #[test]
    fn a_young_post_missing_everywhere_is_amber_not_red() {
        for age in 0..GONE_MIN_AGE_DAYS {
            let s = score(&[answer("a", &[M, M]), answer("b", &[M, M])], age, 0, 1).unwrap();
            assert_eq!(s.bucket, Bucket::Amber, "age {age}");
            assert!(!s.sinks(), "an amber must never sink the job");
        }
        let old = score(
            &[answer("a", &[M, M]), answer("b", &[M, M])],
            GONE_MIN_AGE_DAYS,
            0,
            1,
        )
        .unwrap();
        assert_eq!(old.bucket, Bucket::Red);
        assert!(old.sinks());
    }

    /// A dateless NZB reads as age 0, and age 0 is FRESH. Same rule as
    /// `nzb_age_days` and the "gone" verdict: unknown is not old.
    #[test]
    fn a_dateless_post_is_never_red() {
        let s = score(&[answer("a", &[M, M, M])], 0, 0, 1).unwrap();
        assert_eq!(s.bucket, Bucket::Amber);
    }

    /// A server that never answered is not a vote in either direction.
    /// Without this, one host with a bad password makes every post in
    /// the queue read green (its Unknown blocks every union), which is
    /// exactly the reassurance the feature must not give.
    #[test]
    fn a_silent_server_is_dropped_not_counted() {
        let s = score(
            &[answer("dead", &[U, U, U]), answer("live", &[M, M, M])],
            30,
            0,
            1,
        )
        .unwrap();
        assert_eq!(s.bucket, Bucket::Red);
        assert_eq!((s.answered, s.servers), (1, 2));
        assert!(s.reason.contains("1 of 2 server(s) did not answer"));
    }

    /// An Unknown cell inside a server that DID answer still blocks that
    /// article: a session that died mid-pipeline knows nothing about the
    /// ids it never reached, and a miss must never be manufactured.
    #[test]
    fn a_half_answered_server_blocks_only_its_own_gaps() {
        let s = score(
            &[answer("a", &[M, U, M]), answer("b", &[M, M, U])],
            30,
            0,
            1,
        )
        .unwrap();
        // Article 0 is missing on both; 1 and 2 each have an Unknown.
        assert_eq!((s.absent, s.present), (1, 2));
        assert_eq!(s.bucket, Bucket::Red);
    }

    #[test]
    fn no_evidence_scores_nothing() {
        assert!(score(&[], 30, 0, 1).is_none());
        assert!(score(&[answer("a", &[U, U])], 30, 0, 1).is_none());
        assert!(score(&[answer("a", &[])], 30, 0, 1).is_none());
    }

    /// The sampled count rides every verdict, and none of them phrases
    /// itself as a share of the release.
    #[test]
    fn the_reason_always_discloses_the_sample() {
        for (cells, age) in [(vec![H, H], 30u32), (vec![M, H], 1), (vec![M, M], 30)] {
            let s = score(&[answer("a", &cells)], age, 0, 1).unwrap();
            assert!(s.reason.contains("sampled article(s)"), "{}", s.reason);
            assert!(!s.reason.contains('%'), "{}", s.reason);
        }
    }

    #[test]
    fn large_jobs_sample_wider() {
        assert_eq!(sample_size(0), SAMPLE_K);
        assert_eq!(sample_size(LARGE_JOB_BYTES - 1), SAMPLE_K);
        assert_eq!(sample_size(LARGE_JOB_BYTES), SAMPLE_K_LARGE);
    }

    #[test]
    fn json_round_trips() {
        let s = score(
            &[answer("a", &[M, H]), answer("b", &[M, H])],
            9,
            1_700_000_000,
            2,
        )
        .unwrap();
        assert_eq!(health_from_json(&health_json(&s)), Some(s));
    }

    /// A record written by an older build (or hand-edited) must not
    /// resurrect as a bogus verdict.
    #[test]
    fn an_unreadable_record_is_no_verdict() {
        assert!(health_from_json(&serde_json::json!({})).is_none());
        assert!(health_from_json(&serde_json::json!({"bucket": "puce"})).is_none());
    }

    #[test]
    fn the_failure_clause_tells_before_from_during() {
        let short = score(&[answer("a", &[M, H])], 30, 0, 1).unwrap();
        assert!(
            failure_clause(&short)
                .unwrap()
                .contains("short before the download started")
        );
        let clean = score(&[answer("a", &[H, H])], 30, 0, 1).unwrap();
        assert!(
            failure_clause(&clean)
                .unwrap()
                .contains("went missing did so after that")
        );
    }
}

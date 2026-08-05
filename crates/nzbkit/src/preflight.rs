//! Pre-flight availability check (design: M2): pipelined STAT sweeps build
//! a per-article × per-server availability matrix before any body bytes
//! are spent. STAT is ~50 bytes per article per server; with deep
//! pipelining thousands of articles check in a couple of seconds.
//!
//! The verdict is advisory (the live ledger during download remains
//! authoritative) but it lets an impossible NZB abort in seconds having
//! downloaded nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use crate::config::ServerConfig;
use crate::nntp::Connection;

/// Availability of one article on one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Avail {
    Unknown,
    Have,
    Missing,
}

const UNKNOWN: u8 = 0;
const HAVE: u8 = 1;
const MISSING: u8 = 2;

/// Per-server result of a sweep: `matrix[server][article]`.
pub struct SweepResult {
    pub matrix: Vec<Vec<Avail>>,
    pub elapsed: Duration,
}

impl SweepResult {
    /// Articles unavailable on every server that answered. An `Unknown`
    /// (sweep error) counts as available - pre-flight must not produce
    /// false IMPOSSIBLE verdicts.
    pub fn union_missing(&self) -> Vec<usize> {
        let n = self.matrix.first().map_or(0, |m| m.len());
        (0..n)
            .filter(|&i| {
                self.matrix.iter().all(|m| m[i] == Avail::Missing) && !self.matrix.is_empty()
            })
            .collect()
    }

    /// (have, missing, unknown) counts for one server.
    pub fn server_counts(&self, s: usize) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for a in &self.matrix[s] {
            match a {
                Avail::Have => c.0 += 1,
                Avail::Missing => c.1 += 1,
                Avail::Unknown => c.2 += 1,
            }
        }
        c
    }
}

/// STAT every id on every server. `connections` are per server; `window`
/// is the pipelined STAT depth (responses are single lines, so a deep
/// window is safe and fast).
pub async fn stat_sweep(
    servers: &[ServerConfig],
    ids: &[String],
    connections: usize,
    window: usize,
) -> SweepResult {
    let t0 = std::time::Instant::now();
    // A zero here is not a configuration, it is a hang - the same reason
    // pool.rs clamps its own window and connection counts in the library
    // rather than at each CLI call site. `check --window 0` made the send
    // loop's `sent - recv < window` guard false on the first iteration:
    // not one STAT went out, every worker then blocked on a reply that
    // could never come until the 20 s timeout, every cell stayed Unknown,
    // and `union_missing` (which needs Missing on EVERY server) counted
    // none of them - so a fully unavailable NZB was reported "COMPLETE -
    // every sampled article present".
    let window = window.max(1);
    let ids: Arc<Vec<String>> = Arc::new(ids.to_vec());
    let mut tasks = Vec::new();
    let mut cells: Vec<Arc<Vec<AtomicU8>>> = Vec::new();

    for server in servers {
        let servercells: Arc<Vec<AtomicU8>> =
            Arc::new((0..ids.len()).map(|_| AtomicU8::new(UNKNOWN)).collect());
        cells.push(servercells.clone());
        for c in 0..connections.max(1) {
            let server = server.clone();
            let ids = ids.clone();
            let cells = servercells.clone();
            let nconn = connections.max(1);
            tasks.push(tokio::spawn(async move {
                // Stride partition: connection c handles ids[c], ids[c+n], …
                let mine: Vec<usize> = (c..ids.len()).step_by(nconn).collect();
                let Ok((mut conn, _)) = Connection::connect(&server).await else {
                    return;
                };
                let mut sent = 0usize; // next index into `mine` to send
                let mut recv = 0usize; // next index into `mine` to receive
                while recv < mine.len() {
                    while sent < mine.len() && sent - recv < window {
                        if conn.send_stat(&ids[mine[sent]]).await.is_err() {
                            return;
                        }
                        sent += 1;
                    }
                    if conn.flush().await.is_err() {
                        return;
                    }
                    let read =
                        tokio::time::timeout(Duration::from_secs(20), conn.read_stat()).await;
                    match read {
                        Ok(Ok(have)) => {
                            cells[mine[recv]]
                                .store(if have { HAVE } else { MISSING }, Ordering::Relaxed);
                            recv += 1;
                        }
                        _ => return, // remaining cells stay Unknown
                    }
                }
                conn.quit().await;
            }));
        }
    }
    for t in tasks {
        let _ = t.await;
    }

    let matrix = cells
        .into_iter()
        .map(|sc| {
            sc.iter()
                .map(|a| match a.load(Ordering::Relaxed) {
                    HAVE => Avail::Have,
                    MISSING => Avail::Missing,
                    _ => Avail::Unknown,
                })
                .collect()
        })
        .collect();
    SweepResult {
        matrix,
        elapsed: t0.elapsed(),
    }
}

/// Stratified sample of `n` segment indexes out of `total`, edges
/// first: takedowns nuke the HEAD of a post and truncated uploads lose
/// the TAIL, so with the budget for it the first three and last two
/// indexes are always sampled - a single flaky STAT on a lone edge
/// probe must not be the only witness to a head nuke - and the
/// remainder spreads evenly across the interior. Deterministic on
/// purpose: a re-probe STATs the identical indexes, so a later Green
/// means the previously missing articles appeared, not a lucky
/// re-roll (the §77 re-probe overwrite leans on this).
pub fn stratified_sample(total: usize, n: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    if n >= total {
        return (0..total).collect();
    }
    let n = n.max(2).min(total);
    // Edge redundancy only once the budget covers it; tiny budgets keep
    // one probe per edge.
    let (head, tail) = if n >= 5 { (3, 2) } else { (1, 1) };
    let mut out: Vec<usize> = (0..head).collect();
    out.extend((total - tail)..total);
    let mid = n - out.len();
    let (lo, hi) = (head, total - tail);
    for i in 0..mid {
        out.push(lo + (i + 1) * (hi - lo) / (mid + 1));
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{Chaos, MockServer, make_file_articles};

    /// Three present ids and two the server has never heard of, swept
    /// over one mock. The matrix is the whole point of the pass: a cell
    /// per (server, article), and the verdict helpers read only it.
    #[tokio::test]
    async fn a_sweep_fills_one_cell_per_article_and_names_the_absent_ones() {
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..24_000u32).map(|i| i as u8).collect();
        let segs = make_file_articles("p.bin", &payload, 8_000, "pf", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let mut ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        let present = ids.len();
        ids.push("<gone-1@mock>".into());
        ids.push("<gone-2@mock>".into());

        let out = tokio::time::timeout(
            Duration::from_secs(20),
            stat_sweep(&[srv.server_config()], &ids, 2, 4),
        )
        .await
        .expect("sweep hung");

        assert_eq!(out.matrix.len(), 1, "one row per server");
        assert_eq!(out.matrix[0].len(), ids.len());
        assert_eq!(out.server_counts(0), (present, 2, 0));
        assert_eq!(
            out.union_missing(),
            vec![present, present + 1],
            "only the ids no server could produce"
        );
    }

    /// `check --window 0` sent not one STAT and then waited out the
    /// 20 s reply timeout with every cell Unknown, which `union_missing`
    /// reads as COMPLETE. Both counts clamp to one inside the sweep.
    #[tokio::test]
    async fn zero_window_and_zero_connections_still_sweep() {
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..16_000u32).map(|i| (i * 5) as u8).collect();
        let segs = make_file_articles("w.bin", &payload, 8_000, "win", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();

        let out = tokio::time::timeout(
            Duration::from_secs(10),
            stat_sweep(&[srv.server_config()], &ids, 0, 0),
        )
        .await
        .expect("a zero window hung the sweep again");
        assert_eq!(out.server_counts(0), (ids.len(), 0, 0));
        assert!(out.union_missing().is_empty());
    }

    /// A server that cannot be dialled leaves its row Unknown - and an
    /// Unknown must never be counted as evidence of absence, or an
    /// unreachable server alone would condemn a healthy NZB.
    #[tokio::test]
    async fn an_undialable_server_leaves_unknowns_that_never_condemn_an_article() {
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..8_000u32).map(|i| i as u8).collect();
        let segs = make_file_articles("d.bin", &payload, 8_000, "dead", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let mut dead = srv.server_config();
        // Bound and then closed by the mock's own listener choice: a
        // port nothing is listening on refuses immediately.
        dead.port = 1;
        dead.host = "127.0.0.1".into();
        let mut ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        ids.push("<absent@mock>".into());

        let out = tokio::time::timeout(
            Duration::from_secs(20),
            stat_sweep(&[srv.server_config(), dead], &ids, 1, 8),
        )
        .await
        .expect("sweep hung");

        assert_eq!(out.matrix.len(), 2);
        assert_eq!(out.server_counts(1), (0, 0, ids.len()), "row never dialled");
        assert!(
            out.union_missing().is_empty(),
            "Missing on the live server plus Unknown on the dead one is not a verdict"
        );
        assert!(out.elapsed > Duration::ZERO);
    }

    /// The two verdict helpers, off a matrix built by hand - the shapes
    /// a sweep cannot be made to produce on demand.
    #[test]
    fn union_missing_needs_every_server_to_agree() {
        let none = SweepResult {
            matrix: Vec::new(),
            elapsed: Duration::ZERO,
        };
        assert!(
            none.union_missing().is_empty(),
            "no server answered: nothing is provably absent"
        );

        use Avail::{Have, Missing, Unknown};
        let r = SweepResult {
            matrix: vec![
                vec![Missing, Missing, Have, Missing],
                vec![Missing, Have, Have, Unknown],
            ],
            elapsed: Duration::from_millis(3),
        };
        assert_eq!(r.union_missing(), vec![0]);
        assert_eq!(r.server_counts(0), (1, 3, 0));
        assert_eq!(r.server_counts(1), (2, 1, 1));
    }

    #[test]
    fn stratified_edges() {
        assert_eq!(stratified_sample(10, 2), vec![0, 9]);
        assert_eq!(stratified_sample(5, 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(stratified_sample(5, 100), vec![0, 1, 2, 3, 4]);
        assert_eq!(stratified_sample(0, 3), Vec::<usize>::new());
        let s = stratified_sample(1000, 100);
        assert_eq!(s[0], 0);
        assert_eq!(*s.last().unwrap(), 999);
        assert!(s.len() >= 99 && s.len() <= 100);
    }

    #[test]
    fn stratified_edge_redundancy() {
        // With budget >= 5 the head gets three probes and the tail two,
        // so one flaky edge answer cannot blind a verdict.
        let s = stratified_sample(10_000, 8);
        assert_eq!(s.len(), 8);
        assert!(s.starts_with(&[0, 1, 2]));
        assert!(s.ends_with(&[9_998, 9_999]));
        // Interior points stay strictly between the edge blocks.
        assert!(s[3..6].iter().all(|&i| i > 2 && i < 9_998));
        // Deterministic: the identical call samples the identical
        // indexes (the re-probe overwrite depends on it).
        assert_eq!(s, stratified_sample(10_000, 8));
        // Tight budgets keep one probe per edge.
        assert_eq!(stratified_sample(100, 3)[0], 0);
        assert_eq!(*stratified_sample(100, 3).last().unwrap(), 99);
        // n one over the edge-block size still covers both edges.
        let s = stratified_sample(10, 6);
        assert!(s.starts_with(&[0, 1, 2]) && s.ends_with(&[8, 9]));
    }
}

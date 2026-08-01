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
                self.matrix.iter().all(|m| m[i] == Avail::Missing)
                    && !self.matrix.is_empty()
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
                            cells[mine[recv]].store(
                                if have { HAVE } else { MISSING },
                                Ordering::Relaxed,
                            );
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

/// Stratified sample of `n` segment indexes out of `total`: always the
/// first and last, evenly spread between.
pub fn stratified_sample(total: usize, n: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    if n >= total {
        return (0..total).collect();
    }
    let n = n.max(2).min(total);
    let mut out: Vec<usize> = (0..n)
        .map(|i| i * (total - 1) / (n - 1))
        .collect();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

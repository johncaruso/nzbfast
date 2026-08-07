//! Timeout and backoff arithmetic for the pool (TODO 96.1 adaptive
//! budgets, TODO 121.1 per-article escalation, session backoff): the
//! pure pacing functions and their constants, split out of pool.rs
//! under the size gate. A child module of `pool` (same pattern as
//! unit_tests.rs) so the arithmetic stays private to the pool.

use super::PoolConfig;
use std::time::Duration;

/// Adaptive timeout decomposition (TODO 96.1), all behind
/// `PoolConfig::adaptive_timeout`. Budget clamps mirror nntppool's
/// field-tested 2-10 s window; the stall bound is the rolling
/// no-progress deadline once bytes flow.
pub(super) const ADAPTIVE_FIRST_BYTE_MIN: Duration = Duration::from_secs(2);
pub(super) const ADAPTIVE_FIRST_BYTE_MAX: Duration = Duration::from_secs(10);
pub(super) const ADAPTIVE_STALL: Duration = Duration::from_secs(8);
/// TODO 121.1: hard ceiling of the PER-ARTICLE pre-byte escalation
/// ladder. Cold-storage lookups answer at 12-25 s first byte, so the
/// ladder must be able to pass the 10 s adaptive ceiling; 30 s bounds
/// what one wedged article can hold a connection for (the tail
/// fan-out dup-races stragglers long before this).
pub(super) const ARTICLE_PREBYTE_CEILING: Duration = Duration::from_secs(30);
/// Floor of the TTFB-suspicion bound (TODO 115): the least pre-byte
/// silence that may mark an in-flight article suspect for the hedge.
pub(super) const TTFB_SUSPECT_MIN: Duration = Duration::from_secs(1);

/// Ceiling on the session-level backoff (see [`session_backoff_delay`]).
/// Long enough that a permanently broken account costs a provider a
/// couple of connects a minute per worker; short enough that a provider
/// coming back from a maintenance window is picked up again promptly.
pub(super) const SESSION_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Pacing for a session that CONNECTED but then failed without doing any
/// useful work - a provider that accepts TCP+TLS+AUTHINFO and then
/// answers every BODY with `502 byte limit exceeded` / `400 idle timeout`,
/// or RSTs after the first command.
///
/// The connect-failure backoff above never covers that shape: the connect
/// succeeds every time, so `connect_failures` stays 0 and the failure
/// paths reconnect instantly. One worker then runs connect → AUTH → BODY →
/// error → reconnect several times a second, and a 50-connection pool
/// aims that at one account until the whole queue burns through its
/// retries. On a 250k-segment single-server job that is on the order of a
/// million connect+AUTH attempts at full rate - the traffic shape
/// providers ban accounts for.
///
/// The counter this feeds is reset by a session that did USEFUL WORK
/// (any well-formed BODY response), not merely by one that connected: a
/// connection that has been serving for hours and hits one transient
/// error is back at step one, while a session that can only ever fail
/// keeps climbing. Backing off is per-worker sleep, so a bad server's
/// workers pace themselves without holding anything the rest of the pool
/// needs - queued work was already released by `requeue_or_fail`.
pub(super) fn session_backoff_delay(cfg: &PoolConfig, failures: u32) -> Duration {
    session_backoff_delay_with(cfg, failures, backoff_immediate())
}

/// The ladder itself, with the immediate-first-retry choice explicit so
/// tests can pin both shapes without touching process env.
pub(super) fn session_backoff_delay_with(
    cfg: &PoolConfig,
    failures: u32,
    immediate: bool,
) -> Duration {
    let mut step = failures.clamp(1, 16) - 1;
    // Default-on since 6 Aug (NZBFAST_BACKOFF_IMMEDIATE=0 reverts): the FIRST failed
    // session retries immediately and the geometric ladder starts at
    // the second - 0, base, 2x, 4x... instead of base, 2x, 4x... The
    // useful-work reset makes step 0 the transient-blip case (a
    // long-serving session that just died), where an instant redial
    // recovers for free; a persistently refusing server still meets
    // the full ladder from its second failure on, so the total extra
    // cost against a broken server is one dial per failure episode.
    if immediate {
        if step == 0 {
            return Duration::ZERO;
        }
        step -= 1;
    }
    // A zero/absurd configured base would defeat the whole point.
    let base = cfg.connect_backoff.max(Duration::from_millis(50));
    base.saturating_mul(1u32 << step).min(SESSION_BACKOFF_MAX)
}

/// See [`session_backoff_delay`]. ON by default (graduated 6 Aug on
/// the fault-matrix pricing: flap 39 -> 36-37 s, surviving real dial
/// costs on flap-dial, neutral elsewhere, jitter kills nothing);
/// NZBFAST_BACKOFF_IMMEDIATE=0 restores the old always-wait ladder.
pub(super) fn backoff_immediate() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !std::env::var("NZBFAST_BACKOFF_IMMEDIATE").is_ok_and(|v| v == "0"))
}

/// The pre-byte budget an EWMA of `ewma_ms` earns: 4x it, clamped to
/// [2 s, 10 s], with 0 ("unmeasured") budgeting at the ceiling.
///
/// Free function rather than a method so the escalation ladder in
/// [`Shared::note_ttfb_timeout`] can be walked in a unit test without
/// standing up a pool and a server.
pub(super) fn ttfb_budget_ms(ewma_ms: u64) -> u64 {
    if ewma_ms == 0 {
        return adaptive_first_byte_max_ms();
    }
    (4 * ewma_ms).clamp(adaptive_first_byte_min_ms(), adaptive_first_byte_max_ms())
}

/// The pre-byte FLOOR, `NZBFAST_TTFB_FLOOR_MS` (default: unchanged).
///
/// Providers answer in tens of ms, so `4 x EWMA` lands far below the
/// floor and every server budgets at exactly this value - which makes
/// it, not the ceiling, the number that decides when a pre-byte read
/// gives up. Measured 6 Aug 2026: with six providers sharing one
/// work-stealing queue, a starved provider's pipelined request can
/// take longer than 2 s to produce its first byte while being neither
/// slow nor dead, and the expiry costs the WHOLE session - one
/// provider lost 11 sessions in 53 s that way, every one of them our
/// own budget (no peer ever closed). Raising
/// NZBFAST_READ_TIMEOUT_SECS does not help: it lifts the CEILING,
/// which never binds. Left at the shipped 2 s until the A/B says a
/// wider floor keeps the dead-air payout (deadair 166 s -> 26 s) that
/// the adaptive path exists for.
pub(super) fn adaptive_first_byte_min_ms() -> u64 {
    static M: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *M.get_or_init(|| {
        let base = ADAPTIVE_FIRST_BYTE_MIN.as_millis() as u64;
        std::env::var("NZBFAST_TTFB_FLOOR_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&ms| ms > 0)
            .unwrap_or(base)
    })
}

/// TODO 121.1: per-article escalation of the adaptive pre-byte budget.
///
/// The per-server escalation (`note_ttfb_timeout`) is not enough on its
/// own: fast pipelined samples decay the EWMA back toward the floor
/// between a slow article's retries, so all `article_retries` attempts
/// could run at the 2 s floor and a healthy cold-storage article
/// (12-25 s first byte) died with no knob to save it (§121.1, measured
/// in the 5 Aug sweep). The article's OWN expiry count escalates ITS
/// next attempt from the adaptive ceiling upward - 10 s, 20 s, 30 s -
/// so the retry allowance probes upward for that article while the
/// server's budget stays trained for everyone else. An env-lifted
/// ceiling (`NZBFAST_READ_TIMEOUT_SECS`) stays dominant.
pub(super) fn article_prebyte_budget(server_budget: Duration, prebyte_expiries: u8) -> Duration {
    if prebyte_expiries == 0 {
        return server_budget;
    }
    let base = adaptive_first_byte_max_ms();
    let ladder = base.saturating_mul(1u64 << (prebyte_expiries.min(6) - 1) as u32);
    let ceiling = (ARTICLE_PREBYTE_CEILING.as_millis() as u64).max(base);
    Duration::from_millis(ladder.min(ceiling)).max(server_budget)
}

/// The adaptive pre-byte ceiling: 10 s, LIFTED (never lowered) by an
/// explicitly-set `NZBFAST_READ_TIMEOUT_SECS` - the documented
/// accommodation for slow cold-storage lookups (12-25 s first byte)
/// must not become a no-op under the adaptive clamp. Lift-only: the
/// chaos suite sets the env LOW (that means the flat path only).
pub(super) fn adaptive_first_byte_max_ms() -> u64 {
    static M: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *M.get_or_init(|| {
        let base = ADAPTIVE_FIRST_BYTE_MAX.as_millis() as u64;
        std::env::var("NZBFAST_READ_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(base, |s| s.saturating_mul(1000).max(base))
    })
}

/// TTFB-suspicion bound (TODO 115): pre-byte silence past this makes an
/// article a hedge candidate. 2x the server's TTFB EWMA, floored at 1 s -
/// half the adaptive budget's own floor, so on a healthy-history server
/// suspicion always fires with a full second of budget left to win in.
/// A server whose honest TTFB is near the second (high-RTT satellite)
/// pushes the bound out with the EWMA instead of hedging every article.
/// 0 ("unmeasured") keeps the floor: no history means no reason to wait.
pub(super) fn ttfb_suspect_ms(ewma_ms: u64) -> u64 {
    (2 * ewma_ms).max(TTFB_SUSPECT_MIN.as_millis() as u64)
}

/// The EWMA a pre-byte timeout leaves behind, given the current one.
///
/// See [`Shared::note_ttfb_timeout`] for why this escalates from the
/// budget that expired rather than from `ewma_ms` itself.
pub(super) fn escalated_ttfb_ms(ewma_ms: u64) -> u64 {
    // The env-lifted ceiling, so the escalation ladder can actually
    // reach a raised NZBFAST_READ_TIMEOUT_SECS instead of stalling at
    // the default's quarter.
    let ceiling = adaptive_first_byte_max_ms() / 4;
    // The expired budget in EWMA terms - it is 4x the EWMA by
    // construction, so dividing back out gives the value that WOULD
    // have produced it had the clamp not intervened. From unmeasured
    // that is the ceiling already: there is nothing to double.
    let implied = ttfb_budget_ms(ewma_ms) / 4;
    (ewma_ms.max(implied) * 2).clamp(1, ceiling)
}

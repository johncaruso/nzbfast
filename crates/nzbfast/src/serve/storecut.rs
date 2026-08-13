//! §158 item 7: fault injection for the two durable store writes, so the
//! "lost from BOTH stores" shapes can be measured rather than described.
//!
//! A record moving in or out of the live queue is TWO independent writes
//! - `.spool/queue.json` (`Daemon::save_queue`) and `.spool/history.jsonl`
//! (`Daemon::history_write_locked`) - and §158 fixed their ORDER: the
//! destination store goes first, so a tear reads "in both stores"
//! (reconcilable at load) rather than "in neither" (unrecoverable). Order
//! is only provable by stopping partway, which is what this module does.
//!
//! Two seams, both `#[cfg(test)]`, both thread-local so a test that calls
//! `enqueue`/`park` inline is the only thread affected:
//!
//!  * [`arm_cut`] lets N further durable writes land and drops every one
//!    after that. `arm_cut(1)` is a kill between a path's first and second
//!    write - the exact window the ordering exists for. Restoring a Daemon
//!    over the kept spool directory then reads the bytes a crash would
//!    have left, not a fixture somebody hand-wrote to match their belief.
//!  * [`on_park_gap`] fires once, at the instant `Daemon::park` has
//!    dropped the row from the live queue. That window is a race rather
//!    than a kill - any other thread's `save_queue` publishes a queue.json
//!    without the row - so the test runs that save itself, right there,
//!    instead of hoping a background thread lands inside a few hundred
//!    microseconds.

use super::*;
use std::cell::{Cell, RefCell};

thread_local! {
    /// Durable store writes still allowed on this thread. `None` means no
    /// cut is armed and everything writes normally; `Some(0)` drops every
    /// further write.
    static BUDGET: Cell<Option<u32>> = const { Cell::new(None) };
    /// One-shot callback for the park window; see [`on_park_gap`].
    static PARK_GAP: RefCell<Option<Box<dyn FnOnce(&Daemon)>>> = const {
        RefCell::new(None)
    };
}

/// Let `writes` further durable store writes land on this thread, then
/// drop every one after them. Disarmed by [`disarm`], never implicitly -
/// a test that leaves it armed would silently mute the next test on the
/// same thread.
pub(in crate::serve) fn arm_cut(writes: u32) {
    BUDGET.with(|b| b.set(Some(writes)));
}

pub(in crate::serve) fn disarm() {
    BUDGET.with(|b| b.set(None));
    PARK_GAP.with(|g| *g.borrow_mut() = None);
}

/// Called by the durable-write seams themselves. `true` means this write
/// must NOT happen, which is what a kill at that instant leaves on disk.
pub(in crate::serve) fn cut_here() -> bool {
    BUDGET.with(|b| match b.get() {
        None => false,
        Some(0) => true,
        Some(n) => {
            b.set(Some(n - 1));
            false
        }
    })
}

/// Run `f` the next time `park` drops a row from the live queue on this
/// thread. One shot: the second park in the same test is unaffected.
pub(in crate::serve) fn on_park_gap(f: impl FnOnce(&Daemon) + 'static) {
    PARK_GAP.with(|g| *g.borrow_mut() = Some(Box::new(f)));
}

/// The `park` side of [`on_park_gap`]. Taken out of the cell BEFORE it
/// runs, so a callback that parks again cannot re-enter itself.
pub(in crate::serve) fn park_gap(d: &Daemon) {
    let f = PARK_GAP.with(|g| g.borrow_mut().take());
    if let Some(f) = f {
        f(d);
    }
}

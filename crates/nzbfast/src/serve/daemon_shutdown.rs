//! How the daemon stops, and the pause timer that stops it temporarily
//! (TODO 106 code motion out of daemon.rs).
//!
//! Two halves of one subject: stopping. `wind_down` is the graceful
//! exit - park the transfer, persist the queue, QUIT every open NNTP
//! session - shared by `mode=shutdown` and by SIGTERM/SIGINT, with
//! `wind_down_and_exit` and the signal handlers on top of it. The pause
//! timer is the same thing bounded in time: `timed_pause` stops the
//! queue for N minutes, `arm_pause_timer` is the one-shot that lifts it,
//! and `persist_pause`/`restore_pause` carry the state across a restart
//! so a timed pause survives being stopped mid-pause.
//!
//! A child module of `daemon` on the daemon_idle shape, so `Daemon`'s
//! private fields and daemon.rs's private imports (`info!`, `Value`)
//! stay in scope exactly as they were inline. `pub(super)` became
//! `pub(in crate::serve)` for exactly that reason: `super` is `daemon`
//! here, and every call site - startup, sabcompat, api/system,
//! api/queue, api/config - is one level up, reached through
//! serve/mod.rs's `use daemon::*`.

use super::*;

/// How long the wind-down below is allowed to take before it exits
/// anyway.
///
/// Sized against `docker stop`, which sends SIGTERM and then SIGKILLs 10
/// seconds later. Being killed halfway through the wind-down is the
/// ungraceful exit we are fixing, so the whole sequence has to finish
/// well inside that with room for a loaded host - and every step it
/// waits on is separately bounded (`Connection::quit` at 500 ms, the
/// pool's own EXIT_GRACE at 5 s).
pub(in crate::serve) const WIND_DOWN_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(4);

/// How long going offline waits for the wound-down fleet to park before
/// it clears the warm pool regardless.
///
/// Longer than [`WIND_DOWN_BUDGET`] because nothing is about to SIGKILL
/// us: this one is racing the operator's patience, not a container
/// runtime. A graceful pause escalates to a hard abort at ~10 s
/// (`suspend_matching`), and the abort's own QUITs are bounded, so the
/// gauge reaches zero well inside this on any provider that answers at
/// all. It exists for the one that does not.
pub(in crate::serve) const OFFLINE_PARK_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(60);

/// Stop cleanly and exit: park the transfer, persist the queue, and
/// hand every open NNTP session back to the provider with a QUIT.
///
/// Shared by `mode=shutdown` and by SIGTERM/SIGINT (issue #13). A
/// container stop has exactly the same work to do as the tray's Quit
/// item, and used to do none of it - nothing was wired to signals, so
/// `docker restart` killed the process outright and left the provider
/// counting ~100 orphaned sessions until its own idle timeout. The
/// restart then asked for a full pool the account could not give it and
/// sat at 0 MB/s.
///
/// Bounded by [`WIND_DOWN_BUDGET`] as a whole: if a step overruns we
/// carry on regardless, because a slow clean exit that gets SIGKILLed is
/// worth no more than the abrupt one.
pub(in crate::serve) fn wind_down(d: &Arc<Daemon>, rt: &tokio::runtime::Handle, reason: &str) {
    let started = Instant::now();
    info!(target: "shutdown", "{reason} - persisting queue and closing connections");
    // Order matters. Pause first so nothing new is admitted while we are
    // tearing down, THEN wind the transfer down GRACEFULLY.
    //
    // Graceful, not the immediate abort, and the difference is the whole
    // point of this function: the hard abort drops the pool future, and
    // a dropped worker never reaches the `conn.quit()` its exit path is
    // built around. Measured against a mock provider that logs commands
    // - eight busy connections, SIGTERM, eight sockets closed and not one
    // QUIT logged. The graceful path admits no new articles, lets the
    // in-flight window land, and lets each worker say goodbye, which is
    // what actually returns the session slot to the account. It also
    // costs less on resume: what landed is journalled instead of being
    // re-fetched.
    d.paused.store(true, Ordering::Relaxed);
    d.suspend_active(true);
    d.save_queue();
    // Now wait for the sessions themselves to go, because THAT is what
    // the provider is counting - not the job's state.
    //
    // Aborted workers QUIT on their way out, but only at their next
    // response boundary: the abort flag is checked at the top of the
    // worker loop, not inside the read it is parked on. So the job
    // leaves `Downloading` well before the fleet has said goodbye, and
    // waiting on the job (which is what this loop did first) exited
    // after 0.3 s with eight connections still open and not one QUIT
    // sent - measured against a mock provider that logs its commands.
    // The live gauge is the honest signal.
    let connected = || -> usize {
        d.hub
            .pool_live
            .lock_ok()
            .as_ref()
            .map(|l| {
                l.servers
                    .iter()
                    .map(|s| s.connected.load(Ordering::Relaxed))
                    .sum()
            })
            .unwrap_or(0)
    };
    let open_at_signal = connected();
    while started.elapsed() < WIND_DOWN_BUDGET && connected() > 0 {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if open_at_signal > 0 {
        let left = connected();
        info!(
            target: "shutdown",
            "{} of {open_at_signal} provider connection(s) closed{}",
            open_at_signal - left,
            if left > 0 {
                format!(" - {left} still busy, dropping them")
            } else {
                String::new()
            }
        );
    }
    // The connections nobody is using are the ones a restart trips over:
    // an idle daemon holds no pool at all, but it does hold parked warm
    // sessions, and those are pure occupancy on the account's cap.
    // `clear()` QUITs each one.
    //
    // `.get()`, NOT `hub.warm()`: the accessor CONSTRUCTS the pool on
    // first call, and construction spawns a keepalive tick, which needs
    // a reactor this thread does not have. On a daemon that had never
    // pooled anything, asking for the pool in order to empty it panicked
    // the wind-down thread - and with SIGTERM's default disposition
    // already replaced, that left a process no `docker stop` could end.
    if let Some(warm) = d.hub.warm.get() {
        let left = WIND_DOWN_BUDGET.saturating_sub(started.elapsed());
        let _ = rt.block_on(async {
            tokio::time::timeout(
                left.max(std::time::Duration::from_millis(200)),
                warm.clear(),
            )
            .await
        });
    }
    info!(
        target: "shutdown",
        "wound down in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    // Flush the log tee's buffer along with stdout before the exit.
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// [`wind_down`], then go - and go whatever happens.
///
/// Installing a signal handler replaces SIGTERM's default disposition,
/// so from here on NOTHING else will end this process for us: a panic or
/// a wedge inside the wind-down does not degrade to the old abrupt exit,
/// it degrades to a daemon that ignores `docker stop` entirely and waits
/// out the 10 s until SIGKILL. Both are covered - the wind-down cannot
/// unwind past `catch_unwind`, and the watchdog exits on time even if it
/// blocks forever.
pub(in crate::serve) fn wind_down_and_exit(
    d: &Arc<Daemon>,
    rt: &tokio::runtime::Handle,
    reason: &str,
) -> ! {
    {
        let reason = reason.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(WIND_DOWN_BUDGET + std::time::Duration::from_secs(2));
            info!(target: "shutdown", "{reason}: wind-down overran its budget - exiting now");
            std::process::exit(0);
        });
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wind_down(d, rt, reason)));
    if r.is_err() {
        info!(target: "shutdown", "wind-down failed - exiting anyway");
    }
    std::process::exit(0);
}

/// Wire SIGTERM/SIGINT to [`wind_down_and_exit`].
///
/// Unix only for the terminate signal; Ctrl-C is handled on every
/// platform. A second signal while the first wind-down is still running
/// is ignored on purpose - the budget already bounds it, and re-entering
/// the sequence would abort the QUITs it exists to send.
///
/// The wait runs on a DEDICATED thread with its own single-thread
/// runtime, never as a task on the shared runtime. A spawned signal
/// task is only as responsive as the runtime's free workers, and the
/// index loops park workers in synchronous SQLite work behind one
/// mutex: with every worker blocked that way, a spawned handler is not
/// polled AT ALL - measured on a saturated 4-worker runtime, SIGTERM
/// went unhandled for five minutes, and the live daemon sat ~30 s on
/// SIGTERM mid-deepening (2 Aug, TODO §98.2). On its own thread the
/// same handler answered in under a millisecond under the same
/// saturation. `docker stop` SIGKILLs at 10 s, so those 30 s are the
/// difference between a graceful exit and an abrupt one.
pub(in crate::serve) fn install_shutdown_signals(daemon: &Arc<Daemon>) {
    // Not when a host app owns the process. Two reasons, either alone
    // sufficient: this path ends in `std::process::exit(0)`, which from
    // an iOS staticlib kills the HOST, not a daemon; and the thread
    // parks forever by design, so installing it once per start/stop
    // cycle leaked a thread plus a whole `Arc<Daemon>` graph per
    // generation. An embedded host's stop is `nzbfast_stop`, which the
    // serve loop already answers.
    if super::is_embedded() {
        return;
    }
    let rt = tokio::runtime::Handle::current();
    let d = daemon.clone();
    let spawned = std::thread::Builder::new()
        .name("signal-wait".into())
        .spawn(move || {
            let srt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    info!(target: "shutdown", "cannot build the signal runtime ({e}) - stop will be abrupt");
                    return;
                }
            };
            let reason = srt.block_on(wait_for_shutdown_signal());
            // Off this thread too: the wind-down blocks on locks and on
            // `Handle::block_on`, and this thread must stay free to keep
            // ignoring further signals (see above).
            std::thread::spawn(move || wind_down_and_exit(&d, &rt, reason));
            // Park forever rather than return: dropping the runtime
            // would unregister the signal handlers and restore the
            // default disposition, so a second SIGTERM mid-wind-down
            // would kill the process abruptly - the exact exit the
            // wind-down exists to avoid.
            loop {
                std::thread::park();
            }
        })
        .is_ok();
    if !spawned {
        info!(target: "shutdown", "cannot spawn the signal thread - stop will be abrupt");
    }
}

/// Resolve to the name of whichever shutdown signal arrives first.
pub(in crate::serve) async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // A failure to register is not fatal: it costs the graceful exit,
        // not the daemon. Say so rather than dying at startup.
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                info!(target: "shutdown", "cannot listen for SIGTERM ({e}) - stop will be abrupt");
                let _ = tokio::signal::ctrl_c().await;
                return "SIGINT";
            }
        };
        tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = tokio::signal::ctrl_c() => "SIGINT",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "Ctrl-C"
    }
}

/// Pause now; with `mins > 0` also arm an auto-resume ("pause for N
/// minutes", SAB's set_pause). The timer only fires if no manual
/// pause/resume happened in between (generation check).
pub(in crate::serve) fn timed_pause(d: &Arc<Daemon>, mins: u64, graceful: bool) {
    let was_paused = d.paused.swap(true, Ordering::Relaxed);
    // Every caller of this is a person or a client acting for one - the
    // scheduler pauses through `apply_action`, which claims the pause
    // for itself.
    *d.pause_source.lock_ok() = "user";
    // M23e: also stop the transfer that's in flight, not just new jobs.
    d.suspend_active(graceful);
    // Marker on the transition only; a re-sent pause of a paused queue
    // is not a new moment.
    if !was_paused {
        d.note_event(
            "pause",
            if mins == 0 {
                "downloads paused".to_string()
            } else {
                format!("downloads paused for {mins} minutes")
            },
        );
    }
    if mins == 0 {
        // Still bump the generation: a plain pause has to cancel any
        // auto-resume a previous timed pause left pending.
        d.pause_gen.fetch_add(1, Ordering::Relaxed);
        *d.pause_until.lock_ok() = None;
    } else {
        arm_pause_timer(d, std::time::Duration::from_secs(mins * 60));
    }
    persist_pause(d);
}

/// Arm the auto-resume timer for a pause that is ALREADY in effect.
///
/// Split out of `timed_pause` so a pause restored at startup can run out
/// the time it has left rather than a fresh full interval, and so it can
/// take a Duration - a pause with 90 seconds to go does not round to a
/// whole number of minutes.
pub(in crate::serve) fn arm_pause_timer(d: &Arc<Daemon>, dur: std::time::Duration) {
    let my_gen = d.pause_gen.fetch_add(1, Ordering::Relaxed) + 1;
    *d.pause_until.lock_ok() = Some(Instant::now() + dur);
    let d = d.clone();
    std::thread::spawn(move || {
        std::thread::sleep(dur);
        if d.pause_gen.load(Ordering::Relaxed) == my_gen {
            d.paused.store(false, Ordering::Relaxed);
            *d.pause_until.lock_ok() = None;
            persist_pause(&d);
            info!(target: "pause", "timed pause over - resumed");
            d.note_event("resume", "timed pause over - downloads resumed");
        }
    });
}

/// Record the queue's pause state so it survives a restart.
///
/// A pause is a deliberate act - a metered week, a call in progress, a
/// benchmark running - and an update or a crash-restart used to undo it
/// silently, with the queue back at full speed and nothing on screen
/// saying the user's choice had been dropped.
///
/// A timed pause is stored as an ABSOLUTE deadline, not "N minutes left".
/// "Pause for 30 minutes" is a statement about when downloading may start
/// again, so a daemon that is down for an hour must come back running,
/// not sit out another half hour. `restore_pause` handles the deadline
/// that passed while we were gone.
///
/// Called only from the paths that carry the user's intent. Notably NOT
/// from `shutdown`/`restart_daemon`, which pause the queue as part of
/// winding down - persisting that would mean every clean quit came back
/// paused.
pub(in crate::serve) fn persist_pause(d: &Daemon) {
    // The dashboard's change handle, bumped WITH the write, exactly as
    // `save_queue` does for the job rows - because paused / offline /
    // pause_source / resume_at ride the same revisioned queue payload.
    // Without this the §129 1b poll answers `"queue": null` for an idle
    // daemon whose only change was this one, the page keeps the queue
    // object it last applied, and the second after the header flips to
    // "Offline" the poll repaints "Online" over a daemon that really is
    // offline. Pause hid the same staleness because it is normally
    // pressed mid-download, where `any_active` makes the queue ride
    // regardless.
    d.queue_rev.fetch_add(1, Ordering::Relaxed);
    let paused = d.paused.load(Ordering::Relaxed);
    let until = d.pause_until.lock_ok().map(|deadline| {
        // Instant is monotonic and process-local, so convert through the
        // time REMAINING to get a wall-clock deadline we can write down.
        unix_now() + deadline.saturating_duration_since(Instant::now()).as_secs() as i64
    });
    // Null removes the key: a running queue leaves nothing behind, so
    // settings.json keeps holding only what the user actually changed.
    save_settings(
        &d.settings_path,
        &[
            ("paused", if paused { json!(true) } else { Value::Null }),
            (
                "pause_until_unix",
                match until.filter(|_| paused) {
                    Some(u) => json!(u),
                    None => Value::Null,
                },
            ),
            // Offline must survive a restart, or a daemon that was
            // deliberately kept off the account would silently reconnect
            // the moment it came back - reoccupying the address slot the
            // operator went offline to free, with nothing on screen
            // saying so.
            (
                "offline",
                match d.offline.load(Ordering::Relaxed) {
                    true => json!(true),
                    false => Value::Null,
                },
            ),
            (
                "paused_by_offline",
                match d.paused_by_offline.load(Ordering::Relaxed) {
                    true => json!(true),
                    false => Value::Null,
                },
            ),
        ],
    );
}

/// Put back the pause the last run was in, at startup.
///
/// Runs BEFORE the scheduler's own startup evaluation, which is allowed
/// to overrule it: a schedule is a standing rule about what should be
/// true at this hour, and it already re-evaluates the whole week on boot
/// for exactly that reason.
pub(in crate::serve) fn restore_pause(d: &Arc<Daemon>, saved: &serde_json::Map<String, Value>) {
    // Offline first, and independently of the pause below: it is the
    // stronger state and the one with a promise attached (this machine
    // is not on the account). Restored by setting the flags directly
    // rather than through `set_offline`, because the queue pause it
    // would apply is already recorded alongside it - re-deriving it here
    // would forget whether the operator had ALSO paused by hand.
    if saved.get("offline").and_then(Value::as_bool) == Some(true) {
        d.offline.store(true, Ordering::Relaxed);
        d.paused_by_offline.store(
            saved.get("paused_by_offline").and_then(Value::as_bool) == Some(true),
            Ordering::Relaxed,
        );
        info!(target: "offline", "restored: offline, touching no provider");
    }
    if saved.get("paused").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let Some(deadline) = saved.get("pause_until_unix").and_then(Value::as_i64) else {
        d.paused.store(true, Ordering::Relaxed);
        info!(target: "pause", "restored: queue paused");
        return;
    };
    let left = deadline - unix_now();
    if left <= 0 {
        // The auto-resume fell due while the daemon was down. Honour it:
        // start running, and clear the keys so we don't re-read them.
        info!(target: "pause", "timed pause expired while stopped - resumed");
        persist_pause(d);
        return;
    }
    d.paused.store(true, Ordering::Relaxed);
    arm_pause_timer(d, std::time::Duration::from_secs(left as u64));
    info!(target: "pause", "restored: paused, {} min left", (left + 59) / 60);
}

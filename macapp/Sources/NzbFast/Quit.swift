import AppKit
import os

/// Delivers the one reply that `.terminateLater` owes AppKit, and
/// guarantees it arrives within a fixed ceiling even when the graceful
/// stop wedges.
///
/// Why this exists: a macOS software-update restart hung on NzbFast.app -
/// applicationShouldTerminate returned .terminateLater and the reply
/// never came, so the OS shutdown waited on us until a force-quit
/// (observed on an unattended Mac, 8 Aug 2026). After .terminateLater AppKit parks the run
/// loop in NSModalPanelRunLoopMode until the reply arrives, and neither a
/// main-actor Task hop nor a plain DispatchQueue.main.async is guaranteed
/// a callout in that state - so a stop that itself finished fine could
/// still leave the reply undelivered, with no retry: the OS asks once.
///
/// The contract this class enforces: once quit is requested, this process
/// WILL be gone within ceiling + grace, whatever the engine or the main
/// run loop are doing. Three rungs, each catching the one above:
///   1. The graceful path calls `deliver()` when Daemon.stop() returns
///      (stop is nominally bounded well under the ceiling).
///   2. A background DispatchSourceTimer fires at `ceiling` and delivers
///      the reply anyway - an abrupt engine exit is safe by design, the
///      journal replays anything in flight (see Daemon.stop()).
///   3. If no reply callout lands on the main thread within `grace` more
///      seconds, the main thread itself is wedged and this process is
///      what blocks the whole shutdown: SIGKILL our own child engine and
///      exit(0).
/// The reply is sent through two channels - a CFRunLoop block in the
/// common modes (NSModalPanelRunLoopMode is a common mode) plus a
/// main-queue async - and a flag makes it single-shot whichever lands
/// first.
final class QuitWatchdog: @unchecked Sendable {
    static let log = Logger(subsystem: "com.nzbfast.app", category: "quit")

    /// Ceiling for the graceful stop. Daemon.stop()'s longest legal path
    /// (2 s shutdown POST + 5 s child wait + 2 s orphan sweep) fits.
    private let ceiling: TimeInterval
    /// Extra allowance for the reply callout itself to reach the main
    /// thread before rung 3 concludes it never will.
    private let grace: TimeInterval

    private let lock = NSLock()
    /// First deliver() call wins the log line; later calls are no-ops
    /// past the flag.
    private var deliverLogged = false
    /// reply(toApplicationShouldTerminate:) has been sent (set on the
    /// main thread, read by the rung-3 check on a background thread).
    private var replied = false
    private var timer: DispatchSourceTimer?

    init(ceiling: TimeInterval = 10, grace: TimeInterval = 3) {
        self.ceiling = ceiling
        self.grace = grace
    }

    /// Start the countdown. Call once, when quit begins, BEFORE returning
    /// .terminateLater (safe: the reply callouts are queued to the main
    /// thread, and we are on it, so nothing can fire until the delegate
    /// method has returned).
    func arm() {
        let t = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        t.schedule(deadline: .now() + ceiling)
        t.setEventHandler { [weak self] in self?.expired() }
        t.resume()
        lock.lock()
        timer = t
        lock.unlock()
        Self.log.notice("watchdog armed: ceiling \(Int(self.ceiling)) s + grace \(Int(self.grace)) s")
    }

    private func expired() {
        Self.log.error("watchdog ceiling reached - engine stop has not finished, replying anyway")
        deliver(why: "watchdog ceiling")
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + grace) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let done = self.replied
            self.lock.unlock()
            guard !done else { return }
            Self.log.fault("reply never reached the main thread - force-exiting so the OS can move on")
            if let pid = Daemon.shared.childPidForEmergencyKill {
                kill(pid, SIGKILL)
            }
            exit(0)
        }
    }

    /// Send the termination reply. Callable from any thread, any number
    /// of times; the first callout that reaches the main thread wins.
    func deliver(why: String) {
        lock.lock()
        let first = !deliverLogged
        deliverLogged = true
        lock.unlock()
        if first {
            Self.log.notice("delivering termination reply: \(why, privacy: .public)")
        }
        let sendReply: () -> Void = { [self] in
            lock.lock()
            let dup = replied
            replied = true
            lock.unlock()
            guard !dup else { return }
            Self.log.notice("reply(toApplicationShouldTerminate: true) sent")
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        // Channel 1: a run-loop callout in the common modes, which covers
        // the modal-panel mode .terminateLater parks the loop in.
        CFRunLoopPerformBlock(CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue, sendReply)
        CFRunLoopWakeUp(CFRunLoopGetMain())
        // Channel 2: the main queue, for the states where the queue is
        // drained but our run-loop block would sit unserviced.
        DispatchQueue.main.async(execute: sendReply)
    }
}

//! C ABI over the embedded nzbfast engine. iOS forbids exec, so unlike
//! Android (which runs the nzbfast binary as a child process) the engine
//! must live INSIDE the app process: this crate builds as a staticlib
//! the app links, and the daemon serves its API + dashboard on
//! 127.0.0.1 from a background thread.
//!
//! Contract (mirrored in include/nzbfast.h):
//! - `nzbfast_start(config_dir, port, apikey)` - spawn the engine.
//!   Returns 0 on accepted start, negative on refusal. Asynchronous:
//!   poll the port (or `nzbfast_is_up`) for readiness.
//! - `nzbfast_stop()` - stop it and release the port. Blocks until the
//!   listener is closed and the runtime is torn down (bounded).
//! - `nzbfast_is_up()` - 1 while the engine thread is alive.
//!
//! Threading: all three are safe from any thread; a global mutex
//! serializes state transitions. Start-after-stop is supported (the
//! serve loop's `request_stop` seam exists for exactly this cycle).

use std::ffi::{CStr, c_char};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// How long stop() waits for the runtime to wind up before abandoning
/// still-blocked pool threads. The HTTP workers exit within one accept
/// tick (500 ms), so the port itself is released well inside this.
const STOP_BUDGET: Duration = Duration::from_secs(8);

struct Engine {
    thread: std::thread::JoinHandle<()>,
}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

/// Start the engine. `config_dir` must be a writable directory (the
/// app's Application Support dir on iOS); config, settings, spool and
/// downloads all live under it. `apikey` may be NULL for an open
/// loopback API (the host app is the only possible client on iOS - the
/// bind is hard-wired to 127.0.0.1).
///
/// Returns 0 = started, -1 = already running, -2 = bad arguments.
///
/// # Safety
/// `config_dir` (and `apikey` when non-NULL) must point to valid
/// NUL-terminated UTF-8 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbfast_start(
    config_dir: *const c_char,
    port: u16,
    apikey: *const c_char,
) -> i32 {
    let dir = match unsafe { cstr_utf8(config_dir) } {
        Some(s) if !s.is_empty() => PathBuf::from(s),
        _ => return -2,
    };
    let apikey = unsafe { cstr_utf8(apikey) }.filter(|s| !s.is_empty());

    let mut engine = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(e) = engine.take() {
        if e.thread.is_finished() {
            let _ = e.thread.join();
        } else {
            *engine = Some(e);
            return -1;
        }
    }

    nzbfast::embedded_init();
    // Arm the stop seam BEFORE spawning, under the ENGINE lock: a
    // request_stop() issued any time after this start() returns then
    // lands above this run's baseline and can never be erased. The old
    // design reset a global flag at serve() entry, so a stop that raced
    // the engine thread's bootstrap was wiped and nzbfast_stop() hung
    // forever in join().
    nzbfast::serve::arm_embedded_stop();
    let config = dir.join("config.local.json");
    let out_root = dir.join("downloads");
    let thread = std::thread::Builder::new()
        .name("nzbfast-engine".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("nzbfast-ffi: runtime build failed: {e}");
                    return;
                }
            };
            let opts = nzbfast::embedded_serve_opts(port, apikey, out_root);
            if let Err(e) = rt.block_on(nzbfast::serve::serve(config, opts)) {
                eprintln!("nzbfast-ffi: serve failed: {e:#}");
            }
            // serve() returned (a stop request, or a startup failure):
            // tear the runtime down without waiting on pool threads that
            // may be parked in long blocking work. The HTTP workers exit
            // on their own within one accept tick, which is what
            // actually frees the port.
            rt.shutdown_timeout(STOP_BUDGET);
        });
    match thread {
        Ok(t) => {
            *engine = Some(Engine { thread: t });
            0
        }
        Err(e) => {
            eprintln!("nzbfast-ffi: engine thread spawn failed: {e}");
            -2
        }
    }
}

/// Stop the engine and wait (bounded by the serve loop's own wind-up)
/// for the port to be released. Returns 0 = stopped, -1 = not running.
#[unsafe(no_mangle)]
pub extern "C" fn nzbfast_stop() -> i32 {
    // The ENGINE lock is held through request_stop AND the join: the
    // stop epoch and its Notify are process-global - a start()
    // interleaved here could re-arm the baseline under engine A (which
    // then parks forever while we join it) or race A for the port.
    // Holding the lock makes a concurrent start/stop/is_up park until
    // the old engine is provably gone; the serve loop's own wind-up
    // bounds the join.
    let mut engine = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
    let e = match engine.take() {
        Some(e) => e,
        None => return -1,
    };
    nzbfast::serve::request_stop();
    let _ = e.thread.join();
    0
}

/// 1 while the engine thread is alive (which includes startup, before
/// the listener answers - poll the HTTP port for real readiness).
#[unsafe(no_mangle)]
pub extern "C" fn nzbfast_is_up() -> i32 {
    let engine = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
    match engine.as_ref() {
        Some(e) if !e.thread.is_finished() => 1,
        _ => 0,
    }
}

/// # Safety
/// `p` is NULL or a valid NUL-terminated string.
unsafe fn cstr_utf8(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

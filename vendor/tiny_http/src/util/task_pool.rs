use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// Manages the threads that parse client connections.
///
/// # nzbfast patch 9 (see VENDORING.md)
///
/// Upstream grew this pool without a ceiling: `spawn` called `add_thread`
/// whenever no thread happened to be idle, and `add_thread` used
/// `thread::spawn` - which cannot fail without panicking. Since one task here
/// is one whole *connection* (the task lives as long as the peer keeps the
/// socket open), an unauthenticated client that opens sockets and dribbles a
/// partial request line on each one held a thread per socket indefinitely.
/// Thread stacks, descriptors and heap went with them, and when the OS finally
/// refused another thread the panic landed in the accept thread - the only one -
/// so HTTP was dead for the life of the process even after the pressure eased.
///
/// So: a hard ceiling on threads, which is therefore a hard ceiling on
/// concurrent connections; a fallible spawn that hands the connection back
/// instead of panicking, so the caller can shed it and keep accepting; and a
/// slot that is released even if a task panics.
///
/// The queue-claiming below is also stricter than upstream. Upstream pushed onto
/// `todo` whenever the idle counter was non-zero, but that counter is only
/// decremented by the woken thread - so two `spawn` calls racing one idle thread
/// could queue two tasks for it, and the second connection then sat unparsed
/// until some unrelated connection closed. Here `spawn` claims the idle thread
/// itself, under the same lock, so a queued task always has a thread already
/// committed to it.
pub struct TaskPool {
    sharing: Arc<Sharing>,
    max_threads: usize,
}

struct Sharing {
    state: Mutex<State>,
    condvar: Condvar,
}

struct State {
    /// Tasks handed to a thread that has already been claimed for them.
    todo: VecDeque<Box<dyn FnMut() + Send>>,
    /// Threads parked in `wait`, each of which `spawn` may claim exactly once.
    idle: usize,
    /// Total live threads. This is the quantity the ceiling applies to.
    threads: usize,
    /// Set by `Drop` so parked threads retire instead of waiting forever.
    closing: bool,
}

/// Threads kept parked once created, so a burst does not pay thread creation.
/// Unlike upstream these are *not* pre-spawned: `threads` is what the ceiling
/// applies to, and warm-up threads that have not parked yet are not claimable,
/// so pre-spawning would let the very first connections be refused while four
/// threads sat idle. They are created on demand and retire down to this floor.
static MIN_THREADS: usize = 4;

/// How long a thread above `MIN_THREADS` stays parked before retiring.
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Releases this thread's slot however the thread leaves - including by
/// unwinding out of a task. Without it a panicking connection would burn a slot
/// off the ceiling permanently, and enough of them would wedge the server just
/// as thoroughly as the unbounded growth did.
struct ThreadSlot(Arc<Sharing>);

impl Drop for ThreadSlot {
    fn drop(&mut self) {
        let mut state = match self.0.state.lock() {
            Ok(s) => s,
            // A poisoned lock means another thread panicked holding it. Nothing
            // to release safely; leaving the count alone is the conservative
            // choice (it costs capacity, not correctness).
            Err(_) => return,
        };
        state.threads = state.threads.saturating_sub(1);
    }
}

impl TaskPool {
    /// `max_threads` is the ceiling on concurrent connections; it is raised to
    /// `MIN_THREADS` if a smaller value is asked for, since those threads exist
    /// from the start.
    pub fn new(max_threads: usize) -> TaskPool {
        TaskPool {
            sharing: Arc::new(Sharing {
                state: Mutex::new(State {
                    todo: VecDeque::new(),
                    idle: 0,
                    threads: 0,
                    closing: false,
                }),
                condvar: Condvar::new(),
            }),
            max_threads: max_threads.max(MIN_THREADS),
        }
    }

    /// Runs `code` on a pool thread.
    ///
    /// Returns `Err(code)` when the pool is at its ceiling or the OS refused a
    /// thread, so the caller can close that connection and keep accepting.
    pub fn spawn(
        &self,
        code: Box<dyn FnMut() + Send>,
    ) -> Result<(), Box<dyn FnMut() + Send>> {
        let mut state = match self.sharing.state.lock() {
            Ok(s) => s,
            Err(_) => return Err(code),
        };

        // Queue only while there are more parked threads than already-queued
        // tasks, so every queued task has a thread committed to it. Upstream
        // tested `idle != 0` alone, which let two racing `spawn` calls queue two
        // tasks for one parked thread - and the second connection then sat
        // unparsed until some unrelated connection closed.
        //
        // Comparing against `todo.len()` rather than decrementing `idle` here is
        // deliberate: `idle` is owned entirely by the threads that park and
        // unpark, so it stays symmetric. A thread that finishes a task and takes
        // this one straight off the queue without ever parking would otherwise
        // leave the count short, and the parked thread it stole from would
        // underflow it on waking.
        if state.idle > state.todo.len() {
            state.todo.push_back(code);
            self.sharing.condvar.notify_one();
            return Ok(());
        }

        if state.threads >= self.max_threads {
            return Err(code);
        }

        state.threads += 1;
        drop(state);

        match self.start_thread(Some(code)) {
            Ok(()) => Ok(()),
            Err(code) => {
                if let Ok(mut state) = self.sharing.state.lock() {
                    state.threads -= 1;
                }
                Err(code)
            }
        }
    }

    /// Starts one thread, optionally with a first task.
    ///
    /// `thread::Builder::spawn` consumes the closure, so the task travels in a
    /// slot the caller still holds: that is how a refused thread hands the
    /// connection back rather than dropping it on the floor.
    fn start_thread(
        &self,
        initial_fn: Option<Box<dyn FnMut() + Send>>,
    ) -> Result<(), Box<dyn FnMut() + Send>> {
        let sharing = self.sharing.clone();
        let slot = Arc::new(Mutex::new(initial_fn));
        let mine = slot.clone();

        let started = thread::Builder::new()
            .name("tiny-http-conn".to_owned())
            .spawn(move || {
                let _slot = ThreadSlot(sharing.clone());

                if let Some(mut f) = mine.lock().unwrap().take() {
                    f();
                }

                loop {
                    let mut task = {
                        let mut state = match sharing.state.lock() {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                        // Whether THIS thread is currently counted in `idle`.
                        // Every decrement below is paired with this increment,
                        // which is what keeps the counter honest when one thread
                        // takes work another was notified about.
                        let mut parked = false;

                        loop {
                            if state.closing {
                                if parked {
                                    state.idle -= 1;
                                }
                                return;
                            }
                            if let Some(task) = state.todo.pop_front() {
                                if parked {
                                    state.idle -= 1;
                                }
                                break task;
                            }

                            if !parked {
                                state.idle += 1;
                                parked = true;
                            }

                            let retirable = state.threads > MIN_THREADS;
                            let timed_out = if retirable {
                                let (guard, res) = match sharing
                                    .condvar
                                    .wait_timeout(state, IDLE_TIMEOUT)
                                {
                                    Ok(v) => v,
                                    Err(_) => return,
                                };
                                state = guard;
                                res.timed_out()
                            } else {
                                state = match sharing.condvar.wait(state) {
                                    Ok(g) => g,
                                    Err(_) => return,
                                };
                                false
                            };

                            if timed_out && state.todo.is_empty() && state.threads > MIN_THREADS {
                                state.idle -= 1;
                                return;
                            }
                            // Otherwise loop: re-check `closing`, take any task
                            // that arrived, and stay parked if neither.
                        }
                    };

                    task();
                }
            });

        match started {
            Ok(_) => Ok(()),
            Err(e) => {
                log::warn!("could not start an HTTP connection thread: {}", e);
                // The closure was dropped without running, so the task is still
                // in the slot.
                match slot.lock() {
                    Ok(mut held) => match held.take() {
                        Some(code) => Err(code),
                        None => Ok(()),
                    },
                    Err(_) => Ok(()),
                }
            }
        }
    }
}

impl Drop for TaskPool {
    fn drop(&mut self) {
        if let Ok(mut state) = self.sharing.state.lock() {
            state.closing = true;
        }
        self.sharing.condvar.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    /// The ceiling holds even when every thread is occupied by a task that
    /// never returns - which is what a held-open connection looks like. This is
    /// the property upstream did not have: there, all 40 would have been
    /// accepted and 40 threads created.
    #[test]
    fn spawn_refuses_past_the_ceiling_instead_of_growing() {
        let pool = TaskPool::new(6);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let running = Arc::new(AtomicUsize::new(0));

        let mut accepted = 0;
        for _ in 0..40 {
            let running = running.clone();
            let release_rx = release_rx.clone();
            let task = Box::new(move || {
                running.fetch_add(1, Ordering::AcqRel);
                // Park until the test lets go, standing in for a connection the
                // peer keeps open.
                let _ = release_rx.lock().unwrap().recv();
            });
            if pool.spawn(task).is_ok() {
                accepted += 1;
            }
        }

        assert_eq!(
            accepted, 6,
            "the pool accepted {} tasks with a ceiling of 6",
            accepted
        );
        drop(release_tx);
        assert!(running.load(Ordering::Acquire) <= 6);
    }

    /// A panicking task must give its slot back, or the ceiling erodes to zero
    /// and the server stops accepting for the life of the process. Running three
    /// times the ceiling through it is the assertion: if slots leaked, the pool
    /// would refuse permanently after the fourth panic.
    ///
    /// The panic messages this prints on stderr are the test working.
    ///
    /// A slot is released when the panicking thread finishes unwinding, which
    /// races the next spawn - so a refusal here is timing, not a leak, and is
    /// retried. That window costs at most one refused connection in production,
    /// and only when already at the ceiling.
    #[test]
    fn a_panicking_task_releases_its_slot() {
        let pool = TaskPool::new(4);

        for i in 0..12 {
            let (done_tx, done_rx) = mpsc::channel();
            let mut once = Some(done_tx);
            let mut task: Option<Box<dyn FnMut() + Send>> = Some(Box::new(move || {
                if let Some(tx) = once.take() {
                    let _ = tx.send(());
                    panic!("task blew up");
                }
            }));
            for _ in 0..200 {
                match pool.spawn(task.take().unwrap()) {
                    Ok(()) => break,
                    Err(back) => {
                        task = Some(back);
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
            assert!(
                task.is_none(),
                "the pool stopped accepting work after {} panics",
                i
            );
            done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        }

        // Threads may still be mid-teardown, so give the releases a moment.
        let mut settled = false;
        for _ in 0..200 {
            if pool.sharing.state.lock().unwrap().threads <= 4 {
                settled = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(settled, "panicked tasks leaked their slots");
    }

    /// Every task handed to the pool must actually run. Upstream could queue two
    /// tasks against one idle thread, and the second then waited on an unrelated
    /// connection closing.
    #[test]
    fn a_queued_task_always_has_a_thread_committed_to_it() {
        let pool = TaskPool::new(64);
        let (tx, rx) = mpsc::channel();

        for _ in 0..64 {
            let tx = tx.clone();
            assert!(pool
                .spawn(Box::new(move || {
                    let _ = tx.send(());
                }))
                .is_ok());
        }
        drop(tx);

        let mut ran = 0;
        while rx.recv_timeout(Duration::from_secs(10)).is_ok() {
            ran += 1;
        }
        assert_eq!(ran, 64, "only {} of 64 queued tasks ran", ran);
    }

    /// A slot freed by a finished connection is reused, so the ceiling is a
    /// concurrency limit and not a lifetime budget - and reuse never pushes the
    /// thread count past it.
    #[test]
    fn finished_tasks_return_their_slot_to_the_pool() {
        let pool = TaskPool::new(4);

        for i in 0..50 {
            let (done_tx, done_rx) = mpsc::channel();
            let mut task: Option<Box<dyn FnMut() + Send>> = Some(Box::new(move || {
                let _ = done_tx.send(());
            }));
            // A thread that has just finished may not have parked yet, so a
            // refusal here is timing and not capacity: retry briefly.
            for _ in 0..200 {
                match pool.spawn(task.take().unwrap()) {
                    Ok(()) => break,
                    Err(back) => {
                        task = Some(back);
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
            assert!(task.is_none(), "the pool never accepted task {}", i);
            done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert!(
                pool.sharing.state.lock().unwrap().threads <= 4,
                "thread count passed the ceiling on task {}",
                i
            );
        }
    }
}

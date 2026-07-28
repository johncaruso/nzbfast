//! M15: one global memory budget for every cache tier in the pipeline.
//!
//! The engine treats RAM as a cache, never a requirement: every consumer
//! (extractor holds, verifier partial blocks, the body-buffer pool) has a
//! graceful spill path - materialize to disk, defer to settle read-back,
//! allocate-and-free. The budget just decides *when* each tier spills, so
//! a 190 GB job on an 8 GB NAS degrades to more disk I/O instead of
//! swapping the machine to death.
//!
//! Sizing: by default a quarter of physical RAM, clamped to
//! [256 MB, 16 GB] - small boxes never swap, big boxes never waste. Inside
//! a container the cgroup memory limit (not host RAM) is the OOM-kill
//! line, so the budget is further capped at half of it. The `--mem-limit`
//! flag overrides.

/// Physical RAM in bytes (unix: sysconf pages × page size).
pub fn physical_ram() -> Option<u64> {
    #[cfg(unix)]
    unsafe {
        let pages = libc::sysconf(libc::_SC_PHYS_PAGES);
        let page = libc::sysconf(libc::_SC_PAGE_SIZE);
        if pages > 0 && page > 0 {
            return Some(pages as u64 * page as u64);
        }
    }
    None
}

/// Cgroup memory limit on our own cgroup (Linux): tightest `memory.max`
/// (v2) or `memory.limit_in_bytes` (v1 memory controller) walking from
/// this process's cgroup up to the mount root, so both private-cgroupns
/// containers (path `/`) and nested host paths (systemd slices, docker
/// with host cgroupns) resolve. "max" / v1's page-rounded i64::MAX
/// sentinel read as no limit.
#[cfg(target_os = "linux")]
pub fn cgroup_mem_limit() -> Option<u64> {
    use std::path::Path;
    fn read_limit(p: &Path) -> Option<u64> {
        let v: u64 = std::fs::read_to_string(p).ok()?.trim().parse().ok()?;
        (v < 1 << 48).then_some(v)
    }
    fn tightest(base: &Path, rel: &str, file: &str) -> Option<u64> {
        let mut dir = base.join(rel.trim_start_matches('/'));
        let mut best: Option<u64> = None;
        loop {
            if let Some(v) = read_limit(&dir.join(file)) {
                best = Some(best.map_or(v, |b| b.min(v)));
            }
            if dir == *base || !dir.pop() {
                return best;
            }
        }
    }
    let cg = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let mut best: Option<u64> = None;
    for line in cg.lines() {
        let mut it = line.splitn(3, ':');
        let (Some(_), Some(ctrls), Some(rel)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let found = if ctrls.is_empty() {
            tightest(Path::new("/sys/fs/cgroup"), rel, "memory.max")
        } else if ctrls.split(',').any(|c| c == "memory") {
            tightest(Path::new("/sys/fs/cgroup/memory"), rel, "memory.limit_in_bytes")
        } else {
            None
        };
        if let Some(v) = found {
            best = Some(best.map_or(v, |b| b.min(v)));
        }
    }
    best
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_mem_limit() -> Option<u64> {
    None
}

#[derive(Clone, Copy, Debug)]
pub struct MemBudget {
    pub total: u64,
}

impl MemBudget {
    pub const MIN: u64 = 64 << 20; // even --mem-limit can't go below 64 MB
    const AUTO_FLOOR: u64 = 256 << 20;
    // 16 GB (was 4): the 4 GB ceiling forced the verify-partials spill on
    // big-RAM boxes - measured on the 190 GB Kill Bill set: 540 s at
    // 4.29 GB vs 499 s at 16 GB vs 435 s at 64 GB. RAM/4
    // keeps small machines safe; --mem-limit / the mem_limit setting
    // still overrides in either direction.
    const AUTO_CEIL: u64 = 16 << 30;

    /// Quarter of physical RAM, clamped - the no-configuration default.
    /// In a container, additionally capped at half the cgroup memory
    /// limit: the RAM/4 rule shares a host with other apps and the page
    /// cache, but a cgroup limit is this process's hard OOM-kill line, so
    /// half is spent on cache and half stays free for everything the
    /// budget doesn't track (decode scratch, repair matrices, stacks).
    pub fn auto() -> MemBudget {
        MemBudget { total: Self::auto_total(physical_ram(), cgroup_mem_limit()) }
    }

    fn auto_total(ram: Option<u64>, cgroup_limit: Option<u64>) -> u64 {
        let host = ram
            .map(|r| (r / 4).clamp(Self::AUTO_FLOOR, Self::AUTO_CEIL))
            .unwrap_or(1 << 30);
        match cgroup_limit {
            Some(lim) => host.min((lim / 2).max(Self::MIN)),
            None => host,
        }
    }

    pub fn with_total(total: u64) -> MemBudget {
        MemBudget { total: total.max(Self::MIN) }
    }

    /// Extractor held-span ceiling (spill: materialize volumes to disk).
    pub fn holds_cap(&self) -> usize {
        (self.total / 100 * 45) as usize
    }

    /// Verifier partial-block ceiling, GLOBAL across all slots (spill:
    /// leave blocks Pending → settle read-back hashes them from disk).
    pub fn partials_cap(&self) -> usize {
        (self.total / 100 * 30) as usize
    }

    /// Body-buffer pool retention count (~800 KB each; spill: plain
    /// allocate/free, the allocator absorbs the churn).
    pub fn bufpool_bufs(&self) -> usize {
        ((self.total / 100 * 15) / (800 * 1024)).clamp(32, 512) as usize
    }

    /// fetch→decode channel depth (raw articles in flight between the
    /// pool and the decode threads, ~800 KB each). Historically a fixed
    /// 256 - up to ~200 MB of budget-EXEMPT bytes, which on a 256 MB-
    /// budget box could exceed the entire budget by itself (B2). A
    /// budget/16 slice keeps the pipeline deep on big metal (256 at
    /// 3.3 GB+) without drowning small boxes (20 at the 256 MB floor);
    /// backpressure semantics are unchanged, the channel just fills
    /// sooner and the TCP windows close - the systemic response the
    /// slow-disk throttle test already pins.
    pub fn channel_depth(&self) -> usize {
        ((self.total / 16) / (800 * 1024)).clamp(8, 256) as usize
    }

    /// Wire-side in-flight body byte cap, GLOBAL across every server
    /// pool (B3). Pipelined BODY responses are budget-EXEMPT bytes:
    /// window × connections × ~800 KB pooled bodies - 48 connections at
    /// window 3 is 115 MB+ before the first article even reaches the
    /// fetch→decode channel. Workers stop topping up their pipeline past
    /// one request per connection while the pool's charged estimate
    /// exceeds this; the one-in-flight floor keeps every connection busy
    /// (no deadlock - throughput degrades to window 1 at worst). A
    /// budget/4 slice leaves deep pipelines untouched on big metal
    /// (256 MB+ at the 1 GB auto default) while a 256 MB-budget box is
    /// held to 64 MB of wire bodies.
    pub fn inflight_cap(&self) -> u64 {
        (self.total / 4).clamp(32 << 20, 2 << 30)
    }

    /// Working-buffer ceiling for RAR recovery repair (embedded recovery
    /// records and `.rev` reconstruction).
    ///
    /// These run after the download pipeline has drained, so the cache tiers
    /// above are releasing rather than filling and a quarter of the budget
    /// is comfortably available. The slice exists to keep the repair of a
    /// 20 GB volume bounded at all - before it, recovery read whole volumes
    /// and cloned them, entirely outside this budget.
    pub fn repair_cap(&self) -> u64 {
        (self.total / 4).clamp(8 << 20, 512 << 20)
    }
}

/// The budget this process resolved at startup, in bytes; 0 until set.
static PROCESS_BUDGET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Publishes the resolved budget process-wide.
///
/// Every entry point resolves a budget from `--mem-limit`, the `mem_limit`
/// setting, or [`MemBudget::auto`], then threads it into the pipeline. The
/// repair paths sit several layers below any of those call sites (extraction
/// failure -> recovery-record repair -> per-volume repair), and threading a
/// budget down that chain would touch every caller for one leaf consumer.
pub fn set_process_budget(budget: MemBudget) {
    PROCESS_BUDGET.store(budget.total, std::sync::atomic::Ordering::Relaxed);
}

/// The published budget, or [`MemBudget::auto`] when nothing set one (a
/// library user, or a test calling a repair helper directly).
pub fn process_budget() -> MemBudget {
    match PROCESS_BUDGET.load(std::sync::atomic::Ordering::Relaxed) {
        0 => MemBudget::auto(),
        total => MemBudget { total },
    }
}

/// B4: RAM-tiered caps on job concurrency (connections per server,
/// pipeline window, decode threads). MemBudget protects correctness on
/// small boxes; these protect throughput consistency - 8 connections on
/// a 512 MB NAS just fill the budget faster and spill-churn the HDD,
/// which measures slower than simply running fewer connections. Applied
/// as a clamp on the effective values at job start, never by rewriting
/// user config - the config stays portable, and the same settings are
/// honoured in full the moment they run on bigger hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcurrencyCaps {
    pub connections: usize,
    pub window: usize,
    pub decoders: usize,
}

impl ConcurrencyCaps {
    /// Clamp the requested values to these caps.
    pub fn apply(&self, connections: usize, window: usize, decoders: usize)
    -> (usize, usize, usize) {
        (connections.min(self.connections), window.min(self.window), decoders.min(self.decoders))
    }
}

/// Caps for this machine, or None above 1 GB - big-box behavior stays
/// byte-identical. Same RAM sources as MemBudget::auto: inside a
/// container the cgroup limit, not host RAM, is what we can actually
/// spend, so the tighter of the two picks the tier.
pub fn concurrency_caps() -> Option<ConcurrencyCaps> {
    concurrency_caps_for(physical_ram(), cgroup_mem_limit())
}

fn concurrency_caps_for(ram: Option<u64>, cgroup_limit: Option<u64>) -> Option<ConcurrencyCaps> {
    // Unknown RAM reads as "not small": clamping is an optimization for
    // boxes we can SEE are tiny, never a penalty for a failed probe.
    let eff = match (ram, cgroup_limit) {
        (Some(r), Some(l)) => r.min(l),
        (Some(r), None) => r,
        (None, Some(l)) => l,
        (None, None) => return None,
    };
    if eff <= 512 << 20 {
        Some(ConcurrencyCaps { connections: 4, window: 2, decoders: 2 })
    } else if eff <= 1 << 30 {
        Some(ConcurrencyCaps { connections: 6, window: 3, decoders: 2 })
    } else {
        None
    }
}

/// Peak resident set size of this process in bytes (getrusage; Linux
/// reports KB, macOS bytes). The number benchmarks quote.
pub fn peak_rss() -> Option<u64> {
    #[cfg(unix)]
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
            let raw = ru.ru_maxrss as u64;
            return Some(if cfg!(target_os = "linux") { raw * 1024 } else { raw });
        }
    }
    None
}

/// CURRENT resident set size in bytes - the live number the dashboard's
/// resource chart tracks (peak_rss only ever goes up). macOS: mach
/// task_info; Linux: /proc/self/statm; elsewhere falls back to the peak.
pub fn current_rss() -> Option<u64> {
    #[cfg(target_os = "macos")]
    unsafe {
        // struct mach_task_basic_info (mach/task_info.h): three
        // mach_vm_size_t, two time_value_t, policy_t, integer_t.
        #[repr(C)]
        struct TaskBasicInfo {
            virtual_size: u64,
            resident_size: u64,
            resident_size_max: u64,
            user_time: [i32; 2],
            system_time: [i32; 2],
            policy: i32,
            suspend_count: i32,
        }
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn task_info(task: u32, flavor: u32, info: *mut TaskBasicInfo, count: *mut u32)
                -> i32;
        }
        const MACH_TASK_BASIC_INFO: u32 = 20;
        let mut info: TaskBasicInfo = std::mem::zeroed();
        let mut count = (std::mem::size_of::<TaskBasicInfo>() / 4) as u32;
        if task_info(mach_task_self_, MACH_TASK_BASIC_INFO, &mut info, &mut count) == 0 {
            return Some(info.resident_size);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // statm field 2 = resident pages.
        if let Some(pages) = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()))
        {
            let page = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
            if page > 0 {
                return Some(pages * page as u64);
            }
        }
    }
    peak_rss()
}

/// The kernel's honest memory charge for this process - macOS
/// phys_footprint (what Activity Monitor's Memory column and the memory-
/// pressure system use). Unlike resident_size it EXCLUDES pages the
/// allocator has already offered back via madvise-reusable, so it falls
/// after an idle trim where naive RSS stays pinned. Elsewhere it equals
/// current_rss.
pub fn dashboard_rss() -> Option<u64> {
    #[cfg(target_os = "macos")]
    unsafe {
        // struct task_vm_info (mach/task_info.h), flavor 22.
        #[repr(C)]
        #[derive(Default, Clone, Copy)]
        struct TaskVmInfo {
            virtual_size: u64,
            region_count: i32,
            page_size: i32,
            resident_size: u64,
            resident_size_peak: u64,
            device: u64,
            device_peak: u64,
            internal: u64,
            internal_peak: u64,
            external: u64,
            external_peak: u64,
            reusable: u64,
            reusable_peak: u64,
            purgeable_volatile_pmap: u64,
            purgeable_volatile_resident: u64,
            purgeable_volatile_virtual: u64,
            compressed: u64,
            compressed_peak: u64,
            compressed_lifetime: u64,
            phys_footprint: u64,
            min_address: u64,
            max_address: u64,
        }
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn task_info(task: u32, flavor: u32, info: *mut TaskVmInfo, count: *mut u32) -> i32;
        }
        const TASK_VM_INFO: u32 = 22;
        let mut info = TaskVmInfo::default();
        let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
        if task_info(mach_task_self_, TASK_VM_INFO, &mut info, &mut count) == 0
            && info.phys_footprint > 0
        {
            return Some(info.phys_footprint);
        }
    }
    current_rss()
}

/// Hand freed-but-retained allocator pages back to the OS. When a job
/// ends the pipeline frees its buffers, but malloc keeps the pages
/// resident for reuse - harmless, yet it reads as a leak on the
/// dashboard's RAM line and starves nothing proactively. macOS reports
/// bytes released; glibc's malloc_trim only reports whether anything was
/// released (surfaced as 0 here); other platforms are a no-op.
#[allow(unreachable_code)]
pub fn trim() -> u64 {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            // malloc/malloc.h: zone == NULL means every zone, goal == 0
            // means "release as much as possible".
            fn malloc_zone_pressure_relief(
                zone: *mut libc::c_void,
                goal: libc::size_t,
            ) -> libc::size_t;
        }
        return unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) as u64 };
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        libc::malloc_trim(0);
    }
    0
}

/// Total CPU time (user + system) this process has consumed, in seconds.
/// Deltas between samples over wall time give the process CPU%.
pub fn cpu_time_secs() -> Option<f64> {
    #[cfg(unix)]
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
            return Some(
                ru.ru_utime.tv_sec as f64
                    + ru.ru_utime.tv_usec as f64 / 1e6
                    + ru.ru_stime.tv_sec as f64
                    + ru.ru_stime.tv_usec as f64 / 1e6,
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_slices_and_clamps() {
        let b = MemBudget::with_total(1 << 30);
        assert_eq!(b.holds_cap(), (1u64 << 30) as usize / 100 * 45);
        assert_eq!(b.partials_cap(), (1u64 << 30) as usize / 100 * 30);
        assert!(b.bufpool_bufs() >= 32 && b.bufpool_bufs() <= 512);
        // B2: channel depth scales with the budget and stays clamped.
        assert_eq!(b.channel_depth(), ((1u64 << 30) / 16 / (800 * 1024)) as usize);
        assert_eq!(MemBudget::with_total(256 << 20).channel_depth(), 20);
        assert_eq!(MemBudget::with_total(64 << 20).channel_depth(), 8); // floor
        assert_eq!(MemBudget::with_total(16 << 30).channel_depth(), 256); // cap
        // B3: wire-side in-flight cap scales with the budget, clamped.
        assert_eq!(b.inflight_cap(), (1u64 << 30) / 4);
        assert_eq!(MemBudget::with_total(256 << 20).inflight_cap(), 64 << 20);
        assert_eq!(MemBudget::with_total(64 << 20).inflight_cap(), 32 << 20); // floor
        assert_eq!(MemBudget::with_total(16 << 30).inflight_cap(), 2 << 30); // cap
        // Slices always fit inside the whole.
        assert!(b.holds_cap() + b.partials_cap() < b.total as usize);
        // Floor: even absurd --mem-limit values keep the engine viable.
        assert_eq!(MemBudget::with_total(1).total, MemBudget::MIN);
        // Auto is clamped sane on any machine (a tight cgroup limit may
        // pull it below the 256 MB auto floor, never below MIN).
        let a = MemBudget::auto();
        assert!(a.total >= MemBudget::MIN && a.total <= 16 << 30);
    }

    #[test]
    fn auto_respects_cgroup_limit() {
        let gb = 1u64 << 30;
        // Uncontained: quarter of RAM, clamped.
        assert_eq!(MemBudget::auto_total(Some(64 * gb), None), 16 * gb);
        assert_eq!(MemBudget::auto_total(Some(512 << 20), None), 256 << 20);
        // docker --memory 1g on a big host: half the limit, not RAM/4.
        assert_eq!(MemBudget::auto_total(Some(25 * gb), Some(gb)), gb / 2);
        // Roomy limit doesn't inflate the host-derived figure.
        assert_eq!(MemBudget::auto_total(Some(8 * gb), Some(32 * gb)), 2 * gb);
        // Tiny limit floors at MIN, not at the 256 MB auto floor.
        assert_eq!(MemBudget::auto_total(Some(25 * gb), Some(96 << 20)), MemBudget::MIN);
    }

    #[test]
    fn concurrency_caps_tiers() {
        let mb = |n: u64| Some(n << 20);
        // Tiny tier: <=512 MB.
        assert_eq!(
            concurrency_caps_for(mb(256), None),
            Some(ConcurrencyCaps { connections: 4, window: 2, decoders: 2 })
        );
        assert_eq!(
            concurrency_caps_for(mb(512), None),
            Some(ConcurrencyCaps { connections: 4, window: 2, decoders: 2 })
        );
        // Small tier: <=1 GB.
        assert_eq!(
            concurrency_caps_for(mb(513), None),
            Some(ConcurrencyCaps { connections: 6, window: 3, decoders: 2 })
        );
        assert_eq!(
            concurrency_caps_for(mb(1024), None),
            Some(ConcurrencyCaps { connections: 6, window: 3, decoders: 2 })
        );
        // Above 1 GB: no caps - big-box behavior byte-identical.
        assert_eq!(concurrency_caps_for(mb(1025), None), None);
        assert_eq!(concurrency_caps_for(Some(64 << 30), None), None);
        // The tighter of host RAM and cgroup limit picks the tier.
        assert_eq!(
            concurrency_caps_for(Some(64 << 30), mb(512)),
            Some(ConcurrencyCaps { connections: 4, window: 2, decoders: 2 })
        );
        assert_eq!(concurrency_caps_for(mb(512), Some(64 << 30)).unwrap().connections, 4);
        // Unknown RAM never clamps - a failed probe is not a small box.
        assert_eq!(concurrency_caps_for(None, None), None);
        assert_eq!(concurrency_caps_for(None, mb(256)).unwrap().connections, 4);
    }

    #[test]
    fn concurrency_caps_apply_clamps_only_downward() {
        let caps = ConcurrencyCaps { connections: 6, window: 3, decoders: 2 };
        // Above the caps: clamped, per axis.
        assert_eq!(caps.apply(8, 4, 4), (6, 3, 2));
        // At or below: untouched - a deliberate low setting stays.
        assert_eq!(caps.apply(2, 1, 1), (2, 1, 1));
        assert_eq!(caps.apply(6, 3, 2), (6, 3, 2));
        // Mixed: only the offending axis moves.
        assert_eq!(caps.apply(4, 4, 1), (4, 3, 1));
    }

    #[test]
    fn rss_and_ram_readable() {
        // Smoke: both syscall paths work on the platforms we test on.
        assert!(physical_ram().unwrap_or(0) > 1 << 30);
        assert!(peak_rss().unwrap_or(0) > 1 << 20);
        // Current RSS is live and can never exceed the getrusage peak.
        let cur = current_rss().unwrap_or(0);
        assert!(cur > 1 << 20);
        assert!(cur <= peak_rss().unwrap_or(u64::MAX));
        // CPU clock is readable and monotone.
        let a = cpu_time_secs().unwrap();
        let b = cpu_time_secs().unwrap();
        assert!(a >= 0.0 && b >= a);
    }

    #[test]
    fn trim_links_and_survives() {
        // Smoke: the platform symbol resolves and a burst of freed
        // allocations doesn't make trim misbehave. No RSS assertion -
        // how much the OS takes back is its business.
        let bufs: Vec<Vec<u8>> = (0..64).map(|_| vec![7u8; 1 << 20]).collect();
        drop(bufs);
        trim();
        trim(); // idempotent on an already-trimmed heap
    }
}

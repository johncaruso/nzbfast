use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// mimalloc on macOS + Linux: faster under the pipeline's alloc/free churn
// on constrained-CPU Linux boxes (ARM NAS, Celeron, Pi), and on macOS it
// lets the post-job idle trim (serve.rs) hand freed memory back to the OS.
// Windows keeps the system allocator. See the note in Cargo.toml.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod conntune;
mod gates;
mod groups;
mod groupstats;
mod import_sab;
mod interests;
mod newznab;
mod notify;
mod persist;
mod post_cmd;
mod ratelimit;
mod rss;
mod serve;
mod setup;
mod smart;
mod tools;
mod wall;
mod watchlist;
use nzbkit::config::{Config, ServerConfig};
use nzbkit::nntp::Connection;
use nzbkit::nzb::{FileKind, Nzb};

#[derive(Parser)]
#[command(name = "nzbfast", version, about = "Speed-focused NZB downloader")]
struct Cli {
    /// Path to config with server credentials.
    #[arg(long, default_value = "config.local.json", global = true)]
    config: PathBuf,

    /// Memory budget for the pipeline's cache tiers (e.g. 512M, 2G).
    /// Default: a quarter of physical RAM, clamped to 256M..4G. Beyond
    /// the budget the engine degrades to disk (materialized volumes,
    /// settle read-back) instead of swapping the machine.
    #[arg(long, global = true)]
    mem_limit: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse an NZB and print its contents + minimality accounting.
    Inspect { nzb: PathBuf },
    /// Connection + TLS + AUTHINFO smoke test; reports RTT and capabilities.
    Probe,
    /// Throughput A/B: pipelined vs serial article fetching.
    Bench {
        /// Group to draw benchmark articles from.
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Articles per mode.
        #[arg(long, default_value_t = 100)]
        articles: usize,
        /// Concurrent connections per mode.
        #[arg(long, default_value_t = 5)]
        connections: usize,
        /// Pipelined commands in flight per connection.
        #[arg(long, default_value_t = 3)]
        window: usize,
        /// Run both modes at the same time (paired test - cancels drift in
        /// provider/link conditions; use when total bandwidth isn't the cap).
        #[arg(long)]
        simultaneous: bool,
        /// Fixed-duration mode: fetch continuously for this many seconds and
        /// count bytes (immune to cold-article stragglers). 0 = fetch-all.
        #[arg(long, default_value_t = 0)]
        duration: u64,
    },
    /// Fetch + decode articles through the managed pool (Phase 2b shakeout).
    Fetch {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        #[arg(long, default_value_t = 200)]
        articles: usize,
        #[arg(long, default_value_t = 6)]
        connections: usize,
        #[arg(long, default_value_t = 3)]
        window: usize,
    },
    /// Bandwidth soak: ALL configured servers pull from one shared queue.
    /// Proves aggregate throughput beyond any single provider's cap.
    Soak {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Total articles to pull (≈ 0.75 MB each).
        #[arg(long, default_value_t = 4000)]
        articles: usize,
        /// Connections PER SERVER.
        #[arg(long, default_value_t = 8)]
        connections: usize,
        #[arg(long, default_value_t = 4)]
        window: usize,
        /// Parallel yEnc decode workers.
        #[arg(long, default_value_t = 4)]
        decoders: usize,
        /// Independent tokio runtimes (each with its own I/O driver).
        #[arg(long, default_value_t = 3)]
        shards: usize,
        /// Socket receive buffer per connection, in MB (0 = kernel default).
        #[arg(long, default_value_t = 4)]
        rcvbuf_mb: u32,
    },
    /// Download an NZB end to end: pool → decode → write at final offsets.
    Get {
        nzb: PathBuf,
        /// Output directory.
        #[arg(long, default_value = "downloads")]
        out: PathBuf,
        /// Connections per server.
        #[arg(long, default_value_t = 8)]
        connections: usize,
        #[arg(long, default_value_t = 4)]
        window: usize,
        #[arg(long, default_value_t = 4)]
        decoders: usize,
        /// PAR2 verify mode. "lean" is the slow-CPU boost: like fast,
        /// but also skips per-article yEnc CRCs once PAR2 covers a
        /// file - corruption detection rests on the PAR2 block CRC32
        /// alone in-stream (one CRC32 layer instead of two; ~7% more
        /// single-core throughput). End-of-job verification and repair
        /// are unchanged, and PAR2-less files keep article CRCs.
        /// "fast" claims in-stream blocks by CRC32 only
        /// (each article's yEnc CRC already passed; 2.9× on CPU-bound
        /// boxes), "full" also MD5s every block. Settle read-back always
        /// hashes in full.
        #[arg(long, default_value = "fast")]
        verify: String,
        /// Sampled STAT sweep first; abort without downloading if the post
        /// can't possibly complete (missing > recovery everywhere).
        #[arg(long)]
        preflight: bool,
        /// Disable store-mode direct extraction (write RAR volumes to disk
        /// instead of extracting them in-stream).
        #[arg(long)]
        no_extract: bool,
        /// Archive password for encrypted RAR sets. Usually unnecessary:
        /// a `<meta type="password">` in the NZB or a `{{password}}`
        /// suffix in the NZB filename is picked up automatically.
        #[arg(long)]
        password: Option<String>,
    },
    /// Pre-flight availability check: pipelined STAT sweep across all
    /// servers; verdict COMPLETE / REPAIRABLE / IMPOSSIBLE without
    /// downloading a byte of payload.
    Check {
        nzb: PathBuf,
        /// Percentage of each file's segments to sample (100 = every one).
        #[arg(long, default_value_t = 100)]
        sample: u8,
        /// STAT connections per server.
        #[arg(long, default_value_t = 4)]
        connections: usize,
        /// Pipelined STATs in flight per connection.
        #[arg(long, default_value_t = 50)]
        window: usize,
    },
    /// Verify files in a directory against the PAR2 set found there.
    Verify { dir: PathBuf },
    /// Process an already-assembled directory offline: PAR2-repair from
    /// on-disk recovery (no network), then extract the RAR archives. The
    /// same repair+extract pipeline the daemon runs after a download,
    /// pointed at local files - the robustness-harness hook.
    Extract {
        /// Directory of assembled archive volumes (+ optional .par2 set).
        dir: PathBuf,
        /// Password for encrypted archives.
        #[arg(long)]
        password: Option<String>,
    },
    /// Per-stage CPU benchmark: where compute goes at line rate, and the
    /// machine's compute ceiling vs its network and disk.
    BenchCpu {
        /// MB of synthetic payload per stage.
        #[arg(long, default_value_t = 512)]
        mb: usize,
    },
    /// Full system benchmark: network + compute + disk → expected max
    /// download speed, the bottleneck, and a server-diversity report.
    Sysbench {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
    },
    /// Loopback ceiling bench server: a local NNTP server fast enough
    /// that the CLIENT is the bottleneck. Serves a synthetic release of
    /// any size from ~1 MB of RAM and writes the matching .nzb - point
    /// ANY newsreader client (nzbfast, NZBGet, SABnzbd, …) at it to
    /// measure that client's pipeline ceiling with no provider limits.
    Mockserve {
        #[arg(long, default_value_t = 1190)]
        port: u16,
        /// Bind address; 0.0.0.0 serves LAN clients too.
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Files in the synthetic release.
        #[arg(long, default_value_t = 16)]
        files: u32,
        /// Size of each file ("2G", "512M", …).
        #[arg(long, default_value = "2G")]
        file_size: String,
        /// Article payload size ("750K"…); ~740K matches real posts.
        #[arg(long, default_value = "740K")]
        article_size: String,
        /// Where to write the matching NZB.
        #[arg(long, default_value = "bench-loopback.nzb")]
        nzb: PathBuf,
        /// Serve a matching PAR2 index too (verify-only: no recovery
        /// slices). Gives the client real live-verify MD5/CRC load -
        /// required for any constrained-CPU bench to be representative.
        #[arg(long)]
        par2: bool,
        /// PEM cert chain; with --tls-key, serves implicit TLS (port-563
        /// shape) instead of plain TCP. Every provider is TLS, so the
        /// plain leg alone measures a path no real user is on. Make a
        /// pair with:
        ///   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem \
        ///     -out cert.pem -days 30 -subj /CN=localhost \
        ///     -addext subjectAltName=DNS:localhost,IP:127.0.0.1
        /// then point the client at it with NZBFAST_EXTRA_CA=cert.pem.
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// PEM private key matching --tls-cert.
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
    /// Scan group headers into the local release index (M12).
    Index {
        #[arg(long, default_value = "alt.binaries.teevee")]
        group: String,
        /// Articles to scan backwards from the newest (first run) -
        /// later runs resume from the stored high-water mark.
        #[arg(long, default_value_t = 500_000)]
        backfill: u64,
        /// Only index posts newer than this ("90d"/"26w"/"6m"/"2y";
        /// bare number = days; empty/0 = off). On a first scan this
        /// overrides --backfill: the group's article range is bisected
        /// by Date to find the cutoff, so old headers are never fetched.
        #[arg(long, default_value = "")]
        max_age: String,
        /// Ingest gates JSON - kinds/year/resolution/language/title/size
        /// filters applied before anything is stored (see gates.rs).
        #[arg(long)]
        gates: Option<PathBuf>,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Search the local release index.
    Search {
        query: String,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
        /// Write the NZB of the first hit to this path.
        #[arg(long)]
        nzb: Option<PathBuf>,
    },
    /// Scan a Spotnet group's spot headers (From-record parse + RSA verify)
    /// into the local index (M14j). Header-only pass - no article bodies.
    Spots {
        #[arg(long, default_value = "free.pt")]
        group: String,
        /// Articles to scan backwards from the newest (first run) -
        /// later runs resume from the stored high-water mark.
        #[arg(long, default_value_t = 100_000)]
        backfill: u64,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Search locally indexed spots by title.
    SpotSearch {
        query: String,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Fetch one spot's NZB payload (X-XML headers → alt.binaries.ftd
    /// segments → inflate) and write the NZB file.
    SpotGet {
        /// Spot message-id (angle brackets optional).
        msgid: String,
        #[arg(long, default_value = "out.nzb")]
        nzb: PathBuf,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Interactive setup: add/manage usenet servers, no file editing.
    /// Returns success to proceed; exits non-zero if you choose to quit.
    Setup,
    /// Stream an NZB immediately: enqueue it on the running daemon at
    /// Force priority and hand the OS default player the .m3u - watch
    /// while it downloads (M11).
    Stream {
        /// Path to a .nzb file, or an http(s) URL to one.
        nzb: String,
        /// Daemon to submit to.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 6789)]
        port: u16,
        /// API key (or NZB key), if the daemon requires one.
        #[arg(long)]
        apikey: Option<String>,
        /// Print the URLs only; don't launch the player.
        #[arg(long)]
        no_open: bool,
    },
    /// Run the download daemon: queue manager + watch folder + SABnzbd-
    /// compatible API (Sonarr/Radarr-ready).
    Serve {
        #[arg(long, default_value_t = 6789)]
        port: u16,
        /// Listen address. The default serves every interface, which is
        /// what a NAS/headless box with Sonarr or a phone remote on
        /// another host needs; use 127.0.0.1 to keep it to this machine.
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        /// Open the web dashboard in the default browser once the server
        /// is listening (the double-click launchers use this).
        #[arg(long)]
        open: bool,
        /// Require this API key on every request.
        #[arg(long)]
        apikey: Option<String>,
        /// Secondary add-only key (SABnzbd "NZB key"): may addfile/addurl
        /// but not read the queue or change settings.
        #[arg(long)]
        nzbkey: Option<String>,
        /// Completed downloads root (per-category subdirs).
        #[arg(long, default_value = "downloads")]
        out: PathBuf,
        /// Poll this folder for new .nzb files.
        #[arg(long)]
        watch: Option<PathBuf>,
        /// Post-processing script, run after every job with SABnzbd's
        /// positional args + SAB_* env vars (script ecosystem compatible).
        #[arg(long)]
        script: Option<PathBuf>,
        /// Pause new jobs when free space drops below this (e.g. 10G).
        #[arg(long)]
        min_free: Option<String>,
        /// Download quota per period, e.g. 100G (Force jobs bypass).
        #[arg(long)]
        quota: Option<String>,
        /// Quota period: d = daily, m = monthly (UTC boundaries).
        #[arg(long, default_value = "d")]
        quota_period: char,
        /// RSS feeds config (JSON list of {url, interval_secs, category,
        /// rules}) - items passing the rules are auto-downloaded.
        #[arg(long)]
        feeds: Option<PathBuf>,
        #[arg(long, default_value_t = 8)]
        connections: usize,
        #[arg(long, default_value_t = 4)]
        window: usize,
        #[arg(long, default_value_t = 6)]
        decoders: usize,
        /// Initial download speed cap, e.g. "4M" or "500K" (bytes/sec;
        /// bare numbers accepted). 0 = unlimited. Adjustable live via
        /// mode=config&name=speedlimit.
        #[arg(long)]
        speedlimit: Option<String>,
        /// Time-of-week scheduler: JSON file of {days, time, action,
        /// value} entries, evaluated once per minute in LOCAL time.
        #[arg(long)]
        schedule: Option<PathBuf>,
        /// Auto-adjust the speed cap to yield to other household traffic
        /// (RTT-governed, LEDBAT-style). Toggleable live via
        /// mode=config&name=auto_speed.
        #[arg(long)]
        auto_speed: bool,
        /// Categories whose jobs become metadata-only library entries
        /// (M14i): availability-checked, .strm written, downloaded on
        /// first playback of /stream/<nzo_id>.
        #[arg(long, value_delimiter = ',')]
        library_cats: Vec<String>,
        /// Re-verify parked library entries this often (seconds).
        #[arg(long, default_value_t = 21600)]
        library_recheck_secs: u64,
        /// Index database (newznab facade + dashboard browse).
        #[arg(long, default_value = "index.db")]
        index_db: PathBuf,
        /// Groups to OVER-scan continuously (comma-separated); the
        /// newznab endpoint serves whatever lands in the index.
        #[arg(long, value_delimiter = ',')]
        index_groups: Vec<String>,
        /// Seconds between incremental index scans.
        #[arg(long, default_value_t = 900)]
        index_interval: u64,
        /// Articles to backfill on a group's first scan.
        #[arg(long, default_value_t = 20000)]
        index_backfill: u64,
        /// Only index posts newer than this ("90d"/"6m"/"2y"; bare
        /// number = days; empty/0 = off). Overrides --index-backfill on
        /// a group's first scan via a Date bisection.
        #[arg(long, default_value = "")]
        index_max_age: String,
        /// Ingest gates JSON for the index scanner (see gates.rs).
        #[arg(long)]
        index_gates: Option<PathBuf>,
    },
    /// Import servers from a SABnzbd installation's sabnzbd.ini.
    ImportSab {
        /// Path to sabnzbd.ini (macOS: ~/Library/Application Support/SABnzbd/).
        ini: PathBuf,
        /// Where to write our config (default: the global --config path).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Upload files as yEnc posts to a test group and emit the matching
    /// NZB (ops tool; runbook: bench/nested-corpus/POSTING.md). Requires
    /// an explicit --post-server - posting never picks a server for you.
    Post {
        /// Files and/or directories (walked recursively) to post.
        paths: Vec<PathBuf>,
        /// The ONE configured server to post through (host, or host:port).
        /// Mandatory: there is no default.
        #[arg(long)]
        post_server: String,
        /// Where to write the NZB describing the post.
        #[arg(long, default_value = "posted.nzb")]
        nzb: PathBuf,
        /// Newsgroup to post into.
        #[arg(long, default_value = "alt.binaries.test")]
        group: String,
        /// From header value.
        #[arg(long, default_value = "corpus@nzbfast.com")]
        from: String,
        /// Message-ID domain (right-hand side of generated ids).
        #[arg(long, default_value = "corpus.nzbfast.com")]
        msgid_domain: String,
        /// Decoded payload bytes per article ("700K", "512K", …).
        #[arg(long, default_value = "700K")]
        article_size: String,
        /// Optional set title: subjects become
        /// `title [i/n] - "file" yEnc (p/t)`.
        #[arg(long)]
        title: Option<String>,
        /// Concurrent posting connections.
        #[arg(long, default_value_t = 4)]
        connections: usize,
        /// After posting, download the set back from the same server and
        /// hash it against the sources.
        #[arg(long)]
        verify: bool,
    },
    /// Build an NZB of one COMPLETE release (data + par2 main + volumes,
    /// one poster, shared filename stem) found via OVER - the full-pipeline
    /// test fixture generator.
    MakeReleaseNzb {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Minimum total release size.
        #[arg(long, default_value_t = 1.0)]
        min_gb: f64,
        /// Maximum total release size.
        #[arg(long, default_value_t = 15.0)]
        max_gb: f64,
        #[arg(long, default_value = "release.nzb")]
        out: PathBuf,
    },
    /// Build a real test NZB from complete multipart posts found via OVER.
    MakeTestNzb {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Number of complete files to include.
        #[arg(long, default_value_t = 3)]
        files: usize,
        /// Skip files larger than this.
        #[arg(long, default_value_t = 300)]
        max_file_mb: u64,
        #[arg(long, default_value = "test.nzb")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    nzbkit::disk::raise_fd_limit();
    let budget = match &cli.mem_limit {
        Some(v) => nzbkit::mem::MemBudget::with_total(
            serve::parse_size(v)
                .ok_or_else(|| anyhow::anyhow!("--mem-limit: can't parse size {v:?}"))?,
        ),
        None => nzbkit::mem::MemBudget::auto(),
    };
    // The repair paths run several layers below any command's call site and
    // need the same budget everything else honours.
    nzbkit::mem::set_process_budget(budget);
    match cli.command {
        Command::Inspect { nzb } => inspect(&nzb),
        Command::Probe => probe(&cli.config).await,
        Command::Stream {
            nzb,
            host,
            port,
            apikey,
            no_open,
        } => stream_cmd(&nzb, &host, port, apikey.as_deref(), no_open),
        Command::Bench {
            group,
            articles,
            connections,
            window,
            simultaneous,
            duration,
        } => {
            bench(
                &cli.config,
                &group,
                articles,
                connections,
                window,
                simultaneous,
                duration,
            )
            .await
        }
        Command::Fetch {
            group,
            articles,
            connections,
            window,
        } => fetch(&cli.config, &group, articles, connections, window).await,
        Command::Soak {
            group,
            articles,
            connections,
            window,
            decoders,
            shards,
            rcvbuf_mb,
        } => {
            soak(
                &cli.config,
                &group,
                articles,
                connections,
                window,
                decoders,
                shards,
                rcvbuf_mb,
            )
            .await
        }
        Command::Get {
            nzb,
            out,
            connections,
            window,
            decoders,
            verify,
            preflight,
            no_extract,
            password,
        } => {
            let (fast_verify, verify_lean) = match verify.as_str() {
                "fast" => (true, false),
                "full" => (false, false),
                // Lean: for slow CPUs. Skips the per-article yEnc CRC
                // once PAR2 covers a file - in-stream corruption is then
                // caught by the PAR2 block CRC32 alone (one CRC32 layer
                // instead of two). End-of-job verification and repair
                // are unchanged; PAR2-less downloads keep article CRCs.
                "lean" => (true, true),
                other => anyhow::bail!("--verify must be fast, full, or lean, not {other:?}"),
            };
            // M32 perf: CLI downloads have no /stream readers, so
            // dropping settled page cache is safe and saves real CPU on
            // small-RAM Linux boxes (see disk.rs maybe_drop_cache).
            #[cfg(target_os = "linux")]
            nzbkit::disk::set_drop_cache_default(true);
            if preflight {
                let verdict = check(&cli.config, &nzb, 10, 4, 50).await?;
                if let Verdict::Impossible { .. } = verdict {
                    anyhow::bail!("aborting: pre-flight says this post cannot complete");
                }
            }
            get_with_progress(
                &cli.config,
                &nzb,
                &out,
                connections,
                window,
                decoders,
                fast_verify,
                verify_lean,
                no_extract,
                password,
                None,
                None,
                "",
                None,
                budget,
            )
            .await
        }
        Command::ImportSab { ini, out, force } => {
            import_sab::import(&ini, out.as_deref().unwrap_or(&cli.config), force)
        }
        Command::BenchCpu { mb } => {
            bench_cpu(mb);
            Ok(())
        }
        Command::Sysbench { group } => sysbench_cmd(&cli.config, &group).await,
        Command::Mockserve {
            port,
            bind,
            files,
            file_size,
            article_size,
            nzb,
            par2,
            tls_cert,
            tls_key,
        } => {
            let fsize = serve::parse_size(&file_size)
                .ok_or_else(|| anyhow::anyhow!("bad --file-size {file_size:?}"))?;
            let asize = serve::parse_size(&article_size)
                .ok_or_else(|| anyhow::anyhow!("bad --article-size {article_size:?}"))?
                as usize;
            if par2 {
                println!("[benchserve] hashing the synthetic set for the PAR2 index …");
            }
            let set = std::sync::Arc::new(nzbkit::benchserve::BenchSet::with_par2(
                files, fsize, asize, par2,
            ));
            std::fs::write(&nzb, set.nzb())?;
            println!(
                "[benchserve] set: {} files × {:.2} GB = {:.2} GB{} · nzb: {}",
                files,
                fsize as f64 / 1e9,
                set.total_bytes() as f64 / 1e9,
                if par2 { " + par2 index" } else { "" },
                nzb.display()
            );
            let tls = match (&tls_cert, &tls_key) {
                (Some(c), Some(k)) => Some(nzbkit::benchserve::tls_config(c, k)?),
                (None, None) => None,
                _ => anyhow::bail!("--tls-cert and --tls-key must be given together"),
            };
            println!(
                "[benchserve] point any client at host {bind} port {port}, TLS {}, no auth\n\
                 [benchserve]   nzbfast: {{\"servers\":[{{\"host\":\"localhost\",\"port\":{port},\"tls\":{},\"connections\":16}}]}}\n\
                 [benchserve]   stats print every 10 s; Ctrl-C to stop",
                if tls.is_some() { "ON" } else { "OFF" },
                tls.is_some()
            );
            if tls.is_some() {
                println!(
                    "[benchserve]   self-signed: run the client with NZBFAST_EXTRA_CA=<cert.pem>"
                );
            }
            let stats_set = set.clone();
            tokio::spawn(async move {
                let (mut last_b, mut last_n) = (0u64, 0u64);
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    let b = stats_set.bytes.load(std::sync::atomic::Ordering::Relaxed);
                    let n = stats_set.served.load(std::sync::atomic::Ordering::Relaxed);
                    if b != last_b {
                        println!(
                            "[benchserve] {:>7.2} Gbps wire · {} articles ({} total)",
                            (b - last_b) as f64 * 8.0 / 10.0 / 1e9,
                            n - last_n,
                            n
                        );
                    }
                    (last_b, last_n) = (b, n);
                }
            });
            nzbkit::benchserve::serve_with(&format!("{bind}:{port}"), set, tls).await?;
            Ok(())
        }
        Command::Index { group, backfill, max_age, gates, db } => {
            let age = parse_age(&max_age)?;
            let gates = gates.as_deref().map(gates::Gates::load).transpose()?;
            index_scan(&cli.config, &group, backfill, age, gates.as_ref(), &db).await
        }
        Command::Post {
            paths,
            post_server,
            nzb,
            group,
            from,
            msgid_domain,
            article_size,
            title,
            connections,
            verify,
        } => {
            let asize = serve::parse_size(&article_size)
                .ok_or_else(|| anyhow::anyhow!("bad --article-size {article_size:?}"))?
                as usize;
            post_cmd::run(
                &cli.config,
                post_cmd::PostArgs {
                    paths,
                    post_server,
                    nzb,
                    group,
                    from,
                    msgid_domain,
                    article_size: asize,
                    title,
                    connections,
                    verify,
                },
            )
            .await
        }
        Command::Search { query, db, nzb } => search_index(&query, &db, nzb.as_deref()),
        Command::Spots { group, backfill, db } => {
            spots_scan(&cli.config, &group, backfill, &db).await
        }
        Command::SpotSearch { query, db } => spot_search(&query, &db),
        Command::SpotGet { msgid, nzb, db } => spot_get(&cli.config, &msgid, &nzb, &db).await,
        Command::Setup => {
            if setup::run(&cli.config)? {
                Ok(())
            } else {
                std::process::exit(3); // user chose Quit - launcher won't serve
            }
        }
        Command::Serve {
            port,
            bind,
            open,
            apikey,
            nzbkey,
            out,
            watch,
            script,
            min_free,
            quota,
            quota_period,
            feeds,
            connections,
            window,
            decoders,
            speedlimit,
            schedule,
            auto_speed,
            library_cats,
            library_recheck_secs,
            index_db,
            index_groups,
            index_interval,
            index_backfill,
            index_max_age,
            index_gates,
        } => {
            let size = |name: &str, v: Option<String>| -> Result<Option<u64>> {
                v.map(|s| {
                    serve::parse_size(&s)
                        .ok_or_else(|| anyhow::anyhow!("--{name}: can't parse size {s:?}"))
                })
                .transpose()
            };
            let opts = serve::ServeOpts {
                // Off unless the dashboard turns it on; settings.json
                // overrides this on load.
                group_desc_isc: false,
                port,
                bind,
                open,
                apikey,
                nzbkey,
                out_root: out,
                watch,
                script,
                connections,
                window,
                decoders,
                fast_verify: true,
                verify_lean: false,
                min_free: size("min-free", min_free)?,
                auto_retry_mins: 20,
                quota: size("quota", quota)?,
                quota_period,
                feeds,
                speedlimit,
                schedule,
                auto_speed,
                library_cats,
                library_recheck_secs,
                mem_budget: budget,
                index_db,
                index_groups,
                index_interval_secs: index_interval,
                index_backfill,
                index_max_age_secs: parse_age(&index_max_age)?,
                index_gates: index_gates.as_deref().map(gates::Gates::load).transpose()?,
            };
            serve::serve(cli.config.clone(), opts).await
        }
        Command::Check {
            nzb,
            sample,
            connections,
            window,
        } => {
            check(&cli.config, &nzb, sample, connections, window).await?;
            Ok(())
        }
        Command::Verify { dir } => {
            verify_dir(&dir)?;
            Ok(())
        }
        Command::Extract { dir, password } => {
            if extract_local(&dir, password.as_deref())? {
                Ok(())
            } else {
                std::process::exit(1);
            }
        }
        Command::MakeReleaseNzb {
            group,
            min_gb,
            max_gb,
            out,
        } => make_release_nzb(&cli.config, &group, min_gb, max_gb, &out).await,
        Command::MakeTestNzb {
            group,
            files,
            max_file_mb,
            out,
        } => make_test_nzb(&cli.config, &group, files, max_file_mb, &out).await,
    }
}

// ---------------------------------------------------------------------------
// check - pre-flight availability (M2): STAT sweep + verdict
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Complete,
    Repairable { est_missing: usize, recovery: usize },
    Impossible { est_missing: usize, recovery: usize },
}

pub(crate) async fn check(
    config: &PathBuf,
    nzb_path: &PathBuf,
    sample_pct: u8,
    connections: usize,
    window: usize,
) -> Result<Verdict> {
    use nzbkit::preflight::{stat_sweep, stratified_sample};

    let cfg_all = Config::load(config)?;
    let xml = std::fs::read(nzb_path).with_context(|| format!("reading {}", nzb_path.display()))?;
    let nzb = Nzb::parse(&xml).context("parsing NZB")?;

    // Sampled ids from DATA + par2-main files (recovery volumes count via
    // the recovery budget, not the deficit) + per-id weight = how many
    // segments each sampled id represents in its file.
    let mut ids: Vec<String> = Vec::new();
    let mut weights: Vec<f64> = Vec::new();
    let mut file_of: Vec<usize> = Vec::new();
    for (fi, f) in nzb.files.iter().enumerate() {
        if f.kind() == FileKind::Par2Volume {
            continue;
        }
        let n = f.segments.len();
        let take = if sample_pct >= 100 {
            n
        } else {
            ((n * sample_pct as usize).div_ceil(100)).max(2.min(n))
        };
        for si in stratified_sample(n, take) {
            ids.push(format!("<{}>", f.segments[si].message_id));
            weights.push(n as f64 / take as f64);
            file_of.push(fi);
        }
    }
    let recovery: usize = nzb
        .files
        .iter()
        .filter_map(|f| vol_count_from_name(f.filename_hint().unwrap_or(&f.subject)))
        .sum();
    println!(
        "pre-flight: STAT {} article(s) ({}% sample) × {} server(s), {} conns × window {}",
        ids.len(),
        sample_pct.min(100),
        cfg_all.servers.len(),
        connections,
        window
    );

    let sweep = stat_sweep(&cfg_all.servers, &ids, connections, window).await;
    for (si, s) in cfg_all.servers.iter().enumerate() {
        let (have, missing, unknown) = sweep.server_counts(si);
        println!(
            "  {:<28} {:>5.1}% available ({have} have, {missing} missing{})",
            s.host,
            have as f64 * 100.0 / ids.len().max(1) as f64,
            if unknown > 0 {
                format!(", {unknown} unknown")
            } else {
                String::new()
            }
        );
    }

    let missing = sweep.union_missing();
    let est_missing: f64 = missing.iter().map(|&i| weights[i]).sum();
    let est_missing = est_missing.round() as usize;
    let mut missing_files: std::collections::BTreeMap<usize, usize> = Default::default();
    for &i in &missing {
        *missing_files.entry(file_of[i]).or_default() += 1;
    }
    for (fi, count) in &missing_files {
        let f = &nzb.files[*fi];
        println!(
            "  ✘ {}: {count} of {} sampled segment(s) missing on every server",
            f.filename_hint().unwrap_or(&f.subject),
            f.segments
                .len()
                .min((f.segments.len() * sample_pct.min(100) as usize).div_ceil(100).max(2)),
        );
    }

    // Verdict in article units (block ≈ article for typical posts; the
    // live ledger is exact once the par2 main packet is in hand).
    let verdict = if est_missing == 0 {
        Verdict::Complete
    } else if est_missing <= recovery {
        Verdict::Repairable {
            est_missing,
            recovery,
        }
    } else {
        Verdict::Impossible {
            est_missing,
            recovery,
        }
    };
    match &verdict {
        Verdict::Complete => println!(
            "verdict: COMPLETE - every sampled article present on at least one server ({:.2?})",
            sweep.elapsed
        ),
        Verdict::Repairable {
            est_missing,
            recovery,
        } => println!(
            "verdict: REPAIRABLE - ≈{est_missing} article(s) missing everywhere ≤ {recovery} recovery block(s) ({:.2?})",
            sweep.elapsed
        ),
        Verdict::Impossible {
            est_missing,
            recovery,
        } => println!(
            "verdict: IMPOSSIBLE - ≈{est_missing} article(s) missing everywhere > {recovery} recovery block(s) ({:.2?})",
            sweep.elapsed
        ),
    }
    Ok(verdict)
}

// ---------------------------------------------------------------------------
// verify - PAR2 verification of a directory (M2; also runs after `get`)
// ---------------------------------------------------------------------------

/// Returns Ok(true) if a PAR2 set was found and every present file verified.
/// Offline repair+extract of an assembled directory (no network). Mirrors
/// the daemon's post-download tail: PAR2-repair from on-disk recovery, then
/// extract RAR archives (native first, unrar and recovery-record repair as
/// fallbacks). Returns whether the directory ended in a usable state:
/// extracted payload for an archive set, or verified/repaired data files
/// when the set is bare files under PAR2 with nothing to unpack.
pub(crate) fn extract_local(dir: &std::path::Path, password: Option<&str>) -> Result<bool> {
    use nzbkit::par2repair::{RepairStatus, repair_dir};

    // --- Phase 1: PAR2 repair (only if a set is present) ---------------
    // Detect the set by `.par2` name OR the `PAR2\0PKT` packet magic:
    // obfuscated posts rename recovery volumes to extensionless hex, and
    // repair_dir already magic-sniffs packets and restores data files
    // under their true FileDesc names (it also hash-matches obfuscated
    // data files during the adoption scan), so the only thing that ever
    // hid an obfuscated set from repair was this gate checking the name.
    let has_par2 = dir_has_par2(dir)?;
    let mut par2_ok = true;
    if has_par2 {
        match repair_dir(dir) {
            Ok(RepairStatus::NoDamage) => println!("PAR2: no damage, set verifies ✔"),
            Ok(RepairStatus::Repaired(r)) => {
                println!(
                    "PAR2: repaired ✔ ({} block(s) rebuilt, {} adopted, {} file(s) patched)",
                    r.blocks_rebuilt,
                    r.blocks_adopted,
                    r.files_patched.len()
                );
            }
            Ok(RepairStatus::Unrepairable { needed, have }) => {
                println!("PAR2: UNREPAIRABLE - need {needed} recovery block(s), have {have}");
                par2_ok = false;
            }
            Err(e) => {
                println!("PAR2: repair error - {e}");
                par2_ok = false;
            }
        }
    }

    // --- Phase 2: extract archives (if any), then recurse into any
    //     archive those produced (nested releases go a few deep) ----------
    // A payload we cannot actually produce must fail loudly (rc=1), never
    // exit 0 leaving the wrong bytes on disk - that guarantee is what lets
    // the daemon trust an "extract succeeded".
    //
    // The one softening: a zip we cannot unpack fails only when it IS the
    // payload. A `Subs/subs.zip` beside a feature that unpacked fine is
    // reported and forgiven - the descent that now finds subfolder zips
    // would otherwise turn a great many complete releases into rc=1. The
    // softening keys off the pass's own cause, never off "is there a zip
    // anywhere": a failed RAR/7z beside an unrelated sidecar zip is a
    // payload we did not produce, and must still fail.
    let archives_ok = match extract_nested(dir, password, 0)? {
        NestOutcome::Produced => true,
        NestOutcome::ZipGap => match unsupported_archive_present(dir) {
            Some(u) => {
                println!("{}", u.message());
                !u.blocking
            }
            None => false,
        },
        NestOutcome::Failed => false,
    };
    Ok(par2_ok && archives_ok)
}

/// How an extraction pass ended. The CAUSE travels with the failure
/// because exactly one cause may ever be forgiven - the documented zip
/// gap - and only the pass itself knows which archive stopped it. Deriving
/// it afterwards from a directory scan let an unrelated `Subs/subs.zip`
/// absolve a failed RAR/7z, completing the job with nothing importable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum NestOutcome {
    /// Nothing left packed, or there was nothing to unpack at all.
    Produced,
    /// The pass stopped at a zip - the known gap. The caller may forgive
    /// this one, and only when the zip is a sidecar rather than the payload.
    /// Reported only once everything ELSE in the tree was attempted and
    /// produced: a level that hits a zip still descends into the
    /// subdirectories it was seeded with, so an archive we support but could
    /// not unpack outranks the gap with `Failed`.
    ZipGap,
    /// An archive we do support could not be produced. Never forgivable.
    Failed,
}

impl NestOutcome {
    fn produced(self) -> bool {
        self == NestOutcome::Produced
    }
    /// A pass's own result for a format we support.
    fn from_produced(ok: bool) -> Self {
        if ok { NestOutcome::Produced } else { NestOutcome::Failed }
    }
    /// Combine sibling/child results: a hard failure outranks a zip gap,
    /// which outranks success.
    fn and(self, other: Self) -> Self {
        use NestOutcome::*;
        match (self, other) {
            (Failed, _) | (_, Failed) => Failed,
            (ZipGap, _) | (_, ZipGap) => ZipGap,
            _ => Produced,
        }
    }
}

/// Extract the archives in `dir`, then recurse into any archive that
/// extraction just produced (a nested release: a RAR whose payload is one
/// more RAR/7z, occasionally in a release subfolder). Returns `Produced`
/// when there was nothing to extract (the data files ARE the payload) or
/// every archive present was fully produced; otherwise the cause that
/// stopped it. Bounded to [`nzbkit::extract::nested_depth_cap`]
/// passes (the shared daemon `nested_max_depth` setting); at the cap the
/// deepest layer is left materialized on disk and the job still succeeds -
/// the design guarantee that a too-deep chain degrades, never fails.
fn extract_nested(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
) -> Result<NestOutcome> {
    use nzbkit::extract::release_stem;
    // Nested-level PAR2 repair - the per-level twin of extract_local's
    // phase 1. A poster can pack [damaged inner volumes + the inner
    // .par2 set that fixes them] INSIDE the outer archive; when that
    // layer lands here (unpacked by the pass above, or materialized by
    // a nested-extraction demotion), its recovery set must run before
    // the extraction attempt or the level fails with the cure sitting
    // next to the disease. Depth 0 is the top level extract_local
    // already repaired; the archive gate keeps a bare-file payload
    // (data + its recovery set, nothing packed) from being re-hashed -
    // that set was settled by the stream/top-level pass. Runs before
    // the `before` snapshot so recreated/adopted files count as this
    // level's input, never as freshly-produced nested archives.
    if depth > 0 && dir_has_nested_extractable(dir)? {
        nested_par2_repair(dir);
    }
    let before = snapshot_recursive(dir)?;
    // Volume-set stems present before this pass: a volume REBUILT during
    // extraction (.rev reconstruction, RR repair) lands in the diff as a
    // "new" file but belongs to the outer set - never descend into it.
    let pre_stems: std::collections::HashSet<String> = before
        .iter()
        .filter(|p| looks_like_named_rar(p))
        .filter_map(|p| p.file_name().map(|n| release_stem(&n.to_string_lossy())))
        .collect();
    // Magic-only (obfuscated) outer volumes have no name grammar for the
    // stem guard above, so remember whether the input set held any: a
    // NEW extensionless Rar!-magic file appearing beside such a set is a
    // rebuilt member of it (.rev/RR output), not a nested archive -
    // archives a pass genuinely produces carry their packed names.
    let pre_obfuscated = before
        .iter()
        .any(|p| !looks_like_named_rar(p) && rar_magic(p));
    let is_new_nested_archive = |p: &PathBuf| {
        if !is_extractable_archive(p) {
            return false;
        }
        if looks_like_named_rar(p) {
            let stem = p
                .file_name()
                .map(|n| release_stem(&n.to_string_lossy()))
                .unwrap_or_default();
            if pre_stems.contains(&stem) {
                return false; // rebuilt member of the outer set
            }
        } else if pre_obfuscated && rar_magic(p) {
            return false; // rebuilt member of the obfuscated outer set
        }
        true
    };
    // Subdirectories that ALREADY hold an extractable archive when this
    // pass starts. The after/before diff below only finds archives a pass
    // PRODUCED - but an on-disk unpack writes its entry paths as real
    // subdirectories (the in-stream extractor flattens them), so a nested
    // archive can sit in a subfolder before any pass here ran (CD1/CD2
    // layouts, a fallback unpack's subfoldered payload). Seed the
    // recursion with the TOPMOST such dirs only: each seeded call
    // snapshots its own subtree and seeds deeper pre-existing layers
    // itself, so nothing is entered twice. Our scratch dirs (parked
    // leftover volumes, the nest staging dir) are never seeded. Named-RAR
    // matching is by NAME (like the nested PAR2 gate): a volume whose
    // signature bytes were destroyed still needs its subdir visited for
    // the repair chance.
    let pre_sub_dirs: Vec<PathBuf> = {
        let mut dirs: Vec<PathBuf> = before
            .iter()
            .filter(|p| looks_like_named_rar(p) || is_extractable_archive(p))
            .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
            .filter(|d| d.as_path() != dir)
            .filter(|d| {
                d.strip_prefix(dir).is_ok_and(|rel| {
                    !rel.components().any(|c| {
                        c.as_os_str().to_string_lossy().starts_with(".nzbfast")
                    })
                })
            })
            .collect();
        dirs.sort();
        dirs.dedup();
        let all: std::collections::HashSet<PathBuf> = dirs.iter().cloned().collect();
        dirs.retain(|d| !d.ancestors().skip(1).any(|a| all.contains(a)));
        dirs
    };
    // This level's INPUT archives, decided before anything unpacks. The
    // list is drawn from `before`, but `is_extractable_archive` asks the
    // disk, so evaluating it after the extraction would describe what is
    // left rather than what arrived - and `sweep_spent_entry` below turns
    // "how many release sets were here" into a delete. The obfuscated
    // extractor now removes the volumes IT consumed, so an unswept
    // `Rar!`-magic file beside them (a `.rev`) would be the lone survivor
    // and read as "exactly one set present": the guard that exists to
    // refuse ambiguity would have deleted the recovery data instead.
    let entry_archives: Vec<PathBuf> = before
        .iter()
        .filter(|p| p.parent() == Some(dir) && is_extractable_archive(p))
        .cloned()
        .collect();
    let top = extract_one_level(dir, password, depth)?;
    if top == Some(NestOutcome::Failed) {
        // A format we support, present and not produced -> loud fail.
        // Nothing deeper can redeem it, so stop here.
        return Ok(NestOutcome::Failed);
    }
    // A zip gap is the ONE forgivable cause, so it may only be reported once
    // the rest of the tree has actually been ATTEMPTED. `extract_one_level`
    // sees a single level: returning here would name the forgivable zip while
    // a supported archive sat untouched in a pre-existing subfolder, and the
    // caller's sidecar test would then forgive on the strength of a
    // still-packed `.rar` nobody ever tried. Carry the gap through the
    // descent instead - anything down there we cannot produce outranks it.
    let mut ok = top.unwrap_or(NestOutcome::Produced);
    if top.is_none() && pre_sub_dirs.is_empty() {
        return Ok(NestOutcome::Produced); // no archive anywhere: repaired data is the payload
    }
    // Directories that gained an extractable archive during this pass are
    // the nested layers. The outer volumes stay in `before`, so they are
    // never re-processed.
    // Spent-intermediate sweep: an archive we were handed at this level and
    // then fully denested (its payload now sits beside it) is disposable
    // furniture; leaving it behind is what stranded `level2.rar,level3.rar`
    // on disk after a password-chain nest. `depth >= 1` is the safety gate:
    // depth 0 is the user's actual downloaded set (or an offline `extract`
    // target) - never swept here, its retention is finalize/policy's call -
    // whereas a deeper level is only ever reached because an outer pass
    // (or the in-stream store extractor) already produced these archives,
    // so they ARE intermediates. Runs only on a fully-successful denest;
    // a partial failure keeps every volume for a manual retry. Captured
    // from `before` (the input set), whose files the Case A dance leaves in
    // place, so these paths stay valid at sweep time. Only top-level input
    // archives - a pre-existing SUBFOLDER archive (a `pre_sub_dirs` seed)
    // is swept when its own recursion reaches it as that level's input.
    // `entry_archives` is captured above, before the extraction runs.
    let sweep_spent_entry = |succeeded: bool| {
        if !succeeded || depth == 0 || entry_archives.is_empty() {
            return;
        }
        use std::collections::HashSet;
        let stems: HashSet<String> = entry_archives
            .iter()
            .filter_map(|a| a.file_name())
            .map(|n| release_stem(&n.to_string_lossy()))
            .collect();
        // Exactly one release set present: extract_one_level denested it in
        // full, so every volume is spent. Two independent sets (unusual for
        // a nested release) can't both be proven consumed - keep them all.
        if stems.len() != 1 {
            return;
        }
        let stem = stems.into_iter().next().unwrap_or_default();
        // The spent archive volumes, plus any recovery/verification sidecar
        // for THIS set (`.par2`/`.sfv`/`.rev` sharing the stem). A par2 for a
        // different stem - e.g. the outer post's own `a3.par2` riding along
        // beside a `level2.rar` - has a different stem and is left alone.
        for p in entry_archives.iter().cloned().chain(
            before
                .iter()
                .filter(|p| p.parent() == Some(dir))
                .filter(|p| {
                    p.extension()
                        .map(|e| e.to_string_lossy().to_ascii_lowercase())
                        .is_some_and(|e| matches!(e.as_str(), "par2" | "sfv" | "rev"))
                })
                .filter(|p| {
                    p.file_name()
                        .map(|n| release_stem(&n.to_string_lossy()) == stem)
                        .unwrap_or(false)
                })
                .cloned(),
        ) {
            if std::fs::remove_file(&p).is_ok() {
                println!("[nest] removed spent intermediate {}", p.display());
            }
        }
    };

    let after = if top == Some(NestOutcome::Produced) {
        snapshot_recursive(dir)?
    } else {
        before.clone() // nothing extracted at this level: empty diff
    };
    let cap = nzbkit::extract::nested_depth_cap();
    if depth + 1 >= cap {
        // Depth cap reached. Anything still packed here - an archive this
        // pass produced, or a pre-existing subfolder archive we would
        // otherwise descend into - is the deepest reached layer, already
        // materialized on disk as a healthy archive. The design guarantee
        // is that a chain deeper than the cap degrades to a materialized
        // deepest layer, NEVER a failed job - so we warn (naming what was
        // left, and how to go deeper) and succeed. The disk post-pass
        // already treats a materialized archive as valid output; the caller
        // must not propagate a hard failure here.
        let mut leftover: Vec<String> = after
            .difference(&before)
            .filter(|p| is_new_nested_archive(p))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        for d in &pre_sub_dirs {
            if let Some(name) = d.file_name() {
                leftover.push(format!("{}/", name.to_string_lossy()));
            }
        }
        if !leftover.is_empty() {
            leftover.sort();
            leftover.dedup();
            println!(
                "⚠ nested archives deeper than {cap} levels - deepest layer left \
                 materialized on disk ({}); raise the nested_max_depth setting to unpack further",
                leftover.join(", ")
            );
        }
        // A zip gap carried in from this level outlives the cap: a packed
        // deepest layer is acceptable output, an unpackable zip is still the
        // caller's call. Passing `ok` also keeps the sweep off a zip that
        // this level never spent.
        sweep_spent_entry(ok.produced());
        return Ok(ok);
    }
    let mut inner_dirs: Vec<PathBuf> = after
        .difference(&before)
        .filter(|p| is_new_nested_archive(p))
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();
    inner_dirs.extend(pre_sub_dirs);
    inner_dirs.sort();
    inner_dirs.dedup();

    for idir in inner_dirs {
        if idir == dir {
            // An inner archive at the top level shares the directory with
            // the outer volume set - move just this pass's new top-level
            // files into a scratch subdir so the inner whole-dir scan can't
            // see the outer set, extract there, then lift the results back.
            // A scratch directory this call PROVABLY created.
            //
            // This used to be a fixed `.nzbfast-nest` preceded by an
            // unconditional `remove_dir_all`. The recursive snapshot skips
            // `.nzbfast*`, so a legitimate archive payload extracted to
            // `.nzbfast-nest/` was invisible to every protection and simply
            // deleted the moment a sibling `inner.rar` triggered nesting.
            // `create_dir` fails if the path exists at all, so we can never
            // adopt - or destroy - something that was already there.
            let sub = {
                let mut made = None;
                for n in 0..1024 {
                    let candidate = match n {
                        0 => dir.join(".nzbfast-nest"),
                        n => dir.join(format!(".nzbfast-nest{n}")),
                    };
                    match std::fs::create_dir(&candidate) {
                        Ok(()) => {
                            made = Some(candidate);
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
                made.ok_or_else(|| {
                    anyhow::anyhow!("no free nest scratch name in {}", dir.display())
                })?
            };
            for p in snapshot_files(dir)? {
                // Move this pass's output only - and never a rebuilt member
                // of the outer volume set (.rev/RR repairs land in the diff
                // too, but they belong beside their siblings).
                let rebuilt_outer = looks_like_named_rar(&p)
                    && p.file_name()
                        .map(|n| pre_stems.contains(&release_stem(&n.to_string_lossy())))
                        .unwrap_or(false);
                if !before.contains(&p) && !rebuilt_outer {
                    if let Some(name) = p.file_name() {
                        let _ = std::fs::rename(&p, sub.join(name));
                    }
                }
            }
            ok = ok.and(extract_nested(&sub, password, depth + 1)?);
            if lift_nest_outputs(&sub, dir) {
                let _ = std::fs::remove_dir_all(&sub);
            } else {
                // Never sweep a scratch dir that still holds payload - a
                // swallowed rename here once deleted the stranded output
                // and reported success.
                println!(
                    "⚠ nest lift-back incomplete - keeping {} in place",
                    sub.display()
                );
                ok = ok.and(NestOutcome::Failed);
            }
        } else {
            // A fresh subdir holds only this pass's output - safe to recurse
            // in place (the outer volumes are elsewhere).
            ok = ok.and(extract_nested(&idir, password, depth + 1)?);
        }
    }
    // The nested layer(s) this level held are now denested (or not, if a
    // deeper level failed): sweep the spent input archives on full success.
    sweep_spent_entry(ok.produced());
    Ok(ok)
}

/// Move everything the nest scratch dir holds up into `dir`.
fn lift_nest_outputs(sub: &std::path::Path, dir: &std::path::Path) -> bool {
    lift_scratch_into(sub, dir, "nested", "nest lift-back")
}

/// Move everything scratch dir `sub` holds up into `dir`. Directories
/// merge recursively (an unpack can produce a subdir that already exists
/// at the top level - a blind rename fails ENOTEMPTY and used to be
/// swallowed right before the scratch sweep deleted the stranded
/// payload); a file that would land on a pre-existing path gets a
/// `{prefix}-N-` name instead of silently replacing output (or an outer
/// volume); a move that fails leaves the entry where it is and returns
/// false so the caller keeps the scratch dir instead of sweeping it.
///
/// Never replacing a pre-existing path is what makes this safe as the
/// publish step for `ExtractStaging`: it protects the source volumes,
/// `.rev` volumes, PAR2 sets and password sidecars an archive member
/// could be named after, without any list of protected names - and it
/// asks the filesystem, so a case-insensitive volume (macOS, Windows)
/// reports `release.RAR` as colliding with `release.rar` on its own.
fn lift_scratch_into(
    sub: &std::path::Path,
    dir: &std::path::Path,
    prefix: &str,
    what: &str,
) -> bool {
    let entries = match std::fs::read_dir(sub) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let mut clean = true;
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().map(|n| n.to_os_string()) else {
            clean = false;
            continue;
        };
        let target = dir.join(&name);
        if e.file_type().is_ok_and(|t| t.is_dir()) && target.is_dir() {
            clean &= lift_scratch_into(&p, &target, prefix, what);
            // Only an emptied source dir goes; a stranded entry keeps it.
            clean &= std::fs::remove_dir(&p).is_ok();
            continue;
        }
        // symlink_metadata, not exists(): a dangling symlink at the target
        // is still an occupied name, and a rename onto it would replace the
        // link rather than reveal what it pointed at.
        let dest = if target.symlink_metadata().is_ok() {
            let mut n = 1usize;
            loop {
                let cand = dir.join(format!("{prefix}-{n}-{}", name.to_string_lossy()));
                if cand.symlink_metadata().is_err() {
                    break cand;
                }
                n += 1;
            }
        } else {
            target
        };
        if let Err(err) = std::fs::rename(&p, &dest) {
            println!("⚠ {what}: {} → {}: {err}", p.display(), dest.display());
            clean = false;
        }
    }
    clean
}

/// An isolated directory that holds extractor output until the whole set
/// has been produced, then publishes it into the job directory. Removed
/// on drop, so an extraction that fails part-way leaves nothing behind.
///
/// Extraction cannot write straight into the directory it reads from. A
/// parsed archive keeps PATH-backed sources and reopens each volume for
/// every range it needs (`ArchiveSource::File` in the vendored rars), so
/// an archive member named after one of those volumes - `release.rar`,
/// `release.part02.rar`, a `release.7z` inside `release.7z` - would
/// truncate the very file the decoder is still reading, fail the
/// extraction midstream, and hand an already-destroyed set to the unrar
/// fallback. Both the volume names and the member names come from the
/// post, so both are attacker-chosen.
///
/// A denylist of protected names cannot close that: `.rev` recovery
/// volumes, PAR2 sets and password sidecars are inputs too. Staging
/// removes the whole class instead. `sanitized_entry_path` rejects `..`,
/// absolute paths and drive prefixes, so every output resolves strictly
/// inside the staging dir - and no input is ever inside it, because it is
/// created empty for this one extraction.
struct ExtractStaging {
    dir: PathBuf,
    /// Publish left payload behind: the caller is failing, and the dir
    /// must survive for the operator instead of being swept.
    keep: bool,
}

impl ExtractStaging {
    /// Create a fresh staging dir INSIDE `dir`. Same filesystem on
    /// purpose: publishing is then a rename rather than a copy, and the
    /// decompression-bomb guard's `free_bytes` still measures the volume
    /// the payload actually lands on. The `.nzbfast` prefix is what the
    /// nested pass's tree walkers already skip as scratch.
    fn new(dir: &std::path::Path) -> Result<ExtractStaging> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let sub = dir.join(format!(".nzbfast-extract-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sub);
        std::fs::create_dir_all(&sub)?;
        Ok(ExtractStaging { dir: sub, keep: false })
    }

    fn path(&self) -> &std::path::Path {
        &self.dir
    }

    /// Did the extractor put anything here? Used by the unrar fallback,
    /// whose output directory is an argument we hand to another process:
    /// "exited 0 but wrote nothing" must read as failure, not as an
    /// extraction that produced an empty release.
    fn produced_anything(&self) -> bool {
        std::fs::read_dir(&self.dir).is_ok_and(|mut d| d.next().is_some())
    }

    /// Move the produced set into `dest`. A produced name that collides
    /// with anything already there is disambiguated rather than replacing
    /// it, so an archive that legitimately carries a member named like one
    /// of its own volumes yields both the member and the intact volume.
    fn publish_into(mut self, dest: &std::path::Path) -> Result<()> {
        if lift_scratch_into(&self.dir, dest, "extracted", "publishing extraction") {
            return Ok(()); // drop removes the emptied dir
        }
        self.keep = true;
        anyhow::bail!(
            "extracted output could not be published into {} - it is left in {}",
            dest.display(),
            self.dir.display()
        )
    }
}

impl Drop for ExtractStaging {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Ceiling on password candidates tested per level. Each candidate costs
/// one PBKDF2-HMAC-SHA256 derivation (2^lg2 rounds - intentionally slow),
/// so the cap bounds the KDF work a crafted post can force: fifty
/// candidates at the common 2^15 count run well under a second, and a real
/// password sidecar carries one line, not fifty.
const MAX_PW_CANDIDATES: usize = 50;

/// Largest text sidecar scanned for passwords. A real password note
/// (.txt/.nfo/.diz) is tiny; a multi-megabyte "nfo" is a payload file, not
/// a hint, and re-reading it at every level would be unbounded work.
const PW_SIDECAR_MAX: u64 = 64 * 1024;

/// KDF-depth ceiling for UNSTRUCTURED candidates (sidecar lines, file
/// stems - anything a crafted post can mass-produce). The iteration
/// count comes from the archive header, so a hostile archive can demand
/// 2^24 rounds (~10 s of PBKDF2 per candidate) and turn the candidate
/// sweep into minutes of CPU. Above this depth only the job's own
/// password is tried; the archive keeps today's park/unrar path on a
/// miss. 2^19 keeps the full 50-candidate sweep in low single-digit
/// seconds while covering every count real archivers emit by default.
const PW_KDF_MAX_LG2: u8 = 19;

/// Wall-clock ceiling for one level's whole candidate sweep - the
/// total-work backstop for costs the header does not advertise (the 7z
/// probe decodes up to 64 MB per candidate).
const PW_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// May this candidate pay for a KDF this deep? Structured candidates
/// (the operator-supplied job password) always may; harvested ones only
/// up to [`PW_KDF_MAX_LG2`].
fn kdf_candidate_allowed(lg2_count: u8, structured: bool) -> bool {
    structured || lg2_count <= PW_KDF_MAX_LG2
}

/// A harvested password candidate and where it came from (for the unlock
/// log line: knowing the source file is the whole point of the chain).
/// `structured` marks the operator-supplied job password - the one
/// source a crafted post cannot mass-produce - which alone is exempt
/// from the KDF-depth gate.
struct PwCandidate {
    value: String,
    source: String,
    structured: bool,
}

/// Harvest bounded password candidates from a level's on-disk siblings -
/// the nested password-chain unlock, where level k's extraction drops
/// level k+1's password in a text file beside it. Sources, most-likely
/// first: the job's own password (M24 ordering, resolved upstream), then
/// trimmed lines of small .txt/.nfo/.diz sidecars, then the release stem
/// and sibling file stems. Deduped and capped at [`MAX_PW_CANDIDATES`].
fn harvest_password_candidates(dir: &std::path::Path, provided: Option<&str>) -> Vec<PwCandidate> {
    use nzbkit::extract::release_stem;
    let mut out: Vec<PwCandidate> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut push = |value: &str, source: &str, structured: bool, out: &mut Vec<PwCandidate>| {
        let v = value.trim();
        // A password line, not a paragraph of prose or a binary blob.
        if v.is_empty() || v.chars().count() > 128 || v.contains(['\r', '\n', '\0']) {
            return;
        }
        if out.len() < MAX_PW_CANDIDATES && seen.insert(v.to_string()) {
            out.push(PwCandidate {
                value: v.to_string(),
                source: source.to_string(),
                structured,
            });
        }
    };

    if let Some(p) = provided {
        push(p, "job password", true, &mut out);
    }

    // Small text sidecars: each line is a candidate, and a "password: xxx"
    // / "pass = xxx" line also yields its tail (poster notes vary).
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in &entries {
        let is_sidecar = path.extension().is_some_and(|x| {
            let x = x.to_string_lossy().to_lowercase();
            x == "txt" || x == "nfo" || x == "diz"
        });
        if !is_sidecar {
            continue;
        }
        // symlink_metadata: a planted link must not pull text from
        // outside the job dir (or size-check a different file than the
        // one read below).
        let readable = std::fs::symlink_metadata(path)
            .map(|m| m.is_file() && m.len() <= PW_SIDECAR_MAX)
            .unwrap_or(false);
        if !readable {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        let fname = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        for line in text.lines() {
            push(line, &fname, false, &mut out);
            if let Some(tail) = strip_password_label(line) {
                push(tail, &fname, false, &mut out);
            }
            if out.len() >= MAX_PW_CANDIDATES {
                break;
            }
        }
    }

    // Release stem and sibling file stems: some posters use the release
    // name (or a same-named marker file) as the password.
    for path in &entries {
        if let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) {
            let stem = release_stem(&name);
            push(&stem, "release/sibling stem", false, &mut out);
        }
        if out.len() >= MAX_PW_CANDIDATES {
            break;
        }
    }

    out
}

/// If `line` reads like `password: xxx` / `pass = xxx` / `pw - xxx`,
/// return the trimmed value after the label; else None.
fn strip_password_label(line: &str) -> Option<&str> {
    let t = line.trim();
    let lower = t.to_ascii_lowercase();
    for label in ["password", "passwort", "pass", "pwd", "pw"] {
        if let Some(rest) = lower.strip_prefix(label) {
            let rest = rest.trim_start();
            if let Some(after) = rest.strip_prefix([':', '=', '-']) {
                // Map the offset in `lower` back onto `t` (same length -
                // ASCII lowercasing preserves byte positions).
                let cut = t.len() - after.len();
                let val = t[cut..].trim();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// The first RAR volume in `dir` that needs a password (named or
/// magic-bearing). Any volume of an encrypted set carries the crypt
/// record - a multi-volume set repeats it in every volume's header - so
/// the first match is enough to probe candidates.
fn first_encrypted_rar(dir: &std::path::Path) -> Option<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths.into_iter().find(|p| {
        (looks_like_named_rar(p) || rar_magic(p)) && nzbkit::rar::needs_password(p)
    })
}

/// Does this 7z container open AND decode its first file entry with
/// `password`? Header-encrypted archives fail to open on a wrong
/// password; data-encrypted ones open with plaintext headers and only
/// fail on decode, so the first real entry's bytes are pulled (bounded,
/// to a sink) to force the AES/decompress failure before we trust it.
fn sevenz_password_opens(container: &std::path::Path, password: Option<&str>) -> bool {
    use sevenz_rust2::{ArchiveReader, Password};
    let pw = match password {
        Some(p) if !p.is_empty() => Password::from(p),
        _ => Password::empty(),
    };
    let Ok(mut reader) = ArchiveReader::open(container, pw) else { return false };
    let res = reader.for_each_entries(|entry, rd| {
        if entry.is_directory || !entry.has_stream {
            return Ok(true); // need a real data stream to verify the key
        }
        let mut sink = std::io::sink();
        // Reading the (verification-only) first entry to end trips CRC as
        // well as decode errors; bound it so a huge first member can't
        // stall the probe.
        let mut limited = std::io::Read::take(rd, 64 << 20);
        std::io::copy(&mut limited, &mut sink)?;
        Ok(false) // stop after the first data entry
    });
    res.is_ok()
}

/// Resolve the working password for this level's encrypted archive by
/// harvesting candidates from the level's own outputs. Returns `Some(pw)`
/// once a candidate is proven correct - RAR via the stored check value (no
/// data decrypted), 7z via a real open+decode attempt - or `None` to keep
/// the provided password (it already works, the set is check-less, or
/// nothing matched: today's park behavior is preserved).
fn resolve_level_password(dir: &std::path::Path, provided: Option<&str>) -> Option<String> {
    if let Some(rar) = first_encrypted_rar(dir) {
        return resolve_rar_password(&rar, dir, provided);
    }
    // Single-container 7z only: a multi-part encrypted .7z.001 set would
    // need joining to probe, out of scope for v1 - it keeps today's path.
    if let Ok(jobs) = collect_sevenz_archives(dir) {
        if let Some(z) = jobs.iter().find(|p| p.len() == 1).map(|p| p[0].clone()) {
            if !sevenz_password_opens(&z, None) {
                return resolve_sevenz_password(&z, dir, provided);
            }
        }
    }
    None
}

fn resolve_rar_password(
    rar: &std::path::Path,
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Option<String> {
    use nzbkit::rar::PwVerdict;
    let probe = nzbkit::rar::crypt_probe(rar)?;
    // Check-less set: a wrong password can't be vetoed before it writes
    // garbage, so we never guess - hand it to today's path (unrar, or a
    // manual 🔑).
    if probe.check.is_none() {
        return None;
    }
    if let Some(p) = provided {
        if matches!(probe.verify(p), PwVerdict::Verified) {
            return None; // provided password already works
        }
    }
    let t0 = std::time::Instant::now();
    for cand in harvest_password_candidates(dir, provided) {
        // KDF cost gates: the header's iteration depth is attacker-
        // controlled, so harvested candidates never pay for a deep
        // derivation, and the sweep as a whole is wall-time bounded.
        if !kdf_candidate_allowed(probe.lg2_count, cand.structured) {
            continue;
        }
        if t0.elapsed() > PW_PROBE_BUDGET {
            println!("⚠ password probe budget exhausted - keeping the park path");
            break;
        }
        if matches!(probe.verify(&cand.value), PwVerdict::Verified) {
            println!(
                "🔑 auto-unlocked {} with password from {}",
                rar.file_name().unwrap_or_default().to_string_lossy(),
                cand.source
            );
            return Some(cand.value);
        }
    }
    None
}

fn resolve_sevenz_password(
    z: &std::path::Path,
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Option<String> {
    if let Some(p) = provided {
        if sevenz_password_opens(z, Some(p)) {
            return None; // provided password already works
        }
    }
    // The 7z header does not advertise its KDF depth up front and each
    // probe may decode up to 64 MB, so the wall-clock budget is the
    // whole defense here.
    let t0 = std::time::Instant::now();
    for cand in harvest_password_candidates(dir, provided) {
        if t0.elapsed() > PW_PROBE_BUDGET {
            println!("⚠ password probe budget exhausted - keeping the park path");
            break;
        }
        if sevenz_password_opens(z, Some(&cand.value)) {
            println!(
                "🔑 auto-unlocked {} with password from {}",
                z.file_name().unwrap_or_default().to_string_lossy(),
                cand.source
            );
            return Some(cand.value);
        }
    }
    None
}

/// One extraction pass over `dir`, trying each format we support in turn.
/// `Ok(None)` = no archive present; otherwise the pass's [`NestOutcome`],
/// which names WHICH format stopped it so only the zip gap gets forgiven.
fn extract_one_level(
    dir: &std::path::Path,
    password: Option<&str>,
    depth: usize,
) -> Result<Option<NestOutcome>> {
    // Nested password-chain auto-unlock: an encrypted archive here may be
    // unlockable by a password sitting in a sibling text file the level
    // above just extracted. Harvest and verify a candidate before the
    // extraction attempt; on a hit, use it in place of the job password.
    let harvested = resolve_level_password(dir, password);
    let password = harvested.as_deref().or(password);
    // Phase 0(b) prevalence: one line per nested inner archive the disk
    // post-pass handles (a demoted-from-stream inner, or one never
    // eligible for streaming - RAR4, multipart 7z, a resumed job). Nested
    // levels only; a single-layer job is depth 0 and never counted. See
    // nzbkit::extract::note_nested_level for the shared counting model.
    if depth > 0 {
        if let Some(kind) = nested_inner_kind(dir) {
            nzbkit::extract::note_nested_level(
                depth,
                kind,
                nzbkit::extract::NestedDisposition::Disk,
            );
        }
    }
    // 1. Normally-named RAR set (.rar/.rNN by name; rollover/numeric with
    //    the Rar! magic). Native rars first (bundled unrar fallback); on
    //    failure, missing/destroyed volumes may be rebuildable from .rev
    //    recovery volumes, and byte-damaged ones from embedded recovery
    //    records.
    if dir_has_named_rar(dir)? {
        if try_unrar(dir, password) {
            return Ok(Some(NestOutcome::Produced));
        }
        if try_rev_reconstruct(dir) && try_unrar(dir, password) {
            return Ok(Some(NestOutcome::Produced));
        }
        println!("extraction failed - trying recovery-record self-repair…");
        return Ok(Some(NestOutcome::from_produced(try_rar_rr_repair(dir, password))));
    }
    // 2. Obfuscated RAR: extensionless files carrying the Rar! magic, with
    //    no filename order - ordered by the RAR header volume number.
    let obf = collect_obfuscated_rar_volumes(dir)?;
    if !obf.is_empty() {
        return Ok(Some(NestOutcome::from_produced(extract_obfuscated_rar(
            dir, &obf, password, depth,
        ))));
    }
    // 3. SFX self-extractors: an .exe/.bin/.sfx whose head embeds the RAR
    //    signature past a stub. rars scans for the offset itself; only the
    //    detection lives here. Top level ONLY (depth 0 = the post itself is
    //    an SFX): a payload's setup.exe is often a legitimate WinRAR SFX
    //    installer and must never be auto-exploded by the nested pass or
    //    the daemon's post-extraction pass.
    if depth == 0 {
        let sfx = collect_sfx_archives(dir)?;
        if !sfx.is_empty() {
            return Ok(Some(NestOutcome::from_produced(extract_sfx(dir, &sfx, password))));
        }
    }
    // 4. 7-Zip (native, incl. split .7z.001 multipart).
    let sevenz = collect_sevenz_archives(dir)?;
    if !sevenz.is_empty() {
        return Ok(Some(NestOutcome::from_produced(extract_sevenz(dir, &sevenz, password))));
    }
    // 5. Zip is a KNOWN, documented gap: we cannot produce the payload, so
    //    say so instead of exiting 0 with the archive still packed.
    //    Detection is `nzbkit::zip`'s alone - single containers, the
    //    obfuscated extensionless ones, WinZip-spanned `.z01` sets and
    //    byte-split `.zip.001` sets all report here, and its two standing
    //    rules (never magic-sniff a named file, never touch a
    //    `.cbz`/`.epub` payload) hold unchanged.
    //
    //    This level cannot judge how much the gap matters - a `subs.zip`
    //    beside a landed feature is not the same problem as a post whose
    //    entire payload is still packed - so it reports uniformly and the
    //    top-level caller decides (`unsupported_archive_present`).
    if let Some(found) = nzbkit::zip::first(dir) {
        println!(
            "⚠ {} present ({}) - zip extraction is not supported",
            found.shape.label(),
            found.name
        );
        return Ok(Some(NestOutcome::ZipGap));
    }
    Ok(None)
}

/// Every regular file directly under `dir` (one level), as a set - the
/// before/after diff that tells `extract_nested` what a pass produced.
fn snapshot_files(dir: &std::path::Path) -> Result<std::collections::HashSet<PathBuf>> {
    let mut out = std::collections::HashSet::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        if e.file_type().is_ok_and(|t| t.is_file()) {
            out.insert(e.path());
        }
    }
    Ok(out)
}

/// Every regular file anywhere under `dir` (recursive) - nested archives
/// can land in a release subfolder, so the before/after diff walks the
/// whole tree. Bounded traversal (skips our own scratch nest dirs).
fn snapshot_recursive(dir: &std::path::Path) -> Result<std::collections::HashSet<PathBuf>> {
    let mut out = std::collections::HashSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                // Our own scratch dirs (the nest staging dir, parked
                // leftovers) are furniture, not payload - the
                // before/after diff must never look inside them.
                if e.file_name().to_string_lossy().starts_with(".nzbfast") {
                    continue;
                }
                stack.push(p);
            } else if ft.is_file() {
                out.insert(p);
            }
        }
    }
    Ok(out)
}

/// Does `dir` hold a `.par2` set by name OR by the `PAR2\0PKT` magic
/// (obfuscated recovery volumes lose their extension)?
fn dir_has_par2(dir: &std::path::Path) -> Result<bool> {
    use std::io::Read;
    for e in std::fs::read_dir(dir)?.flatten() {
        let path = e.path();
        if path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
        {
            return Ok(true);
        }
        if e.metadata().is_ok_and(|m| m.is_file() && m.len() >= 8) {
            let mut head = [0u8; 8];
            if std::fs::File::open(&path)
                .and_then(|mut f| f.read_exact(&mut head))
                .is_ok()
                && &head == b"PAR2\x00PKT"
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Does `dir` hold anything the nested pass could try to extract? Named
/// RAR volumes count by NAME alone - a damaged volume whose signature
/// bytes were destroyed (the exact case the nested PAR2 pass exists to
/// heal) fails every magic sniff but still announces itself as `.rar`.
fn dir_has_nested_extractable(dir: &std::path::Path) -> Result<bool> {
    Ok(std::fs::read_dir(dir)?.flatten().any(|e| {
        let p = e.path();
        e.file_type().is_ok_and(|t| t.is_file())
            && (looks_like_named_rar(&p) || is_extractable_archive(&p))
    }))
}

/// Run PAR2 repair over the recovery sets a nested layer carries, before
/// its extraction attempt. Only sets whose data files are actually in
/// `dir` run (repair_present_sets): the downloaded set's own index -
/// present beside an in-stream-extracted payload whose volumes never
/// touched disk - matches nothing and is left alone, so this never
/// re-verifies or resurrects the outer set. The extraction attempt that
/// follows is the level's verdict; an unrepairable set still gets its
/// .rev and recovery-record chances in extract_one_level.
fn nested_par2_repair(dir: &std::path::Path) {
    use nzbkit::par2repair::{RepairStatus, repair_present_sets};
    let results = match repair_present_sets(dir) {
        Ok(r) => r,
        Err(e) => {
            println!("nested PAR2: scan error - {e}");
            return;
        }
    };
    for r in results {
        match r {
            Ok(RepairStatus::NoDamage) => println!("nested PAR2: no damage, set verifies ✔"),
            Ok(RepairStatus::Repaired(rep)) => println!(
                "nested PAR2: repaired ✔ ({} block(s) rebuilt, {} adopted, {} file(s) patched)",
                rep.blocks_rebuilt,
                rep.blocks_adopted,
                rep.files_patched.len()
            ),
            Ok(RepairStatus::Unrepairable { needed, have }) => println!(
                "nested PAR2: UNREPAIRABLE - need {needed} recovery block(s), have {have}"
            ),
            Err(e) => println!("nested PAR2: repair error - {e}"),
        }
    }
}

/// The name grammar the RAR extract paths share: `.rar`/`.rNN` by name, or
/// a rollover (`.sNN`…) / numeric (`.001`) extension carrying the Rar!
/// magic. Factored out so obfuscation detection can ask the inverse.
fn looks_like_named_rar(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    let by_name = name.ends_with(".rar")
        || name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
        });
    let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
        let t = &name[p + 1..];
        (t.len() >= 3
            && (b's'..=b'z').contains(&t.as_bytes()[0])
            && t[1..].bytes().all(|c| c.is_ascii_digit()))
            || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
    });
    by_name || (rollover_or_numeric && rar_magic(path))
}

/// Is a nested archive sitting in `dir` beside leftover outer volumes -
/// a named RAR of a foreign stem or a 7z at the top level (the fallback
/// unrar's own output when the payload is RAR-in-RAR), or any named
/// RAR/7z in a subdirectory (the unpack writes entry paths as real
/// subdirs; outer volumes only ever materialize at the top)? Obfuscated
/// (extensionless) top-level RARs are deliberately NOT counted: a
/// leftover volume that never earned its PAR2 rename would be
/// indistinguishable from payload, and re-processing the outer set is
/// the worse failure.
fn nested_archive_beside_leftovers(
    dir: &std::path::Path,
    outer_stems: &std::collections::HashSet<String>,
) -> bool {
    use nzbkit::extract::release_stem;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                // Never look inside our own scratch dirs.
                if !p
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(".nzbfast"))
                {
                    stack.push(p);
                }
            } else if ft.is_file() {
                let hit = if d == dir {
                    if looks_like_named_rar(&p) {
                        p.file_name().is_some_and(|n| {
                            !outer_stems.contains(&release_stem(&n.to_string_lossy()))
                        })
                    } else {
                        sevenz_magic(&p)
                    }
                } else {
                    looks_like_named_rar(&p) || sevenz_magic(&p)
                };
                if hit {
                    return true;
                }
            }
        }
    }
    false
}

/// Parks the leftover outer volume files in a scratch subdir so the
/// nested pass can run without seeing (and re-processing) them, restoring
/// on drop - including unwind, because the volumes are the user's retry
/// currency and must be back in place whatever the pass does.
struct OuterHold {
    dir: PathBuf,
    hold: PathBuf,
}

impl OuterHold {
    fn park(
        dir: &std::path::Path,
        outer_stems: &std::collections::HashSet<String>,
    ) -> std::io::Result<Self> {
        use nzbkit::extract::release_stem;
        let hold = dir.join(".nzbfast-outer-hold");
        // A crashed earlier run may have left volumes parked - fold them
        // back first so this park starts from the dir's real state.
        if hold.is_dir() {
            Self::restore(&hold, dir);
        }
        std::fs::create_dir_all(&hold)?;
        // Construct before moving: an error mid-park drops `me`, which
        // restores whatever was already moved.
        let me = Self {
            dir: dir.to_path_buf(),
            hold: hold.clone(),
        };
        for e in std::fs::read_dir(dir)?.flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_file())
                && looks_like_named_rar(&p)
                && p.file_name().is_some_and(|n| {
                    outer_stems.contains(&release_stem(&n.to_string_lossy()))
                })
            {
                if let Some(name) = p.file_name() {
                    std::fs::rename(&p, hold.join(name))?;
                }
            }
        }
        Ok(me)
    }

    /// Move every parked volume back. Returns how many could NOT be
    /// returned, so the caller knows whether the hold is safe to delete.
    fn restore(hold: &std::path::Path, dir: &std::path::Path) -> usize {
        let mut stranded = 0;
        if let Ok(entries) = std::fs::read_dir(hold) {
            for e in entries.flatten() {
                let p = e.path();
                let Some(name) = p.file_name() else {
                    stranded += 1;
                    continue;
                };
                if let Err(err) = std::fs::rename(&p, dir.join(name)) {
                    eprintln!(
                        "[hold] could not put {} back: {err}",
                        name.to_string_lossy()
                    );
                    stranded += 1;
                }
            }
        }
        stranded
    }
}

impl Drop for OuterHold {
    fn drop(&mut self) {
        // Delete the hold only when it is EMPTY.
        //
        // This used to swallow every restore failure and then
        // `remove_dir_all` the hold regardless - so any volume that could not
        // be moved back was deleted instead. The hold exists precisely to
        // protect the outer volume set during nested extraction, which makes
        // "the restore failed, so destroy what we were protecting" the worst
        // possible response.
        //
        // `remove_dir` refuses a non-empty directory, so a stranded volume
        // survives where the user can find it. Same rule as the nest scratch:
        // never delete a path unless this code proved it is spent.
        let stranded = Self::restore(&self.hold, &self.dir);
        if stranded == 0 {
            let _ = std::fs::remove_dir(&self.hold);
        } else {
            eprintln!(
                "[hold] {stranded} volume(s) left in {} - not deleting it",
                self.hold.display()
            );
        }
    }
}

/// Is a normally-named RAR set present in `dir`?
fn dir_has_named_rar(dir: &std::path::Path) -> Result<bool> {
    Ok(std::fs::read_dir(dir)?
        .flatten()
        .any(|e| looks_like_named_rar(&e.path())))
}

/// RAR volumes whose names carry NO recognized RAR extension but which
/// start with the Rar! magic (obfuscated usenet posts strip extensions and
/// rename volumes to hex). Only consulted when no normally-named set was
/// found, so this never shadows the fast name-based path.
fn collect_obfuscated_rar_volumes(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_file())
            && !looks_like_named_rar(&path)
            && rar_magic(&path)
        {
            out.push(path);
        }
    }
    Ok(out)
}

/// The RAR5+ volume number from a parsed archive header, when present.
/// RAR5 volume sets carry it; older families and single archives do not
/// (they sort by filename, which for a real set already reflects order).
fn archive_volume_number(archive: &rars::Archive) -> Option<u64> {
    match archive {
        rars::Archive::Rar50Plus(a) => a.main.volume_number,
        _ => None,
    }
}

/// Extract obfuscated RAR volumes: parse each candidate, PARTITION the
/// volumes into their original sets (a directory can hold several
/// interleaved obfuscated sets - the volumes carry no usable names, so
/// grouping runs on headers: volume numbers plus split-member name
/// continuity across volume boundaries), order each set by header volume
/// number, and extract every set. Returns true only when every detected
/// set extracted.
fn extract_obfuscated_rar(
    dir: &std::path::Path,
    candidates: &[PathBuf],
    password: Option<&str>,
    depth: usize,
) -> bool {
    let options = rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes));
    let mut parsed: Vec<(Option<u64>, PathBuf, rars::Archive)> = Vec::new();
    for path in candidates {
        match rars::ArchiveReader::read_path_with_options(path, options.clone()) {
            Ok(archive) => parsed.push((archive_volume_number(&archive), path.clone(), archive)),
            // A Rar!-magic file that will not parse is not a usable volume;
            // skip it rather than abort the whole set.
            Err(e) => println!("  – skipping {}: {e}", path.display()),
        }
    }
    if parsed.is_empty() {
        return false;
    }
    parsed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    // First/last member metadata drives the continuity linkage.
    let boundary = |archive: &rars::Archive| -> (Option<(Vec<u8>, bool)>, Option<(Vec<u8>, bool)>) {
        let mut first: Option<(Vec<u8>, bool)> = None;
        let mut last: Option<(Vec<u8>, bool)> = None;
        for member in archive.members() {
            let name = member.meta.name_bytes().to_vec();
            if first.is_none() {
                first = Some((name.clone(), member.meta.is_split_before));
            }
            last = Some((name, member.meta.is_split_after));
        }
        (first, last)
    };

    // Partition. Sets start at volumes with no volume number (a RAR5 set's
    // first volume, or a standalone archive); numbered volumes attach to
    // the open set whose tail's split-after member name matches their
    // split-before head - or, when the boundary member is not split, to
    // the only open set awaiting that number.
    let mut sets: Vec<Vec<(PathBuf, rars::Archive)>> = Vec::new();
    let mut open: Vec<usize> = Vec::new(); // indexes of sets still growing
    for (number, path, archive) in parsed {
        if number.is_none() {
            let closed = {
                let (_, last) = boundary(&archive);
                // A first volume whose last member is not split-after is a
                // complete single-volume archive.
                !last.is_some_and(|(_, split_after)| split_after)
            };
            sets.push(vec![(path, archive)]);
            if !closed {
                open.push(sets.len() - 1);
            }
            continue;
        }
        let number = number.unwrap_or(0);
        let (first, last) = boundary(&archive);
        // Candidate open sets currently ending at `number - 1` volumes past
        // their first (RAR5 numbers later volumes 1, 2, …).
        let expecting: Vec<usize> = open
            .iter()
            .copied()
            .filter(|&si| sets[si].len() as u64 == number)
            .collect();
        let chosen = match expecting.len() {
            0 => None,
            1 => Some(expecting[0]),
            _ => expecting
                .iter()
                .copied()
                .find(|&si| {
                    let tail = &sets[si].last().expect("open set is non-empty").1;
                    let (_, tail_last) = boundary(tail);
                    match (&tail_last, &first) {
                        (Some((tail_name, true)), Some((head_name, true))) => {
                            tail_name == head_name
                        }
                        _ => false,
                    }
                }),
        };
        match chosen {
            Some(si) => {
                sets[si].push((path, archive));
                if !last.is_some_and(|(_, split_after)| split_after) {
                    open.retain(|&s| s != si);
                }
            }
            None => {
                // No open set expects this volume - treat it as starting
                // its own (best effort; extraction will surface gaps).
                println!(
                    "  – volume {} (#{number}) matches no open set - treating as its own set",
                    path.display()
                );
                sets.push(vec![(path, archive)]);
            }
        }
    }

    println!(
        "unpacking {} obfuscated RAR set(s) ({} volume(s)) by header order…",
        sets.len(),
        sets.iter().map(|s| s.len()).sum::<usize>()
    );
    let mut all_ok = true;
    for set in sets {
        // Keep each set's SOURCE paths instead of dropping them on the
        // floor: they are the exact files we parsed and are about to feed
        // the extractor, so a successful extraction proves them ours AND
        // spent. Nothing downstream can re-derive that. The nested pass's
        // `sweep_spent_entry` groups candidates by `release_stem`, and a
        // hash name matches none of the volume suffixes it strips - seven
        // obfuscated volumes read as seven separate releases, its
        // "exactly one set present" guard trips, and the whole set used
        // to be left sitting beside the extracted payload.
        let (sources, archives): (Vec<PathBuf>, Vec<rars::Archive>) = set.into_iter().unzip();
        // Does this set declare a real file to produce? A `.rev` recovery
        // volume also starts with `Rar!`, so it arrives here as a
        // candidate, and its payload can carry a RAR signature the SFX
        // scan latches onto - parsing as a memberless "set" of its own.
        // Deleting one destroys the recovery data a damaged set is
        // repaired FROM, which is the worst outcome available here.
        let has_member = archives.iter().any(|a| a.members().any(|m| !m.meta.is_directory));
        // Taken per set, immediately before the extraction that fills it:
        // the diff against it names exactly what THIS set published.
        let before = snapshot_recursive(dir).ok();
        match write_archives_to(dir, &archives, password) {
            Ok(()) => {
                println!("native unpack complete ✔");
                // Same depth gate the named-set sweep uses, and for the
                // same reason: depth 0 is the user's own downloaded set or
                // an offline `extract` target, whose retention is
                // finalize/policy's call, not ours. Without this an
                // obfuscated set would be deleted where an identical named
                // set is kept, which is a difference the user never asked
                // for and cannot see coming.
                if depth >= 1 {
                    sweep_spent_obfuscated(dir, &sources, has_member, before.as_ref());
                }
            }
            Err(e) => {
                // Every volume of a failed set stays. PAR2 repair, `.rev`
                // reconstruction and a plain retry all read them, and on
                // a finished download they are the only copy.
                println!("⚠ obfuscated RAR unpack failed ({e})");
                all_ok = false;
            }
        }
    }
    all_ok
}

/// Remove the obfuscated volumes one set consumed, once that set has
/// extracted and published successfully.
///
/// `sources` is not a guess from a filename: it is the list of files this
/// pass opened, parsed as RAR headers and handed to the extractor, so each
/// entry is provably an input of the extraction that just succeeded.
/// Three separate refusals, any one of which keeps the ENTIRE set:
///
/// * `has_member` is false - the set declared no file member, so it never
///   produced one. That is the `.rev` shape, and recovery data must
///   survive its own misdetection.
/// * we could not snapshot `dir` beforehand, so nothing here can tell an
///   input from an output. No proof, no delete.
/// * the extraction published no file at all - there is no payload these
///   volumes could be spent ON.
///
/// and per path: never remove something the extraction just published.
/// `lift_scratch_into` refuses to replace an existing name, so a member
/// colliding with a volume lands as `extracted-N-…` and the volume is
/// still the volume - but this asks the before/after diff rather than
/// trusting that invariant to hold forever.
fn sweep_spent_obfuscated(
    dir: &std::path::Path,
    sources: &[PathBuf],
    has_member: bool,
    before: Option<&std::collections::HashSet<PathBuf>>,
) {
    if !has_member {
        return;
    }
    let Some(before) = before else { return };
    let Ok(after) = snapshot_recursive(dir) else { return };
    let published: std::collections::HashSet<PathBuf> =
        after.difference(before).cloned().collect();
    if published.is_empty() {
        return;
    }
    for path in sources {
        if published.contains(path) {
            println!("[extract] keeping {} - the extraction published it", path.display());
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => println!("[extract] removed spent volume {}", path.display()),
            Err(e) => println!("⚠ could not remove spent volume {}: {e}", path.display()),
        }
    }
}

/// Archive detector used for nested-layer descent: is this file an
/// archive a pass should descend into (RAR, 7z, or zip)? SFX stubs and
/// other executables are deliberately excluded - a payload executable
/// produced by an outer archive must never be re-exploded.
///
/// Zip counts even though we cannot yet unpack one: descent is what puts
/// the level in front of the reporting path, and a zip that nothing ever
/// descends into is a zip nobody ever hears about (a `Release/x.zip`
/// produced by an outer RAR used to vanish from every log). `nzbkit::zip`
/// keeps `.cbz`/`.epub` payloads out of that on its own.
fn is_extractable_archive(path: &std::path::Path) -> bool {
    rar_magic(path) || sevenz_magic(path) || nzbkit::zip::is_container(path)
}

/// Phase 0(b): classify the nested inner archive the disk post-pass is
/// about to handle in `dir`, for the prevalence tally. Mirrors
/// `extract_one_level`'s detection order (RAR, then 7z, then the zip gap);
/// `None` when the dir holds no extractable archive. Cheap - a bounded
/// head read for the RAR sub-type, run once per nested level.
fn nested_inner_kind(dir: &std::path::Path) -> Option<&'static str> {
    // A RAR volume by name (a sig-destroyed member still announces `.rar`)
    // or by magic (obfuscated, extensionless) - sub-classify from its head.
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_file())
            && (looks_like_named_rar(&p) || rar_magic(&p))
        {
            return Some(classify_rar_head(&p));
        }
    }
    // 7-Zip (native, incl. split .7z.001 multipart).
    if collect_sevenz_archives(dir).is_ok_and(|v| !v.is_empty()) {
        return Some("7z");
    }
    // Zip stays a documented extraction gap, but a zip inner is still a
    // nested layer worth counting. The tally has no zip bucket yet, so it
    // lands under the catch-all `other` - the prevalence LINE still names
    // it, which is what makes a zip-packed nest legible in a log.
    if nzbkit::zip::first(dir).is_some() {
        return Some("zip");
    }
    None
}

/// Read a RAR volume's head and name its shape for the prevalence line:
/// `rar-encrypted` (encryption is the salient blocker, header- or
/// file-level), else `rar-store` / `rar-compressed` from the first mapped
/// entry's method. `other` when the head parses no entry (a damaged or
/// exotic volume) - rare here, since nested PAR2 repair ran first.
fn classify_rar_head(path: &std::path::Path) -> &'static str {
    use nzbkit::rar::{Method, VolumeMapper};
    use std::io::Read;
    // Header-encrypted sets expose no entries without a password; the
    // crypt probe reads the record straight off the head.
    if nzbkit::rar::crypt_probe(path).is_some() {
        return "rar-encrypted";
    }
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut buf = vec![0u8; 512 * 1024];
    let mut n = 0;
    if let Ok(mut f) = std::fs::File::open(path) {
        while n < buf.len() {
            match f.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(_) => break,
            }
        }
    }
    let mut m = VolumeMapper::new(size);
    m.feed(0, &buf[..n]);
    match m.entries.first() {
        Some(e) if e.encrypted || e.crypt.is_some() => "rar-encrypted",
        Some(e) => match e.method {
            Method::Store => "rar-store",
            Method::Compressed => "rar-compressed",
        },
        None => "other",
    }
}

/// SFX self-extractor candidates: executable-ish extensions whose first
/// 1MB embeds the RAR signature after a launcher stub. The plain-RAR case
/// (magic at offset 0) is handled by the normal paths, not here.
fn collect_sfx_archives(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    use std::io::Read;
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let path = e.path();
        let sfx_ext = path.extension().is_some_and(|x| {
            let x = x.to_string_lossy().to_lowercase();
            x == "exe" || x == "bin" || x == "sfx"
        });
        if !sfx_ext || !e.file_type().is_ok_and(|t| t.is_file()) || rar_magic(&path) {
            continue;
        }
        let mut head = vec![0u8; 1 << 20];
        let n = std::fs::File::open(&path)
            .and_then(|mut f| f.read(&mut head))
            .unwrap_or(0);
        if head[..n]
            .windows(7)
            .any(|w| w == b"Rar!\x1a\x07\x00" || w == b"Rar!\x1a\x07\x01")
        {
            out.push(path);
        }
    }
    Ok(out)
}

/// Extract each SFX archive standalone (rars locates the archive past the
/// stub itself).
fn extract_sfx(dir: &std::path::Path, archives: &[PathBuf], password: Option<&str>) -> bool {
    let options = rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes));
    let mut all_ok = true;
    for path in archives {
        println!(
            "unpacking SFX archive {} natively…",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        match rars::ArchiveReader::read_path_with_options(path, options)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .and_then(|archive| write_archives_to(dir, &[archive], password))
        {
            Ok(()) => println!("SFX unpack complete ✔"),
            Err(e) => {
                println!("⚠ SFX unpack failed ({e})");
                all_ok = false;
            }
        }
    }
    all_ok
}

/// Does the file start with the 7-Zip signature (`7z\xBC\xAF\x27\x1C`)?
fn sevenz_magic(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 6];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .map(|_| b == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
        .unwrap_or(false)
}

/// Is this single path a 7z container or one part of a split set? The
/// per-path twin of `collect_sevenz_archives`' grouping grammar, for
/// callers that ask about one file rather than scanning a directory.
pub(crate) fn sevenz_archive_part(path: &std::path::Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    name.ends_with(".7z")
        || split_7z_part(&name).is_some()
        || (path.extension().is_none() && sevenz_magic(path))
}

fn verify_dir(dir: &std::path::Path) -> Result<bool> {
    use nzbkit::par2::{Par2Set, verify_file};

    let mut par2_bytes: Vec<Vec<u8>> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
        {
            par2_bytes.push(std::fs::read(&path)?);
        }
    }
    if par2_bytes.is_empty() {
        println!("no .par2 files in {} - verification skipped", dir.display());
        return Ok(false);
    }
    let refs: Vec<&[u8]> = par2_bytes.iter().map(|v| v.as_slice()).collect();
    let set = match Par2Set::parse(&refs) {
        Ok(s) => s,
        Err(e) => {
            println!("PAR2 parse failed ({e}) - verification skipped");
            return Ok(false);
        }
    };
    println!(
        "PAR2 set: {} file(s), block size {}, {} recovery block(s) on hand",
        set.files.len(),
        set.block_size,
        set.recovery_blocks_seen
    );

    let mut all_ok = true;
    for f in &set.files {
        let path = dir.join(nzbkit::disk::sanitize_filename(&f.name));
        match std::fs::read(&path) {
            Ok(data) => {
                let v = verify_file(f, set.block_size, &data);
                let bad = v.blocks.iter().filter(|ok| !**ok).count();
                if bad == 0 && v.md5_ok {
                    println!("  ✔ {} - {} blocks, MD5 ok", f.name, v.blocks.len());
                } else {
                    all_ok = false;
                    println!(
                        "  ✘ {} - {bad}/{} blocks bad, md5 {}",
                        f.name,
                        v.blocks.len(),
                        if v.md5_ok { "ok" } else { "MISMATCH" }
                    );
                }
            }
            Err(_) => {
                all_ok = false;
                println!("  ✘ {} - file missing", f.name);
            }
        }
    }
    Ok(all_ok)
}

// ---------------------------------------------------------------------------
// get - the downloader (PLAN M1)
// ---------------------------------------------------------------------------

struct FileSlot {
    hint: String,
    is_par2_main: bool,
    total_segments: usize,
    remaining: std::sync::atomic::AtomicUsize,
    missing: std::sync::atomic::AtomicUsize,
    /// Par2-main slots capture decoded bytes in memory so the recovery set
    /// activates mid-download without re-reading from disk.
    capture: Option<std::sync::Mutex<Vec<u8>>>,
}

/// When the last outstanding par2-main slot completes, parse the captured
/// packets and switch the verifier to in-stream mode.
/// M15b: hash spans that were decoded before PAR2 activation by reading
/// them back from disk WHILE the download continues - the work that used
/// to be the settle pass's re-read (42 GB on the 87 GB run) overlaps the
/// network phase instead. Coverage-gated: a span not fully on disk yet
/// (or in a still-unclassified slot) is skipped and settles as before.
fn backfill_pre_activation(
    verifier: &nzbkit::live::LiveVerifier,
    extractor: &nzbkit::extract::Extractor,
    n_slots: usize,
    par2_slots: &[bool],
) -> u64 {
    let mut fed: u64 = 0;
    let mut buf = vec![0u8; 4 << 20];
    for sidx in 0..n_slots {
        if par2_slots[sidx] {
            continue;
        }
        // Spans this run decoded keep a fresh span's claim strength, so
        // their boundary blocks compose as CRC parts instead of demanding
        // a block-sized byte buffer each. take_pre_spans decides which
        // spans qualify and hands back the source to feed them under;
        // crash-resume seeds, and pcrc-absent articles outside lean mode,
        // take the full-MD5 disk path.
        let (spans, how) = verifier.take_pre_spans(sidx);
        for (off, len) in spans {
            let mut o = off;
            let end = off + len;
            while o < end {
                let n = ((end - o) as usize).min(buf.len());
                if !extractor.covered(sidx, o, n) {
                    break; // not (yet) on disk - leave for settle
                }
                if extractor.read_at(sidx, o, &mut buf[..n]).is_err() {
                    break;
                }
                match how {
                    nzbkit::live::PreSpanSrc::Backfill => {
                        verifier.on_data_backfill(sidx, "", 0, o, &buf[..n])
                    }
                    nzbkit::live::PreSpanSrc::Disk => {
                        verifier.on_data_from_disk(sidx, "", 0, o, &buf[..n])
                    }
                }
                fed += n as u64;
                o += n as u64;
            }
        }
    }
    fed
}

fn maybe_activate_par2(
    slots: &[Arc<FileSlot>],
    verifier: &nzbkit::live::LiveVerifier,
    outstanding: &std::sync::atomic::AtomicUsize,
) -> bool {
    use std::sync::atomic::Ordering;
    if outstanding.fetch_sub(1, Ordering::AcqRel) != 1 {
        return false;
    }
    let guards: Vec<std::sync::MutexGuard<Vec<u8>>> = slots
        .iter()
        .filter_map(|s| s.capture.as_ref())
        .map(|c| c.lock().unwrap())
        .collect();
    let refs: Vec<&[u8]> = guards.iter().map(|g| g.as_slice()).collect();
    match verifier.activate(&refs) {
        Ok(set) => {
            println!(
                "  ▶ PAR2 set live: {} file(s), block size {} - verifying in-stream",
                set.files.len(),
                set.block_size
            );
            true
        }
        Err(e) => {
            println!("  ⚠ PAR2 activation failed ({e}) - falling back to post-download verify");
            verifier.set_off();
            false
        }
    }
}

/// Age in whole days of an NZB `<file date="…">` unix timestamp. Absent,
/// zero, or future dates count as fresh (0) - retention exclusion must
/// never fire on posts we can't date.
fn nzb_age_days(date: i64) -> u32 {
    if date <= 0 {
        return 0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    ((now - date).max(0) / 86_400) as u32
}

/// Live handle the daemon's streaming endpoint uses to reach the active
/// download's output writers (M11). `get` installs its extractor here for
/// the duration of the run.
#[derive(Default)]
pub(crate) struct StreamHub {
    /// The active download's extractor, tagged with its owning nzo_id ("" for
    /// a CLI download with no daemon owner). The tag lets a /stream request
    /// clone the extractor and confirm ownership in ONE lock acquisition
    /// (see [`StreamHub::extractor_for`]), so a job transition can never hand
    /// a request another job's extractor between the owner check and the
    /// clone.
    pub extractor: std::sync::Mutex<Option<(String, Arc<nzbkit::extract::Extractor>)>>,
    /// M14h dashboard feeds: in-stream verifier + per-server pool gauges
    /// of the ACTIVE download.
    pub verifier: std::sync::Mutex<Option<Arc<nzbkit::live::LiveVerifier>>>,
    pub pool_live: std::sync::Mutex<Option<Arc<nzbkit::pool::LiveStats>>>,
    /// Pool-level speed limiter (M14g), shared with every server's pool of
    /// the active download; the daemon adjusts it live via mode=config.
    pub rate: Arc<nzbkit::pool::RateLimit>,
    /// M11 hot lane: number of /stream readers currently attached. The
    /// pool reserves a slice of connections for promoted (seek) work
    /// while this is non-zero.
    pub stream_readers: Arc<std::sync::atomic::AtomicUsize>,
    /// Stream request generation: bumped per /stream request. Only the
    /// newest ALIVE reader may promote - an abandoned pre-seek reader
    /// parked at the write frontier would otherwise keep re-promoting its
    /// stale window, fighting the live seek's window for the hot lane
    /// (each promote rewrites the promoted set). Tracked as a set of
    /// live generations so a short probe that comes and goes hands
    /// promote rights BACK to the player it briefly outranked.
    pub stream_gen: Arc<std::sync::atomic::AtomicU64>,
    pub stream_alive: Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>,
    /// M11 seek re-prioritization: installed per run; the /stream layer
    /// promotes the articles under a player's read position through it.
    pub seek: std::sync::Mutex<Option<Arc<SeekCtl>>>,
    /// User-cancel of the ACTIVE download: the daemon flips the flag and
    /// aborts the pool through the control; get_with_progress bails
    /// ("stopped by user") instead of settling/extracting partial data.
    pub abort: std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
    pub queue_ctl: std::sync::Mutex<Option<Arc<nzbkit::pool::QueueControl>>>,
    /// Connections parked between jobs (see `nzbkit::warmpool`). Lives on
    /// the hub because it must outlive any single download - that is the
    /// entire point. Daemon only: a one-shot CLI `get` has no second job
    /// to hand them to, so it keeps the old connect-and-QUIT behaviour.
    pub warm: std::sync::OnceLock<Arc<nzbkit::warmpool::WarmPool>>,
    /// Hosts the daemon has ruled out for the NEXT download (exhausted
    /// block accounts); get_with_progress skips them at pool build.
    pub excluded_hosts: std::sync::Mutex<Vec<String>>,
    /// M2c.5: may this run speculatively prefetch a recovery volume the
    /// moment an article goes terminally Missing? The daemon enables it
    /// per MAIN job when no quota is configured (mirrors the sidecar-
    /// prefetch guard); defaults false so sidecar/other hub users never
    /// side-fetch. CLI runs (no hub) are governed by the
    /// NZBFAST_NO_SPEC_PREFETCH env instead.
    pub spec_prefetch: std::sync::atomic::AtomicBool,
    /// M29 availability oracle: the daemon installs a fresh sink per
    /// job; get_with_progress hands it to every server's pool config and
    /// stamps the job context (pool host order + group family). The
    /// daemon drains it into the ledger at net-drain.
    pub oracle: std::sync::Mutex<Option<Arc<nzbkit::oracle::OracleSink>>>,
    /// M29 opt-in routing (`oracle_route`, OFF by default): when the
    /// daemon installs a ledger snapshot here, get_with_progress drops
    /// any enabled server whose backbone is confidently GONE for this
    /// release's (family, age-bucket) - saving the doomed primary
    /// round-trips on takedown'd content. Never empties the pool, so a
    /// wrong verdict costs only latency, never the last path.
    pub route_gone: std::sync::Mutex<Option<nzbkit::oracle::Snapshot>>,
}

impl StreamHub {
    /// Clone the installed extractor, but only when it belongs to `want`.
    /// `want = None` is the M11 active-download stream, which owns whatever
    /// is installed. For `want = Some(id)` the tag must match, so the owner
    /// check and the clone happen under ONE lock - a job transition that has
    /// published the new owner but not yet installed its extractor (or still
    /// has the old one installed) returns None here, so a request never
    /// receives another job's extractor.
    pub fn extractor_for(&self, want: Option<&str>) -> Option<Arc<nzbkit::extract::Extractor>> {
        let g = self.extractor.lock().unwrap();
        let (owner, ex) = g.as_ref()?;
        match want {
            Some(id) if id != owner => None,
            _ => Some(ex.clone()),
        }
    }

    /// The warm connection pool, created on first use (it spawns a
    /// keepalive tick, so it needs a runtime and cannot be built by
    /// `Default`). `NZBFAST_WARM_POOL=0` forces it off everywhere.
    ///
    /// §36: this only ever runs for a server whose own `warm_pool` is
    /// set - the caller gates it. Reaching here does NOT mean pooling is
    /// on for the job, only that this server asked for it.
    ///
    /// The per-server cap is deliberately generous rather than tied to
    /// the configured `connections`: the fleet that parks connections was
    /// already sized by the account limit, so it cannot overshoot, while
    /// a cap read from a config that has since SHRUNK would silently
    /// evict live connections mid-run. Shrinking `connections` instead
    /// resolves itself through the idle timeout.
    pub fn warm(&self) -> Option<Arc<nzbkit::warmpool::WarmPool>> {
        if std::env::var("NZBFAST_WARM_POOL").is_ok_and(|v| v == "0") {
            return None;
        }
        Some(
            self.warm
                .get_or_init(|| {
                    nzbkit::warmpool::WarmPool::new(
                        nzbkit::warmpool::DEFAULT_MAX_IDLE,
                        64,
                    )
                })
                .clone(),
        )
    }
}

/// M11: translates OUTPUT-file byte ranges (what a media player reads)
/// back to pending pool articles and moves them to the queue front. Line
/// rate ≫ any media bitrate, so a promoted 32 MB window lands in well
/// under a second of line time - seeks feel instant.
pub(crate) struct SeekCtl {
    /// Per slot: (encoded cumulative start, bracketed message-id) per
    /// segment in file order - empty for par2 slots - plus the slot's
    /// total encoded bytes. Offsets are NZB-declared (encoded) sizes;
    /// callers scale decoded positions proportionally, and ±2 articles of
    /// slack absorb the yEnc-overhead estimate error.
    slot_articles: Vec<(Vec<(u64, String)>, u64)>,
    ctl: Arc<nzbkit::pool::QueueControl>,
    extractor: Arc<nzbkit::extract::Extractor>,
    /// Volume-sorted non-par2 slot indices (NZB metadata, known before a
    /// single article lands). The last-resort span mapping: the
    /// extractor's map needs at least each volume's parsed header, so a
    /// span in a not-yet-classified volume (the file TAIL at play start,
    /// racing the header probes) would otherwise map to nothing - and a
    /// promote missing the tail displaces the tail-burst articles.
    vol_slots: Vec<usize>,
}

impl SeekCtl {
    /// A live /stream reader touched us: keep the pool's stream mode
    /// (shallow pipelines, see pool.rs) fresh so any promotion - this
    /// read's or a later seek's - preempts instead of queueing behind
    /// deep in-flight windows.
    pub fn note_stream(&self) {
        self.ctl.note_stream_active();
    }

    /// Promote the pending articles carrying output bytes of `name` (a
    /// slot file or an extracted inner file) for every span, in span
    /// order - promote() front-loads the queue in exactly the order
    /// given, which is the order the player reads (playhead span first,
    /// then the file tail). One promote per call: the stream layer keeps
    /// the playhead window AND the still-uncovered tail (MKV Cues / MP4
    /// moov) hot together - a playhead-only promote would displace the
    /// tail-burst articles a player is about to ask for. `file_size`
    /// (the caller's writer knows it) anchors the NZB-ladder fallback
    /// for spans in volumes the extractor hasn't classified yet.
    pub fn promote_output_spans(&self, name: &str, file_size: u64, spans: &[(u64, u64)]) -> usize {
        let mut ids: Vec<String> = Vec::new();
        for &(start, end) in spans {
            if start >= end {
                continue;
            }
            let mapped = self.extractor.map_output_range(name, start, end);
            if mapped.is_empty() {
                // No volume covering this span has classified yet (its
                // header article is still in flight - routine in the
                // first seconds, exactly when the player probes the
                // tail). Estimate from NZB metadata alone.
                self.ladder_fallback(file_size, start, end, &mut ids);
                continue;
            }
            // map_output_range returns pieces sorted by output offset, so
            // pushing in iteration order preserves player-read order.
            for (slot, vs, ve, vsize) in mapped {
                let Some((arts, enc_total)) = self.slot_articles.get(slot) else { continue };
                if arts.is_empty() || *enc_total == 0 {
                    continue;
                }
                // Decoded volume offset → encoded article ladder
                // (proportional; yEnc overhead is uniform within a file).
                let scale = |v: u64| {
                    if vsize > 0 {
                        (v as f64 / vsize as f64 * *enc_total as f64) as u64
                    } else {
                        v
                    }
                };
                let (es, ee) = (scale(vs), scale(ve));
                let lo = arts.partition_point(|(o, _)| *o <= es).saturating_sub(2);
                let hi = (arts.partition_point(|(o, _)| *o < ee) + 1).min(arts.len());
                for (_, id) in &arts[lo..hi] {
                    ids.push(id.clone());
                }
            }
        }
        // promote() ranks by first occurrence, so cross-span duplicates
        // are harmless.
        self.ctl.promote(&ids)
    }

    /// Zero-knowledge span mapping: scale output-file offsets onto the
    /// concatenated encoded ladders of the volume-sorted data slots (pure
    /// NZB metadata). Coarser than the extractor's map - yEnc overhead
    /// and volume headers skew it slightly - so take a generous ±4
    /// articles of slack per edge.
    fn ladder_fallback(&self, file_size: u64, start: u64, end: u64, ids: &mut Vec<String>) {
        let total_enc: u64 =
            self.vol_slots.iter().filter_map(|&s| self.slot_articles.get(s)).map(|(_, t)| t).sum();
        if file_size == 0 || total_enc == 0 {
            return;
        }
        let to_enc = |v: u64| (v as f64 / file_size as f64 * total_enc as f64) as u64;
        let (gs, ge) = (to_enc(start), to_enc(end.min(file_size)));
        let mut base = 0u64;
        for &si in &self.vol_slots {
            let Some((arts, enc_total)) = self.slot_articles.get(si) else { continue };
            if *enc_total == 0 || arts.is_empty() {
                continue;
            }
            let (slot_lo, slot_hi) = (base, base + enc_total);
            base += enc_total;
            if ge <= slot_lo || gs >= slot_hi {
                continue;
            }
            let (es, ee) = (gs.saturating_sub(slot_lo), (ge - slot_lo).min(*enc_total));
            let lo = arts.partition_point(|(o, _)| *o <= es).saturating_sub(4);
            let hi = (arts.partition_point(|(o, _)| *o < ee) + 4).min(arts.len());
            for (_, id) in &arts[lo..hi] {
                ids.push(id.clone());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_with_progress(
    config: &PathBuf,
    nzb_path: &PathBuf,
    out_dir: &PathBuf,
    connections: usize,
    window: usize,
    decoders: usize,
    // PAR2 fast verify (TODO §10): CRC32-only in-stream block claims.
    // NZBFAST_FAST_VERIFY=0/1 overrides for bench A/Bs.
    fast_verify: bool,
    // M32 "lean" verify (slow-CPU boost): with fast verify on, also skip
    // the per-article yEnc CRC once PAR2 covers a file - in-stream
    // integrity rests on the PAR2 block CRC32 alone (one CRC32 layer
    // instead of two). Settle read-back + repair authority unchanged;
    // PAR2-less downloads keep full article CRCs automatically.
    verify_lean: bool,
    no_extract: bool,
    // Explicit archive password (CLI/API). NZB `<meta type="password">`
    // and the `Name{{password}}.nzb` filename convention are picked up
    // automatically; this overrides both.
    password: Option<String>,
    progress: Option<Arc<AtomicU64>>,
    hub: Option<Arc<StreamHub>>,
    // The nzo_id that owns this run's hub extractor (daemon jobs); empty for
    // CLI downloads. Tags the installed extractor so /stream ownership is
    // checked atomically with the clone (finding 11).
    stream_owner: &str,
    // net_done fires when the network phase is done (all articles
    // terminal, consumers drained) - the daemon starts the next job's
    // download then, while this job's tail (settle/repair/extract) runs.
    net_done: Option<tokio::sync::oneshot::Sender<()>>,
    budget: nzbkit::mem::MemBudget,
) -> Result<()> {
    use nzbkit::nzb::FileKind;
    use nzbkit::pool::{ArticleReq, BufPool, FetchOutcome, PoolConfig, fetch_all_multi_ctl};
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    // B4: on small-RAM boxes clamp job concurrency to the machine's tier
    // - spill-churn on an HDD costs more than the connections buy, so
    // consistency wins over peak. A clamp on the effective values, not a
    // config rewrite: settings stay portable and apply in full on bigger
    // hardware. Above 1 GB the caps are None and nothing changes.
    let (connections, window, decoders) = match nzbkit::mem::concurrency_caps() {
        Some(caps) => {
            let clamped = caps.apply(connections, window, decoders);
            if clamped != (connections, window, decoders) {
                println!(
                    "[mem] small-RAM machine: clamping to {} conns × window {} × {} decoders (was {connections}×{window}×{decoders})",
                    clamped.0, clamped.1, clamped.2
                );
            }
            clamped
        }
        None => (connections, window, decoders),
    };
    // Rotational output on a NAS-class box: one decoder, so the article
    // lanes stop being seek lanes. See disk::decoders_for_storage for why
    // it is gated on the box as well as the disk.
    let decoders = {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        let storage = nzbkit::disk::detect_storage(out_dir);
        let picked = nzbkit::disk::decoders_for_storage(storage, cores, decoders);
        if picked != decoders {
            println!(
                "[disk] rotational output on a {cores}-core box: {picked} decoder \
                 (was {decoders}) to keep writes in order - override with \
                 NZBFAST_STORAGE=ssd"
            );
        }
        picked
    };

    let mut cfg_all = Config::load(config)?;
    // Soft-disabled servers never join a pool.
    cfg_all.servers.retain(|s| {
        if !s.enabled {
            println!("[config] {} disabled - not in the pool", s.host);
        }
        s.enabled
    });
    // Exhausted block accounts (daemon-computed): out of the pool.
    if let Some(h) = &hub {
        let excluded = h.excluded_hosts.lock().unwrap().clone();
        if !excluded.is_empty() {
            cfg_all.servers.retain(|s| {
                let keep = !excluded.contains(&s.host);
                if !keep {
                    println!("[block] {} exhausted - not using it for this download", s.host);
                }
                keep
            });
        }
    }
    if cfg_all.servers.is_empty() {
        anyhow::bail!("no usable servers (all disabled or block-exhausted)");
    }
    let xml = std::fs::read(nzb_path).with_context(|| format!("reading {}", nzb_path.display()))?;
    let nzb = Nzb::parse(&xml).context("parsing NZB")?;

    // The release's dominant group family - one NZB ≈ one family. Used
    // both for the oracle routing gate below and the ledger sink context.
    let job_family = {
        let mut freq: HashMap<&str, usize> = HashMap::new();
        for f in &nzb.files {
            for g in &f.groups {
                *freq.entry(g.as_str()).or_default() += 1;
            }
        }
        freq.into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(g, _)| nzbkit::oracle::group_family(g))
            .unwrap_or_else(|| "misc".into())
    };
    // Newest article post date, or None when the release is fully undated.
    // Undated jobs carry no usable age, so the oracle IGNORES them entirely
    // (no routing verdict, no ledger recording): an undated outcome would
    // otherwise mis-file as bucket 0 ("fresh") for the writer but read back
    // as bucket 6 ("3y+") on every read - a split-brain that can even
    // false-flag an undated retention-expired family as "being reaped".
    let job_posted: Option<i64> =
        nzb.files.iter().filter_map(|f| (f.date > 0).then_some(f.date)).max();

    // M29 opt-in routing (`oracle_route`, OFF unless the daemon installed
    // a snapshot): drop enabled servers whose backbone the availability
    // ledger is confident is GONE for this release's (family, age-bucket),
    // saving the doomed primary round-trips on takedown'd content. Guarded
    // three ways: needs an installed snapshot, needs a real post date to
    // pick an age bucket, and NEVER empties the pool - so a wrong verdict
    // only costs latency (a surviving server + the fill ladder still try),
    // never the last path.
    if let Some(snap) = hub.as_ref().and_then(|h| h.route_gone.lock().unwrap().clone()) {
        if let Some(date) = job_posted {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            let age = ((now - date).max(0) / 86_400) as u32;
            let gone: Vec<String> = cfg_all
                .servers
                .iter()
                .filter(|s| {
                    snap.backbone_gone(&nzbkit::oracle::backbone_of(&s.host), &job_family, age)
                })
                .map(|s| s.host.clone())
                .collect();
            // Only skip if at least one server survives (never the last path).
            if !gone.is_empty() && gone.len() < cfg_all.servers.len() {
                cfg_all.servers.retain(|s| {
                    let keep = !gone.contains(&s.host);
                    if !keep {
                        println!(
                            "[oracle] {} predicted gone for {job_family} (age {age}d) - skipping it this download",
                            s.host
                        );
                    }
                    keep
                });
            }
        }
    }

    // Archive password, in priority order: explicit > NZB meta > filename
    // convention. Only consulted if the set turns out to be encrypted.
    let password: Option<String> = match password {
        Some(p) => {
            println!("[password] using supplied archive password");
            Some(p)
        }
        None => {
            if let Some(p) = nzb.password() {
                println!("[password] NZB carries an archive password (meta)");
                Some(p.to_string())
            } else if let Some(p) = braces_password(nzb_path) {
                println!("[password] archive password taken from {{{{…}}}} in the NZB filename");
                Some(p)
            } else {
                None
            }
        }
    };

    // Crash-resume journal: completed articles from a previous run of this
    // exact NZB are already on disk - at final offsets in their own file
    // (v1 lines) or at journal-recorded placements (direct-extracted
    // spans), which the restore pass copies back into volume files now.
    let (journal, resume_state) = nzbkit::journal::Journal::open(out_dir, &xml)?;
    let journal = Arc::new(journal);
    // Plaintext-once (`D`) records re-encrypt through the password; with
    // no password those articles refetch instead - never guessed.
    let restored = nzbkit::journal::restore(out_dir, &resume_state, password.as_deref());
    let mut completed = resume_state.completed;
    if !restored.ids.is_empty() {
        let moved: u64 = restored
            .seeds
            .iter()
            .flat_map(|s| s.spans.iter().map(|&(_, l)| l))
            .sum();
        println!(
            "resume: restored {} article(s) ({:.1} MB) from previous run's output files",
            restored.ids.len(),
            moved as f64 / 1e6
        );
        completed.extend(restored.ids.iter().cloned());
    }
    let resuming = !completed.is_empty();

    // Eager set: everything except PAR2 recovery volumes (minimality layer 1).
    // Par2-main segments go FIRST in the queue so the recovery set activates
    // within the first round-trips and verification runs in-stream.
    //
    // Obfuscated posts often ship recovery volumes but no plain `.par2`
    // index. The critical packets (Main/FileDesc/IFSC) are duplicated in
    // every volume, so bootstrap the set from the smallest volume instead -
    // its recovery slices also count toward any later repair.
    let has_main = nzb.files.iter().any(|f| f.kind() == FileKind::Par2Main);
    let bootstrap_vol: Option<usize> = if has_main {
        None
    } else {
        nzb.files
            .iter()
            .enumerate()
            .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
            .min_by_key(|(_, f)| f.bytes())
            .map(|(i, _)| i)
    };
    if let Some(bi) = bootstrap_vol {
        println!(
            "no main .par2 in NZB - bootstrapping set from smallest volume ({:.1} MB)",
            nzb.files[bi].bytes() as f64 / 1e6
        );
    }
    let mut slots: Vec<Arc<FileSlot>> = Vec::new();
    let mut id_to_slot: HashMap<String, usize> = HashMap::new();
    // M11: per-slot article ladder (encoded cumulative offset → id) for
    // seek promotion; aligned with `slots` (empty for par2 slots).
    let mut slot_arts: Vec<(Vec<(u64, String)>, u64)> = Vec::new();
    let mut par2_ids: Vec<ArticleReq> = Vec::new();
    // Each data file's FIRST segment goes right after the par2 index:
    // the offset-0 article carries the RAR signature + headers, so the
    // extractor classifies every slot within the first round-trips instead
    // of holding gigabytes of unclassifiable spans (M3 scheduling rule).
    let mut head_ids: Vec<ArticleReq> = Vec::new();
    let mut data_ids: Vec<ArticleReq> = Vec::new();
    let mut dup_segments = 0usize;
    for (fi, f) in nzb.files.iter().enumerate() {
        // Articles inherit their file's post date; per-server retention
        // routing (M14e) keys off this age.
        let age_days = nzb_age_days(f.date);
        let is_bootstrap = bootstrap_vol == Some(fi);
        if f.kind() == FileKind::Par2Volume && !is_bootstrap {
            continue;
        }
        let is_par2_main = f.kind() == FileKind::Par2Main || is_bootstrap;
        let idx = slots.len();
        slots.push(Arc::new(FileSlot {
            hint: f
                .filename_hint()
                .map(str::to_string)
                .unwrap_or_else(|| format!("file{idx:03}")),
            is_par2_main,
            total_segments: f.segments.len(),
            remaining: AtomicUsize::new(f.segments.len()),
            missing: AtomicUsize::new(0),
            capture: is_par2_main.then(|| std::sync::Mutex::new(Vec::new())),
        }));
        let mut arts: Vec<(u64, String)> = Vec::new();
        let mut enc_cum = 0u64;
        for (si, seg) in f.segments.iter().enumerate() {
            let bracketed = format!("<{}>", seg.message_id);
            // Malformed NZBs repeat a message-id, within one file or across
            // two. The pool fetches each id exactly once (a second request
            // would never turn terminal - the duplicate-id forever-hang),
            // so a repeat is settled here: the FIRST occurrence owns the
            // article. A same-file repeat is covered by that one fetch
            // (yEnc offsets come from the article, not the NZB); a
            // cross-file repeat means these bytes never reach THIS file -
            // count it missing and let PAR2 repair fill the hole.
            if let Some(&owner) = id_to_slot.get(&bracketed) {
                dup_segments += 1;
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                if owner != idx {
                    slots[idx].missing.fetch_add(1, Ordering::Relaxed);
                }
                enc_cum += seg.bytes;
                continue;
            }
            id_to_slot.insert(bracketed.clone(), idx);
            if !is_par2_main {
                arts.push((enc_cum, bracketed.clone()));
            }
            enc_cum += seg.bytes;
            // On resume, journal-completed data articles are skipped -
            // their bytes are on disk and the settle pass verifies them.
            // Par2-main articles always refetch (tiny; activation needs
            // the packets in memory).
            if !is_par2_main && completed.contains(&bracketed) {
                slots[idx].remaining.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            let req = ArticleReq {
                id: bracketed,
                age_days,
            };
            if is_par2_main {
                par2_ids.push(req);
            } else if si == 0 {
                head_ids.push(req);
            } else {
                data_ids.push(req);
            }
        }
        slot_arts.push((arts, enc_cum));
    }
    if dup_segments > 0 {
        println!("  ⚠ NZB repeats {dup_segments} segment id(s) - each article is fetched once");
    }
    // M11 head+tail burst (hub-attached runs, i.e. the daemon): the first
    // volume's opening ~16 MB and the last volume's closing ~8 MB jump the
    // data queue, so a media player gets the container header AND the
    // end-of-file seek index (MKV Cues / MP4 moov both live at the end)
    // within seconds of queue-add. These are ordinary file bytes - nothing
    // is wasted if nobody ever streams.
    if hub.is_some() {
        let mut data_slots: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_par2_main)
            .map(|(i, _)| i)
            .collect();
        data_slots.sort_by_key(|&i| nzbkit::extract::vol_sort_key(&slots[i].hint));
        let mut burst: std::collections::HashSet<&str> = Default::default();
        if let Some(&first) = data_slots.first() {
            for (off, id) in &slot_arts[first].0 {
                if *off >= 16_000_000 {
                    break;
                }
                burst.insert(id.as_str());
            }
        }
        if let Some(&last) = data_slots.last() {
            let (arts, total) = &slot_arts[last];
            for (off, id) in arts.iter().rev() {
                if off + 8_000_000 <= *total {
                    break;
                }
                burst.insert(id.as_str());
            }
        }
        if !burst.is_empty() {
            let (mut early, rest): (Vec<_>, Vec<_>) =
                data_ids.into_iter().partition(|r| burst.contains(r.id.as_str()));
            early.extend(rest);
            data_ids = early;
        }
    }
    let mut ids = par2_ids;
    ids.extend(head_ids);
    ids.extend(data_ids);
    if resuming {
        println!(
            "resuming: {} article(s) already on disk, {} to fetch",
            completed.len(),
            ids.len()
        );
    }

    let verifier_seed_slots: Vec<usize> = slots
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.is_par2_main && s.remaining.load(Ordering::Relaxed) == 0)
        .map(|(i, _)| i)
        .collect();

    let verifier = Arc::new(nzbkit::live::LiveVerifier::with_partials_cap(
        slots.len(),
        budget.partials_cap(),
    ));
    // Fast verify (TODO §10): default ON - bench-validated 2.9× on
    // CPU-bound boxes (Europe bench box E-core round, 21 Jul), nzbget parity.
    // The env var overrides flag/config either way (bench A/Bs).
    let fast_verify = match std::env::var("NZBFAST_FAST_VERIFY") {
        Ok(v) => v != "0",
        Err(_) => fast_verify,
    };
    verifier.set_fast_verify(fast_verify);
    verifier.set_lean(fast_verify && verify_lean);
    if !fast_verify {
        println!("verify: full (per-block MD5+CRC32)");
    } else if verify_lean {
        println!(
            "verify: lean - article CRCs skipped once PAR2 covers a file \
             (single-CRC32 in-stream; end-of-job verification unchanged)"
        );
    }
    let n_par2_slots = slots.iter().filter(|s| s.is_par2_main).count();
    let par2_outstanding = Arc::new(AtomicUsize::new(n_par2_slots));
    if n_par2_slots == 0 {
        verifier.set_off();
    }
    // All file writing goes through the extractor: plain files write
    // through; store-mode RAR volumes extract in-stream (M3). Resumed
    // runs disable in-stream mapping (previous spans aren't refetched, so
    // headers may be incomplete) - volumes materialize and extraction
    // happens from disk after verification instead.
    // The archive shape prints ONCE, folded into the first volume line
    // that lands after the mappers have worked it out - several decode
    // consumers race for that line, so the flag is shared.
    let shape_said = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let extractor = Arc::new(nzbkit::extract::Extractor::with_resume(
        out_dir,
        slots.len(),
        !no_extract && !resuming,
        resuming,
    ));
    // The root has to know its own Arc before any span arrives, or a
    // top-level chase (a posted .7z) has nothing for its worker to reach
    // the extractor through and quietly declines. Unconditional: the
    // promote hook below anchors too, but it only exists on the daemon
    // path, and `nzbfast get` chases the same archives.
    extractor.anchor();
    extractor.set_holds_cap(budget.holds_cap());
    // An inner file's declared `unpacked_size` is an attacker-controlled
    // RAR header vint, and on Linux preallocation is a real fallocate - so
    // a few-hundred-KB post declaring 8 TB used to genuinely reserve the
    // volume's free space until the finish-time gates demoted it. The
    // NZB's own posted byte count is the defensible bound: nothing posted
    // here can legitimately unpack to more than what was posted (compressed
    // inner files can, but preallocation is an optimisation - writes past
    // the reservation extend the file exactly as they do on macOS, where
    // nothing is reserved at all). Deliberately a RESERVATION ceiling and
    // not a clamp on the declared size, which resume truncation and the
    // reported extracted size both depend on.
    if nzb.total_bytes() > 0 {
        extractor.set_prealloc_ceiling(nzb.total_bytes());
    }
    // Decompression-bomb budget for the IN-STREAM extractor - the same
    // guard `write_archives_to`/`extract_one_sevenz` put on the disk and
    // post-pass sinks, which until now covered only the fallback and not
    // the default path. Shared across every inner file and every nesting
    // level, so a bomb split over many outputs gets one allowance.
    if let Some(free) = crate::serve::free_bytes(out_dir) {
        extractor.set_extract_budget(free.saturating_sub(EXTRACT_RESERVE));
    }
    // With a password, RAR5 encrypted STORE sets stay on the in-stream
    // path: ciphertext assembles at plain store offsets and one AES pass
    // at finish decrypts it - no materialized volumes, no unrar.
    if let Some(pw) = &password {
        extractor.set_password(pw);
    }
    // That AES pass replaces the ciphertext this journal's placement
    // records point INTO. Once a file holds plaintext it is no longer the
    // bytes the journal describes, so a resume that still trusted it would
    // copy translated fragments out of it into the volume files and mark
    // those articles restored - skipping the refetch, and without PAR2
    // looping forever on poisoned local bytes while the provider still has
    // every original article. Gate the publish on retiring the claim
    // first: the extractor hands over the output names and moves no byte
    // until this returns Ok, and `invalidate` is durable before it does.
    //
    // Weak, like the promote hook: the extractor outlives this scope, and
    // a strong clone parked in it would defeat the `Arc::try_unwrap` that
    // retires the whole journal after a verified finish. A journal that is
    // already gone claims nothing, so publishing is free.
    {
        let j = Arc::downgrade(&journal);
        extractor.set_decrypt_barrier(Arc::new(move |names: &[String]| match j.upgrade() {
            Some(j) => j.invalidate(names),
            None => Ok(()),
        }));
    }
    // Crash resume (placement journal): adopt the restored volume files
    // as slot writers and register their spans with the verifier - the
    // M15b backfill hashes every restored byte against the PAR2 block map
    // once the set activates, so nothing is trusted unverified.
    for seed in &restored.seeds {
        if seed.slot >= slots.len() || slots[seed.slot].is_par2_main {
            continue;
        }
        if let Err(e) = extractor.seed_slot(seed.slot, &seed.name, seed.size, &seed.spans) {
            eprintln!("resume: adopting {} failed: {e}", seed.name);
            continue;
        }
        verifier.seed_pre_spans(seed.slot, &seed.spans);
        // The journal name (the real on-disk name) beats the subject hint
        // for PAR2 file matching.
        verifier.set_name_hint(seed.slot, &seed.name);
    }
    // Fully-resumed slots see no articles - seed their names so PAR2
    // matching and read-back verification still reach them.
    for &si in &verifier_seed_slots {
        verifier.set_name_hint(si, &slots[si].hint);
    }
    // M11: seek re-prioritization handle. QueueControl attaches to the
    // pool's pending queue when the fetch starts; SeekCtl turns player
    // read positions into promotions through it.
    let queue_ctl = Arc::new(nzbkit::pool::QueueControl::default());
    let abort_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The promote ladder is built for EVERY run, not just the daemon's.
    // A player seek needs the hub; the 7z tail prefetch does not - it is
    // the extractor asking for the articles carrying an archive's end
    // header, and without it the chase cannot read the archive map until
    // the tail arrives on its own, which in a sequential download is
    // last. That turns one-pass into a decode burst at the end, and it
    // denies drop-behind trimming the read watermark it needs, so a `get`
    // of a large .7z demoted where the daemon streamed it.
    let seek = {
        let mut vol_slots: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_par2_main)
            .map(|(i, _)| i)
            .collect();
        vol_slots.sort_by_key(|&i| nzbkit::extract::vol_sort_key(&slots[i].hint));
        Arc::new(SeekCtl {
            slot_articles: std::mem::take(&mut slot_arts),
            ctl: queue_ctl.clone(),
            extractor: extractor.clone(),
            vol_slots,
        })
    };
    // Weak - the hook must not pin the SeekCtl/Extractor pair into a
    // reference cycle.
    let weak_seek = Arc::downgrade(&seek);
    extractor.set_promote_hook(Arc::new(move |name: &str, size: u64, spans: &[(u64, u64)]| {
        if let Some(s) = weak_seek.upgrade() {
            s.promote_output_spans(name, size, spans);
        }
    }));
    if let Some(h) = &hub {
        *h.extractor.lock().unwrap() = Some((stream_owner.to_string(), extractor.clone()));
        *h.verifier.lock().unwrap() = Some(verifier.clone());
        *h.seek.lock().unwrap() = Some(seek);
        *h.abort.lock().unwrap() = Some(abort_flag.clone());
        *h.queue_ctl.lock().unwrap() = Some(queue_ctl.clone());
    }
    let eager_bytes = nzb.eager_bytes();
    println!(
        "{}: {} files ({:.1} MB eager of {:.1} MB total) → {}",
        nzb_path.display(),
        slots.len(),
        eager_bytes as f64 / 1e6,
        nzb.total_bytes() as f64 / 1e6,
        out_dir.display()
    );

    let buf_pool = BufPool::new(budget.bufpool_bufs());
    // Decoded-payload buffers, recycled the same way as the network-side
    // `buf_pool` - the decoder writes each article's bytes into a buffer
    // taken from here and the consumer returns it after write+verify, so
    // the hot path does no per-article ~800 KB payload allocation.
    let out_pool = BufPool::new(budget.bufpool_bufs());
    // Stall-detection timeout; env override exists for the chaos suite
    // (a mock stall shouldn't cost a test 30 wall-clock seconds).
    let read_timeout = std::env::var("NZBFAST_READ_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or_else(|| PoolConfig::default().read_timeout);
    // Per-server budget: the CLI --connections is a ceiling; a server's
    // config `connections` (its account limit) caps its own pool; a
    // fresh auto-tuned knee (conntune.json, M7b.1) caps below that -
    // over-asking a provider measured 3-4× SLOWER than the knee.
    let tuned = crate::conntune::load(config);
    let tuned_note: Vec<String> = cfg_all
        .servers
        .iter()
        .filter_map(|s| {
            let t = tuned.get(&s.host)?;
            (t.connections > 0 && (t.connections as u32) < s.connections.max(1))
                .then(|| format!("{} {}", s.host, t.connections))
        })
        .collect();
    if !tuned_note.is_empty() {
        println!("  connection auto-tune: {}", tuned_note.join(" · "));
    }
    // Config is reloaded for every daemon job, while the warm pool lives
    // across jobs. Reconcile the cache before building the new fleet so
    // sessions authenticated with a removed password/user, proxy or bind
    // address stop occupying the provider's connection cap immediately.
    if let Some(warm) = hub.as_ref().and_then(|h| h.warm()) {
        warm.retain_servers(&cfg_all.servers).await;
    }
    let mut servers: Vec<_> = cfg_all
        .servers
        .iter()
        .map(|s| {
            let base = connections.min(s.connections.max(1) as usize);
            let cfg = PoolConfig {
                connections: match tuned.get(&s.host) {
                    Some(t) if t.connections > 0 => base.min(t.connections),
                    _ => base,
                },
                window,
                buf_pool: Some(buf_pool.clone()),
                read_timeout,
                rate: hub.as_ref().map(|h| h.rate.clone()),
                // B3: wire-side in-flight bytes are budget-exempt (window
                // × connections × ~800 KB); this cap throttles pipeline
                // top-up globally when the budget is small. Shared uses
                // the same value in every server's config - the counter
                // it gates lives on the pool's Shared state.
                inflight_cap: budget.inflight_cap(),
                // Daemon only (`hub` is absent for a one-shot CLI `get`,
                // which has no next job to hand connections to), and only
                // for a server the user has switched ON. §36: the pool is
                // off by default and settled PER SERVER, because whether
                // it helps is a property of the link - worth -19.5% on a
                // controlled 50 ms path, and indistinguishable from
                // nothing on a real jittery one. `mode=warm_bench`
                // measures this server and recommends.
                warm: match s.warm_pool {
                    true => hub.as_ref().and_then(|h| h.warm()),
                    false => None,
                },
                ..PoolConfig::default()
            };
            (s.clone(), cfg)
        })
        .collect();
    // Per-server live gauges for the dashboard (workers update, API reads).
    let pool_live = nzbkit::pool::LiveStats::for_servers(&servers);
    for (_, cfg) in servers.iter_mut() {
        cfg.live = Some(pool_live.clone());
    }
    if let Some(h) = &hub {
        *h.pool_live.lock().unwrap() = Some(pool_live.clone());
    }
    // M29 oracle: every server pool records per-article hit/430 outcomes
    // into the daemon's per-job sink (in-memory; flushed to the ledger at
    // net-drain). Context = pool host order + the NZB's dominant group's
    // family. Undated jobs are skipped (job_posted is None): their outcomes
    // have no reliable age bucket, so recording them would pollute the
    // fresh buckets and skew the takedown fingerprint.
    if let Some(sink) = hub
        .as_ref()
        .filter(|_| job_posted.is_some())
        .and_then(|h| h.oracle.lock().unwrap().clone())
    {
        sink.set_context(
            servers.iter().map(|(s, _)| s.host.clone()).collect(),
            job_family.clone(),
        );
        for (_, cfg) in servers.iter_mut() {
            cfg.oracle = Some(sink.clone());
        }
    }

    // B2: channel depth scales with the budget - a fixed 256 held up to
    // ~200 MB of raw articles OUTSIDE the budget, more than a small
    // box's entire allowance. See MemBudget::channel_depth.
    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(budget.channel_depth());
    // Consumers are dedicated OS threads (A6, constrained-CPU): decode +
    // pwrite + verify are all synchronous CPU/disk work, and running them
    // inline on tokio workers starves the socket reactor on 2-4 core
    // boxes (every worker stuck in MD5/pwrite → TCP reads stall →
    // throughput craters). A std Mutex around the receiver is fine
    // between OS threads: the handoff is microseconds against ~800 KB
    // of decode work per article, and no async scheduler hop is involved.
    let rx = Arc::new(std::sync::Mutex::new(rx));
    // The daemon shares this counter to report live queue progress.
    let decoded_bytes = progress.unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    let decode_errors = Arc::new(AtomicU64::new(0));
    // Test knob: cap the consumer (decode+write) stage to N MB/s to
    // simulate a slow disk. The correct systemic response - proven by the
    // backpressure test - is that the bounded channel fills, workers stop
    // reading sockets, TCP windows close, and providers slow to match,
    // with RSS flat. Async sleep, so pool I/O tasks stay unstarved.
    let throttle_mbps: Option<f64> = std::env::var("NZBFAST_THROTTLE_WRITE_MBPS")
        .ok()
        .and_then(|v| v.parse().ok());
    if let Some(m) = throttle_mbps {
        println!("⚠ consumer throttle active: {m} MB/s (slow-disk simulation)");
    }
    let throttle_t0 = Instant::now();

    // M15b backfill: filled by whichever consumer wins the activation
    // race; awaited (and reported) before the settle pass.
    let backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let par2_flags: Arc<Vec<bool>> = Arc::new(slots.iter().map(|s| s.is_par2_main).collect());

    // Handle for the two par2-activation spawn_blocking sites below -
    // decode threads are plain OS threads with no implicit runtime context.
    let rt = tokio::runtime::Handle::current();
    let mut consumers = Vec::new();
    // Plaintext-once D records parked until their seam bytes settle on
    // disk (see the PlacedCrypto arm below). Shared across the decode
    // threads; leftovers at join time simply refetch on resume.
    type PendingD = (usize, String, String, u64, Vec<nzbkit::extract::Frag>);
    let pending_d: Arc<std::sync::Mutex<Vec<PendingD>>> = Default::default();
    // More decode threads than cores is pure scheduler churn (measured on
    // the 2-CPU cgroup rig): the default 4 stands on big metal, small
    // boxes get one per core.
    let n_decoders = decoders
        .max(1)
        .min(std::thread::available_parallelism().map_or(usize::MAX, |n| n.get()));
    for i in 0..n_decoders {
        let rx = rx.clone();
        let pending_d = pending_d.clone();
        let pool = buf_pool.clone();
        let out_pool = out_pool.clone();
        let slots = slots.clone();
        let id_to_slot = id_to_slot.clone();
        let decoded_bytes = decoded_bytes.clone();
        let decode_errors = decode_errors.clone();
        let verifier = verifier.clone();
        let extractor = extractor.clone();
        let shape_said = shape_said.clone();
        let par2_outstanding = par2_outstanding.clone();
        let journal = journal.clone();
        let backfill = backfill.clone();
        let par2_flags = par2_flags.clone();
        let rt = rt.clone();
        let thread = std::thread::Builder::new()
            .name(format!("decode-{i}"))
            .spawn(move || {
            loop {
                // Drain a batch per lock hold: the futex wake + context
                // switch of a blocking_recv handoff is per-batch, not
                // per-article - at loopback article rates (8k+/s) the
                // per-article version tripled sys time on 2 CPUs. At NAS
                // rates the batch is 1 and behavior is identical.
                let mut batch: Vec<FetchOutcome> = Vec::with_capacity(8);
                {
                    let mut rx = rx.lock().unwrap();
                    if let Some(first) = rx.blocking_recv() {
                        batch.push(first);
                        while batch.len() < 8 {
                            match rx.try_recv() {
                                Ok(o) => batch.push(o),
                                Err(_) => break,
                            }
                        }
                    }
                }
                if batch.is_empty() {
                    break; // channel closed and drained
                }
                for outcome in batch {
                match outcome {
                    FetchOutcome::Done { id, raw } => {
                        let Some(&sidx) = id_to_slot.get(&id) else {
                            pool.give(raw);
                            continue;
                        };
                        let slot = &slots[sidx];
                        let mut out = out_pool.take();
                        // M32 perf: once live verify (full-MD5 mode) has
                        // matched this slot to a PAR2 file, the article
                        // CRC is a redundant pass over bytes the verifier
                        // hashes anyway - skip it and feed the span
                        // untrusted. First article per slot (and every
                        // article under fast verify / no PAR2) keeps it.
                        let delegated = verifier.delegates_integrity(sidx);
                        match nzbkit::yenc_simd::decode_into_integrity(
                            &raw, &mut out, !delegated,
                        ) {
                            Ok((dec, integrity)) => {
                                let crc_checked = integrity.crc_checked;
                                let name = if dec.name.is_empty() {
                                    slot.hint.clone()
                                } else {
                                    dec.name.clone()
                                };
                                match extractor.write_verified(
                                    sidx,
                                    &name,
                                    dec.file_size,
                                    dec.offset(),
                                    &out,
                                    // The checked pcrc32 over exactly these
                                    // bytes: a STORE span that is this whole
                                    // article composes from it instead of
                                    // hashing them again.
                                    integrity.verified_article_crc,
                                ) {
                                    Err(e) => {
                                        eprintln!("write {name}: {e}");
                                        decode_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Ok(persist) => {
                                    match &persist {
                                        nzbkit::extract::Persist::Placed(frags) => {
                                            if slot.is_par2_main {
                                                journal.record(&id);
                                            } else {
                                                journal.record_placed(
                                                    sidx,
                                                    &id,
                                                    extractor.slot_file_info(sidx),
                                                    &name,
                                                    dec.file_size,
                                                    frags,
                                                );
                                            }
                                        }
                                        // Plaintext-once span: parked
                                        // until its seam slivers are on
                                        // disk (usually one neighboring
                                        // article later) - a D record for
                                        // RAM-held bytes would survive a
                                        // kill the bytes did not.
                                        nzbkit::extract::Persist::PlacedCrypto(frags) => {
                                            pending_d.lock().unwrap().push((
                                                sidx,
                                                id.clone(),
                                                name.clone(),
                                                dec.file_size,
                                                frags.clone(),
                                            ));
                                        }
                                        nzbkit::extract::Persist::No => {}
                                    }
                                    // Flush every parked D whose bytes
                                    // have settled; E/K/T facts go first
                                    // so the records they support are
                                    // never orphaned.
                                    {
                                        let mut pd = pending_d.lock().unwrap();
                                        if !pd.is_empty() {
                                            let ev = extractor.drain_crypto_events();
                                            journal.record_crypto_events(&ev);
                                            pd.retain(|(sidx, id, name, size, frags)| {
                                                if extractor.crypto_span_on_disk(frags) {
                                                    journal.record_placed_crypto(
                                                        *sidx,
                                                        id,
                                                        extractor.slot_file_info(*sidx),
                                                        name,
                                                        *size,
                                                        frags,
                                                        &extractor.crypto_frag_mask(frags),
                                                    );
                                                    false
                                                } else {
                                                    true
                                                }
                                            });
                                        }
                                    }
                                    decoded_bytes
                                        .fetch_add(out.len() as u64, Ordering::Relaxed);
                                    if let Some(mbps) = throttle_mbps {
                                        let target = decoded_bytes.load(Ordering::Relaxed)
                                            as f64
                                            / (mbps * 1e6);
                                        let actual = throttle_t0.elapsed().as_secs_f64();
                                        if target > actual {
                                            // Dedicated thread: a plain sleep
                                            // stalls only this decoder.
                                            std::thread::sleep(
                                                std::time::Duration::from_secs_f64(
                                                    (target - actual).min(0.25),
                                                ),
                                            );
                                        }
                                    }
                                    if let Some(cap) = &slot.capture {
                                        // Par2 main: mirror the bytes in memory
                                        // for mid-download set activation.
                                        //
                                        // `off` is the article's declared yEnc
                                        // `begin - 1`, clamped only to >= 1 -
                                        // never to the file size. Unlike the
                                        // extractor's disk path (a sparse
                                        // write_all_at at a huge offset costs no
                                        // RAM), this resize ZERO-FILLS real
                                        // memory, so one article declaring
                                        // begin=10^15 in a file whose name merely
                                        // contains ".par2" allocated a petabyte
                                        // and aborted the daemon. A main .par2
                                        // packet is small; cap the mirror well
                                        // above any real one and drop the rest -
                                        // an oversized "main" packet is not a
                                        // set we could have activated anyway.
                                        const MAX_PAR2_CAPTURE: usize = 256 << 20;
                                        let mut buf = cap.lock().unwrap();
                                        let off = dec.offset() as usize;
                                        let end = off.saturating_add(out.len());
                                        if end <= MAX_PAR2_CAPTURE {
                                            if buf.len() < end {
                                                buf.resize(end, 0);
                                            }
                                            buf[off..end].copy_from_slice(&out);
                                        }
                                    } else if crc_checked {
                                        verifier.on_data(
                                            sidx,
                                            &dec.name,
                                            dec.file_size,
                                            dec.offset(),
                                            &out,
                                        );
                                    } else {
                                        // CRC skipped (or absent): not
                                        // decoder-vouched. Full MD5
                                        // under delegation; CRC-only
                                        // under lean (its contract).
                                        verifier.on_data_unverified(
                                            sidx,
                                            &dec.name,
                                            dec.file_size,
                                            dec.offset(),
                                            &out,
                                        );
                                    }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("decode error ({id}): {e}");
                                decode_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        out_pool.give(out);
                        pool.give(raw);
                        if slot.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
                            if extractor.is_mapped(sidx) {
                                let shape = match extractor.archive_shape() {
                                    Some(sh)
                                        if !shape_said.swap(true, Ordering::Relaxed) =>
                                    {
                                        format!(" [{}]", sh.display())
                                    }
                                    _ => String::new(),
                                };
                                println!(
                                    "  ✔ {} → extracting in-stream{shape}",
                                    slot.hint
                                );
                            } else if let Some(p) = extractor.slot_path(sidx) {
                                println!(
                                    "  ✔ {}",
                                    p.file_name().unwrap_or_default().to_string_lossy()
                                );
                            }
                            if slot.is_par2_main
                                && maybe_activate_par2(&slots, &verifier, &par2_outstanding)
                            {
                                let v = verifier.clone();
                                let ex = extractor.clone();
                                let flags = par2_flags.clone();
                                let n = slots.len();
                                *backfill.lock().unwrap() =
                                    Some(rt.spawn_blocking(move || {
                                        backfill_pre_activation(&v, &ex, n, &flags)
                                    }));
                            }
                        }
                    }
                    FetchOutcome::Missing { id } | FetchOutcome::Failed { id, .. } => {
                        if let Some(&sidx) = id_to_slot.get(&id) {
                            slots[sidx].missing.fetch_add(1, Ordering::Relaxed);
                            if slots[sidx].remaining.fetch_sub(1, Ordering::AcqRel) == 1
                                && slots[sidx].is_par2_main
                                && maybe_activate_par2(&slots, &verifier, &par2_outstanding)
                            {
                                let v = verifier.clone();
                                let ex = extractor.clone();
                                let flags = par2_flags.clone();
                                let n = slots.len();
                                *backfill.lock().unwrap() =
                                    Some(rt.spawn_blocking(move || {
                                        backfill_pre_activation(&v, &ex, n, &flags)
                                    }));
                            }
                        }
                    }
                }
                }
            }
        })
        .expect("spawn decode thread");
        consumers.push(thread);
    }

    // Live rate ticker (2 s), driven by the consumer-side decoded counter.
    // Missing-article churn shows too: a mostly-taken-down post decodes
    // nothing while the pool grinds through 430s, and without the count
    // that phase is indistinguishable from a hard stall (seen live on a
    // 12k-segment post that flatlined at "0.0 MB/s" for minutes).
    let ticker_bytes = decoded_bytes.clone();
    let ticker_slots = slots.clone();
    let ticker = tokio::spawn(async move {
        let mut last = 0u64;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = ticker_bytes.load(Ordering::Relaxed);
            let missing: usize = ticker_slots
                .iter()
                .map(|s| s.missing.load(Ordering::Relaxed))
                .sum();
            let miss = if missing > 0 {
                format!("  ({missing} missing)")
            } else {
                String::new()
            };
            println!(
                "  … {:>7.1} MB/s ({:.2} Gbps)  written {:.2} GB{miss}",
                (now - last) as f64 / 2e6,
                (now - last) as f64 * 8.0 / 2e9,
                now as f64 / 1e9
            );
            last = now;
        }
    });

    // Deadlock watchdog. A pool bug that leaves an article non-terminal
    // wedges the whole job AFTER its bytes are downloaded: fetch_all_multi
    // never returns, silently, until something external kills it (seen on
    // a 190 GB low-memory run - 3 h frozen, download complete, no output).
    // Pausing aborts the transfer rather than freezing it, and even a slow
    // server keeps moving bytes, so a fully-frozen decode counter with
    // segments still outstanding is unambiguously the deadlock. When that
    // holds, dump the pool state and abort: the stuck slot's blocks then
    // fall into PAR2 repair (usually recovered) or fail loud, and the
    // journal makes either outcome resume cleanly.
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let decoded = decoded_bytes.clone();
        let slots = slots.clone();
        let qc = queue_ctl.clone();
        let abort_flag = abort_flag.clone();
        let stalled = stalled.clone();
        let secs: u64 = std::env::var("NZBFAST_STALL_ABORT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(180);
        // Poll several times per stall window (bounded 1..=15 s) so a short
        // override fires promptly in tests and production stays low-churn.
        let poll = (secs / 4).clamp(1, 15);
        tokio::spawn(async move {
            let mut last = decoded.load(Ordering::Relaxed);
            let mut frozen = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(poll)).await;
                if abort_flag.load(Ordering::Relaxed) {
                    return;
                }
                let now = decoded.load(Ordering::Relaxed);
                if now != last {
                    last = now;
                    frozen = 0;
                    continue;
                }
                frozen += poll;
                let outstanding: usize =
                    slots.iter().map(|s| s.remaining.load(Ordering::Relaxed)).sum();
                if frozen >= secs && outstanding > 0 {
                    eprintln!(
                        "⚠ download stalled: no decode progress for {frozen}s with \
                         {outstanding} segment(s) still outstanding - the connection \
                         pool has wedged. Dumping state and aborting; the journal keeps \
                         what landed, PAR2 fills any gap, and a retry resumes."
                    );
                    qc.dump_state();
                    stalled.store(true, Ordering::Relaxed);
                    qc.abort();
                    return;
                }
            }
        })
    };

    let t0 = Instant::now();
    // M2c.5 speculative recovery prefetch: the moment ANY article goes
    // terminally Missing/Failed, damage is certain - fetch the smallest
    // recovery volume on a tiny side pool (1 conn/server; the main pool
    // owns the provider grants) so the post-settle exact-fit pass starts
    // with recovery blocks already on disk. The daemon gates this via
    // hub.spec_prefetch (off when a quota is configured - mirrors the
    // sidecar-prefetch guard); CLI runs opt out with
    // NZBFAST_NO_SPEC_PREFETCH=1. Risk is bounded to one small volume of
    // possibly-wasted bytes. Skipped when the set bootstraps from a
    // volume (one is already inbound) or the NZB ships no volumes.
    let prefetched: Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let prefetch_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spec_prefetch_task: Option<tokio::task::JoinHandle<()>> = {
        let allowed = match &hub {
            Some(h) => h.spec_prefetch.load(Ordering::Relaxed),
            None => std::env::var_os("NZBFAST_NO_SPEC_PREFETCH").is_none(),
        };
        let target = (allowed && has_main)
            .then(|| {
                nzb.files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                    .min_by_key(|(_, f)| f.bytes())
                    .map(|(fi, f)| (fi, f.bytes()))
            })
            .flatten();
        target.map(|_| {
            // Smallest-first ladder of every recovery volume: (fi, reqs,
            // declared/estimated slice count). The watcher escalates one
            // rung at a time while the missing count outruns the blocks
            // already prefetched - missing articles are CERTAIN damage,
            // so cover for the observed count is never wasted bytes.
            let mut ladder: Vec<(usize, Vec<ArticleReq>, HashMap<String, usize>, usize, u64)> =
                nzb.files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                    .map(|(fi, f)| {
                        let age_days = nzb_age_days(f.date);
                        let mut reqs = Vec::new();
                        let mut idm = HashMap::new();
                        for seg in &f.segments {
                            let b = format!("<{}>", seg.message_id);
                            idm.insert(b.clone(), fi);
                            reqs.push(ArticleReq { id: b, age_days });
                        }
                        let name = f.filename_hint().unwrap_or(&f.subject);
                        // Conservative when the name doesn't declare a
                        // count: claim 1 so escalation keeps going rather
                        // than stopping on an inflated estimate.
                        let count = vol_count_from_name(name).unwrap_or(1);
                        (fi, reqs, idm, count, f.bytes())
                    })
                    .collect();
            ladder.sort_by_key(|(_, _, _, _, bytes)| *bytes);
            let side_servers = side_pool_servers(&servers);
            let slots2 = slots.clone();
            let out2 = out_dir.clone();
            let bp = buf_pool.clone();
            let vol_cap = volume_prealloc_cap(&nzb);
            let pre = prefetched.clone();
            let stop = prefetch_stop.clone();
            tokio::spawn(async move {
                let mut covered = 0usize;
                let mut ladder = ladder;
                loop {
                    if stop.load(Ordering::Acquire) {
                        return; // network phase over - settle takes it from here
                    }
                    let miss: usize =
                        slots2.iter().map(|s| s.missing.load(Ordering::Relaxed)).sum();
                    if miss > covered {
                        // Exact-fit rung: the smallest unfetched volume
                        // covering the whole deficit (else the biggest
                        // left) - the pure smallest-first ladder
                        // over-fetched ~2x once the damage count ran
                        // ahead of the rungs.
                        let deficit = miss - covered;
                        if ladder.is_empty() {
                            return; // every volume already prefetched
                        }
                        let at = ladder
                            .iter()
                            .position(|(_, _, _, count, _)| *count >= deficit)
                            .unwrap_or(ladder.len() - 1);
                        let (fi, reqs, idm, count, bytes) = ladder.remove(at);
                        println!(
                            "[repair] {miss} article(s) terminally missing - prefetching recovery volume ({:.1} MB) alongside the download",
                            bytes as f64 / 1e6
                        );
                        match fetch_volume_articles(&side_servers, reqs, idm, &out2, &bp, vol_cap)
                            .await
                        {
                            Ok(paths) if !paths.is_empty() => {
                                covered += count.max(1);
                                pre.lock().unwrap().push((fi, paths));
                            }
                            Ok(_) => {
                                // Not one byte of that volume landed (every
                                // article failed, or it was unwritable).
                                // Claiming its blocks as covered would stall
                                // escalation, and recording the file index
                                // would strike it off the post-settle fetch
                                // list - so do neither and try the next rung.
                                println!(
                                    "[repair] that volume produced no file - trying the next one"
                                );
                            }
                            Err(e) => {
                                println!(
                                    "[repair] speculative prefetch failed ({e}) - the post-settle fetch covers it"
                                );
                                return;
                            }
                        }
                        continue; // re-check immediately - miss may have grown
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            })
        })
    };
    // D1 (big-link): the single-runtime path tops out at ~4.1 Gbps per
    // process - one I/O driver thread saturates while the NIC has headroom.
    // On big machines with enough connections, shard the fleet across
    // independent runtimes (the soak-proven fetch_all_sharded). Small
    // boxes stay on the single-runtime path: extra runtimes are pure
    // overhead below the ceiling. NZBFAST_SHARDS=n forces either way
    // (1 = force single-runtime).
    let total_conns: usize = servers.iter().map(|(_, c)| c.connections).sum();
    let shards = std::env::var("NZBFAST_SHARDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        // Clamp the operator override: each shard spins its own 2-thread
        // runtime, and an absurd value (NZBFAST_SHARDS=100000) would panic
        // on thread exhaustion and take down the download. 16 covers any
        // real fleet.
        .map(|n| n.clamp(1, 16))
        .unwrap_or_else(|| {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            if cores >= 12 && total_conns >= 24 {
                (total_conns as usize / 16).clamp(2, 4)
            } else {
                1
            }
        });
    let stats = if shards > 1 {
        println!("  sharding {total_conns} connections across {shards} I/O runtimes");
        let servers_owned = servers.clone();
        let qc = queue_ctl.clone();
        tokio::task::spawn_blocking(move || {
            nzbkit::pool::fetch_all_sharded(servers_owned, ids, tx, shards, Some(&qc))
        })
        .await
        .expect("sharded fetch panicked")
    } else {
        fetch_all_multi_ctl(&servers, ids, tx, Some(&queue_ctl)).await
    };
    // Network phase over: stop a still-waiting watcher, and let a
    // mid-fetch prefetch finish before settle harvests the directory.
    prefetch_stop.store(true, Ordering::Release);
    if let Some(t) = spec_prefetch_task {
        let _ = t.await;
    }
    // Decode threads exit when the channel closes (fetch dropped tx).
    // Join off the reactor - thread::join blocks.
    let _ = tokio::task::spawn_blocking(move || {
        for c in consumers {
            let _ = c.join();
        }
    })
    .await;
    // Final D-record flush: seams that closed after the last article's
    // own flush pass settle now; anything still RAM-held refetches on
    // resume, which is exactly the truthful record.
    {
        let mut pd = pending_d.lock().unwrap();
        if !pd.is_empty() {
            let ev = extractor.drain_crypto_events();
            journal.record_crypto_events(&ev);
            pd.retain(|(sidx, id, name, size, frags)| {
                if extractor.crypto_span_on_disk(frags) {
                    journal.record_placed_crypto(
                        *sidx,
                        id,
                        extractor.slot_file_info(*sidx),
                        name,
                        *size,
                        frags,
                        &extractor.crypto_frag_mask(frags),
                    );
                    false
                } else {
                    true
                }
            });
        }
    }
    let elapsed = t0.elapsed();
    ticker.abort();
    watchdog.abort();
    if stalled.load(Ordering::Relaxed) {
        println!(
            "  ⚠ recovered from a stalled pool by aborting the tail - \
             verifying and repairing what landed"
        );
    }
    // User cancelled: skip settle/repair/extract on the partial data.
    // The journal keeps what landed - a later retry resumes from it.
    // (Bailing drops net_done, which the daemon reads as network-drained.)
    if abort_flag.load(Ordering::Relaxed) {
        anyhow::bail!("stopped by user");
    }
    // Graceful pause: the pool admitted no new work and let every in-flight
    // article finish and journal, so a resume re-fetches only the unstarted
    // queue - nothing here is wasted. Park it like an abort (skip settle),
    // but say so: this is a clean wind-down, not a cancel.
    if queue_ctl.is_draining() {
        anyhow::bail!("paused (drained in-flight; queue kept for resume)");
    }
    // Network drained: everything from here is disk/CPU. Tell the daemon
    // so the next queued download can start soaking the line now.
    if let Some(tx) = net_done {
        let _ = tx.send(());
    }
    // Any pre-activation spans the backfill is still hashing belong to
    // this tail - wait so settle sees final block states (M15b).
    let bf = backfill.lock().unwrap().take();
    if let Some(h) = bf {
        if let Ok(fed) = h.await {
            if fed > 0 {
                println!(
                    "  » backfilled {:.1} MB of pre-activation spans during download",
                    fed as f64 / 1e6
                );
            }
        }
    }

    let total: u64 = stats.iter().map(|s| s.bytes).sum();
    println!(
        "\n{:.1} MB raw in {:.2?} → {:.1} MB/s ({:.2} Gbps); {:.1} MB written",
        total as f64 / 1e6,
        elapsed,
        total as f64 / 1e6 / elapsed.as_secs_f64(),
        total as f64 * 8.0 / 1e9 / elapsed.as_secs_f64(),
        decoded_bytes.load(Ordering::Relaxed) as f64 / 1e6,
    );
    for ((s, _), st) in servers.iter().zip(&stats) {
        println!(
            "  {:<28} {:>8.1} MB · {} conns, {} reconnects",
            s.host,
            st.bytes as f64 / 1e6,
            st.connects,
            st.reconnects
        );
    }
    let mut incomplete = 0;
    for slot in &slots {
        let miss = slot.missing.load(Ordering::Relaxed);
        let unresolved = slot.remaining.load(Ordering::Relaxed);
        if miss > 0 || unresolved > 0 {
            incomplete += 1;
            println!(
                "  ⚠ {}: {} missing, {} unresolved of {} segments",
                slot.hint, miss, unresolved, slot.total_segments
            );
        }
    }
    let derrs = decode_errors.load(Ordering::Relaxed);
    if derrs > 0 {
        println!("  ⚠ {derrs} decode/write errors");
    }
    if incomplete == 0 && derrs == 0 {
        println!("all {} files complete ✔", slots.len());
    }

    // Slots whose offset-0 article never landed are still unclassified,
    // their spans held in memory - flush them to plain files so settle
    // read-back and PAR2 repair see the bytes on disk.
    extractor.settle_unclassified()?;

    // --- settle verification (in-stream results; read-back only for gaps) ---
    let mut damage_in_mapped = false;
    let mut all_good = false;
    // The bytes on disk are fine but turning them into the output file
    // failed - a distinct failure from an incomplete or unrepaired
    // download. Holds WHICH extraction path gave up: several reach here
    // on jobs that never needed (or ran) a PAR2 repair at all, so the
    // reason travels with the flag rather than being assumed at the end.
    let mut reextract_failed: Option<&'static str> = None;
    match verifier.set() {
        Some(set) => {
            let vt0 = Instant::now();
            // Settle every slot in parallel - read-back hashing (MD5) is
            // single-thread ~0.6 GB/s, and a big-block set can push
            // gigabytes through this path.
            let settled: Vec<(usize, Option<nzbkit::live::SlotReport>)> = {
                let verifier = &verifier;
                let extractor = &extractor;
                let slot_list: Vec<usize> = slots
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| !s.is_par2_main)
                    .map(|(i, _)| i)
                    .collect();
                let next = AtomicUsize::new(0);
                let results: std::sync::Mutex<Vec<(usize, Option<nzbkit::live::SlotReport>)>> =
                    std::sync::Mutex::new(Vec::new());
                std::thread::scope(|scope| {
                    for _ in 0..std::thread::available_parallelism().map_or(4, |n| n.get()).min(12)
                    {
                        scope.spawn(|| loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= slot_list.len() {
                                break;
                            }
                            let sidx = slot_list[i];
                            // A chased slot has no file either - its bytes
                            // are in the frontier buffer - and read_at
                            // serves it byte-exact, so it takes the same
                            // reader. Sending it down the path branch
                            // would read-back against a file that does not
                            // exist and report every pending block bad.
                            let r = if extractor.is_mapped(sidx) || extractor.is_chased(sidx) {
                                let reader = |off: u64, buf: &mut [u8]| {
                                    extractor.read_at(sidx, off, buf)
                                };
                                verifier
                                    .finish_slot_from(sidx, nzbkit::live::ReadAt::Reader(&reader))
                            } else {
                                // Fully-resumed slots never created a writer
                                // this run - the run-1 file (yEnc name ==
                                // hint for unobfuscated posts) backs them.
                                let path = extractor.slot_path(sidx).or_else(|| {
                                    let p = out_dir.join(
                                        nzbkit::disk::sanitize_filename(&slots[sidx].hint),
                                    );
                                    p.exists().then_some(p)
                                });
                                verifier.finish_slot(sidx, path.as_deref())
                            };
                            results.lock().unwrap().push((sidx, r));
                        });
                    }
                });
                let mut v = results.into_inner().unwrap();
                v.sort_by_key(|(s, _)| *s);
                v
            };
            let mut reports: Vec<(usize, nzbkit::live::SlotReport)> = Vec::new();
            for (sidx, r) in settled {
                let slot = &slots[sidx];
                let mapped = extractor.is_mapped(sidx);
                if let Some(r) = r {
                    if !r.bad_blocks.is_empty() {
                        println!(
                            "  ✘ {} - {}/{} blocks bad",
                            r.par2_name.as_deref().unwrap_or(&slot.hint),
                            r.bad_blocks.len(),
                            r.total_blocks
                        );
                        if mapped {
                            damage_in_mapped = true;
                        }
                    }
                    // Deobfuscation: the PAR2 FileDesc name is the real one.
                    if let Some(pname) = &r.par2_name {
                        extractor.rename(sidx, pname);
                        // A CHASED slot is excluded from the on-disk half
                        // for the same reason a mapped one is: it has no
                        // finished file. It can now have a PARTIAL one -
                        // drop-behind trimming spills the archive's
                        // consumed prefix there - and renaming that moves
                        // the path out from under a live writer's open
                        // fd, so the rest of the spill lands in a file
                        // nothing points at.
                        if !mapped && !extractor.is_chased(sidx) {
                            if let Some(path) = extractor.slot_path(sidx) {
                                let real = nzbkit::disk::sanitize_filename(pname);
                                if path.file_name().and_then(|n| n.to_str())
                                    != Some(real.as_str())
                                {
                                    // A previous run's copy may already sit
                                    // at the real name (re-download into the
                                    // same folder). The bytes we just PAR2-
                                    // verified are authoritative - REPLACE,
                                    // never strand this download under its
                                    // obfuscated post name.
                                    //
                                    // Rename straight over it: `fs::rename`
                                    // replaces atomically on unix AND windows
                                    // (MOVEFILE_REPLACE_EXISTING), so there is
                                    // never a moment with neither file. The
                                    // old code removed the target first and
                                    // then ignored the rename's result, so a
                                    // failed rename left the good previous
                                    // copy deleted and the verified bytes
                                    // still under the obfuscated name.
                                    let target = out_dir.join(&real);
                                    let existed = target.exists();
                                    match std::fs::rename(&path, &target) {
                                        Ok(()) => println!(
                                            "  » renamed {} → {real}{}",
                                            path.file_name()
                                                .unwrap_or_default()
                                                .to_string_lossy(),
                                            if existed { " (replaced the previous copy)" } else { "" }
                                        ),
                                        Err(e) => eprintln!(
                                            "  ✘ could not publish {real}: {e} - the verified \
                                             file is still at {}",
                                            path.display()
                                        ),
                                    }
                                }
                            }
                        }
                    }
                    reports.push((sidx, r));
                }
            }
            let live: u64 = reports.iter().map(|(_, r)| r.live_blocks).sum();
            let readback: u64 = reports.iter().map(|(_, r)| r.readback_blocks).sum();
            let bad: usize = reports.iter().map(|(_, r)| r.bad_blocks.len()).sum();
            let missing_files = verifier.unclaimed_files();
            // `damage` decides WHETHER repair runs; `needed` (the deficit
            // after slices already on hand) decides how much to FETCH.
            // Conflating them skipped repair entirely whenever on-hand
            // slices covered the damage count - silent corruption with
            // exit 0 (latent for bootstrap sets, wide open once M2c.5
            // prefetched volumes mid-download).
            let mut damage = bad;
            for name in &missing_files {
                if let Some(f) = set.files.iter().find(|f| f.name == *name) {
                    damage += f.length.div_ceil(set.block_size.max(1)) as usize;
                    println!("  ✘ {} - file missing entirely", f.name);
                }
            }
            // Slices already on hand: seen while building the set (the
            // bootstrap volume) + M2c.5 prefetched volumes on disk -
            // counted from the files themselves (exact, so a partial
            // prefetch discounts only what actually landed), and their
            // NZB entries leave the fetch-candidate list.
            let mut on_hand = set.recovery_blocks_seen;
            let mut already: Vec<usize> = bootstrap_vol.into_iter().collect();
            for (fi, paths) in prefetched.lock().unwrap().iter() {
                already.push(*fi);
                for pth in paths {
                    if let Ok(bytes) = std::fs::read(pth) {
                        on_hand += nzbkit::par2repair::recovery_slice_locators(
                            &bytes,
                            &set.recovery_set_id,
                        )
                        .into_iter()
                        .filter(|(_, _, len)| *len == set.block_size as usize)
                        .count();
                    }
                }
            }
            let needed = damage.saturating_sub(on_hand);
            println!(
                "verified {} file(s): {} blocks in-stream, {} by read-back, {} bad - settled in {:.0} ms",
                reports.len(),
                live,
                readback,
                bad,
                vt0.elapsed().as_secs_f64() * 1000.0,
            );
            if damage > 0 {
                // M2c.1: first try repairing straight INTO the extracted
                // output through the block→payload mapping - no volume
                // files ever touch disk. Every declined case (gate miss,
                // I/O error, MD5 verify failure) returns false and the
                // materialize path below runs unchanged.
                let mapped_ok = if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_none() {
                    try_mapped_repair(
                        &servers,
                        &nzb,
                        out_dir,
                        &set,
                        needed,
                        &already,
                        buf_pool.clone(),
                        &extractor,
                        &reports,
                        &missing_files,
                    )
                    .await?
                } else {
                    false
                };
                // Mapped repair writes corrected plaintext through the
                // crypto shim, which refreshes chain checkpoints and
                // final-block padding. Persist those facts before any
                // crash can leave a truthful D placement paired with
                // stale pre-repair K/T records.
                journal.record_crypto_events(&extractor.drain_crypto_events());
                if mapped_ok {
                    all_good = true;
                } else {
                // PAR2 repair operates on volume FILES - materialize every
                // mapped slot of the set (complete ones too: par2 verifies
                // the whole set from disk) under its PAR2 name. A CHASED
                // slot (a posted .7z streaming out of RAM) has no file
                // either and must come down too, or par2 sees it missing
                // and tries to recreate a whole archive we are holding.
                let any_mapped = reports.iter().any(|(s, _)| extractor.is_mapped(*s));
                let any_chased = reports.iter().any(|(s, _)| extractor.is_chased(*s));
                if any_mapped || any_chased {
                    println!("materializing volumes for repair…");
                    // Only a MAPPED set needs the post-repair re-extract:
                    // a materialized .7z is the disk post-pass's input and
                    // it runs regardless, so claiming it here would send
                    // the set through reextract_dir for nothing.
                    damage_in_mapped |= any_mapped;
                    for (sidx, r) in &reports {
                        if extractor.is_mapped(*sidx) || extractor.is_chased(*sidx) {
                            if let Some(pname) = &r.par2_name {
                                extractor.rename(*sidx, pname);
                            }
                            if let Err(e) = extractor.materialize(*sidx) {
                                eprintln!("materialize slot {sidx}: {e}");
                            }
                        }
                    }
                }
                let main_par2 = {
                    let mut p = None;
                    for (sidx, slot) in slots.iter().enumerate() {
                        if slot.is_par2_main {
                            if let Some(path) = extractor.slot_path(sidx) {
                                p = Some(path);
                                break;
                            }
                        }
                    }
                    p
                };
                let repaired = fetch_and_repair(
                    &servers,
                    &nzb,
                    out_dir,
                    &set,
                    needed,
                    main_par2,
                    &already,
                    buf_pool.clone(),
                )
                .await?;
                // Repaired volume files on disk → re-extract them cleanly.
                // rc=0 requires the END state to be usable output, not
                // just a successful repair.
                //
                // Par-only post: the poster shipped a par2 set with 100%+
                // recovery and DELETED the data files - the NZB has no
                // data slots at all, so `reports` is empty and every set
                // file arrives via whole-file recreation. The recreated
                // set sits on disk exactly like a materialized one and
                // needs the same re-extract pass; without it the job
                // exits 0 with the recreated volumes still packed (the
                // nested pass skips them as the downloaded outer set).
                // A recreated bare payload passes through reextract_dir
                // untouched (no volumes → Ok(true)).
                let recreated_set = reports.is_empty() && !missing_files.is_empty();
                if repaired && (damage_in_mapped || recreated_set) {
                    all_good = reextract_dir(out_dir, password.as_deref())?;
                    if !all_good {
                        reextract_failed =
                            Some("PAR2 repair succeeded but re-extraction failed");
                    }
                } else {
                    all_good = repaired;
                    if !all_good {
                        // PAR2 could not repair - the volumes' own embedded
                        // recovery records are the last remaining redundancy.
                        all_good = try_rar_rr_repair(out_dir, password.as_deref());
                    }
                }
                } // mapped_ok else
            } else {
                println!("clean download - no repair, no post-verify pass ✔");
                all_good = true;
            }
        }
        None => {
            // No PAR2 set in the NZB (or activation failed): best-effort
            // post-download verify against whatever .par2 files landed.
            verify_dir(out_dir)?;
            all_good = incomplete == 0 && derrs == 0;
            if !all_good {
                // Missing articles left zero-filled holes and there is no
                // PAR2 to fill them - embedded RAR recovery records can.
                all_good = try_rar_rr_repair(out_dir, password.as_deref());
            }
        }
    }

    // --- extraction summary ---
    let ex_report = extractor.finish()?;
    // Named-RAR volume files of the DOWNLOADED set sitting in the output
    // dir at end-of-download (fallback groups' materialized volumes,
    // resumed runs' on-disk sets). Direct-extraction payload is subtracted
    // by name: a payload that is itself a named RAR set (RAR-in-RAR
    // release) is not an outer volume, and the nested pass below must
    // denest it rather than skip on its presence.
    let outer_vol_stems: std::collections::HashSet<String> = {
        use nzbkit::extract::release_stem;
        let payload: std::collections::HashSet<&str> =
            ex_report.extracted.iter().map(|(n, _)| n.as_str()).collect();
        std::fs::read_dir(out_dir)
            .map(|it| {
                it.flatten()
                    .map(|e| e.path())
                    .filter(|p| looks_like_named_rar(p))
                    .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .filter(|n| !payload.contains(n.as_str()))
                    .map(|n| release_stem(&n))
                    .collect()
            })
            .unwrap_or_default()
    };
    let final_shape = extractor.archive_shape();
    if !ex_report.extracted.is_empty() {
        println!(
            "extracted {} file(s) in-stream ({:.1} MB) - volumes never touched disk{}:",
            ex_report.extracted.len(),
            ex_report.extracted_bytes as f64 / 1e6,
            final_shape
                .as_ref()
                .map(|sh| format!(" [{}]", sh.display()))
                .unwrap_or_default()
        );
        for (name, size) in &ex_report.extracted {
            let lock = if ex_report.decrypted.contains(name) {
                " 🔓 decrypted"
            } else {
                ""
            };
            println!("  ▶ {name} ({:.1} MB){lock}", *size as f64 / 1e6);
        }
    } else if let Some(sh) = final_shape.as_ref() {
        // Nothing came out in-stream, so the shape has not been printed
        // anywhere yet - and it is exactly what explains why.
        println!("archive: {}", sh.display());
    }
    // Coalesce fallback reports by reason (an encrypted 180-volume set
    // would otherwise print 180 identical lines).
    let mut by_reason: std::collections::BTreeMap<&str, usize> = Default::default();
    for (_, why) in &ex_report.fallbacks {
        *by_reason.entry(why.as_str()).or_default() += 1;
    }
    for (why, n) in by_reason {
        println!("  ⚠ direct extraction fell back for {n} volume group(s): {why} - volumes on disk");
    }

    // Resumed runs skipped in-stream extraction - extract from the (now
    // verified) volume files on disk.
    if resuming && !no_extract && all_good {
        all_good = reextract_dir(out_dir, password.as_deref())?;
        if !all_good {
            reextract_failed =
                Some("resumed job: the verified volumes on disk could not be extracted");
        }
    }
    // The unrar ladder below reasons about RAR VOLUMES, so a top-level 7z
    // chase that demoted is filtered out of it entirely: that demote
    // leaves a materialized .7z, which the post-extraction pass further
    // down owns. Left in, its reason text steers all three arms wrongly -
    // "held-bytes cap" reads as an unowned set and "encrypted" as a
    // locked RAR - and each one ends at try_unrar over a directory with
    // no RAR in it, which answers false and fails a job that is fine.
    let vol_fallbacks: Vec<&(String, String)> = ex_report
        .fallbacks
        .iter()
        .filter(|(_, w)| !sevenz_disk_fallback(w))
        .collect();
    // Compressed (non-encrypted) archives can't stream-extract, but a
    // bundled unrar unpacks the verified volumes. Encrypted sets join in
    // when a password is known; without one they stay on disk.
    let enc_fallback = vol_fallbacks
        .iter()
        .any(|(_, w)| w.contains("encrypted") || w.contains("password"));
    // Every OTHER demote leaves its volumes unowned - see
    // [`fallback_needs_disk_unpack`].
    let unowned_fallback = vol_fallbacks
        .iter()
        .any(|(_, w)| fallback_needs_disk_unpack(w));
    if all_good
        && (vol_fallbacks
            .iter()
            .any(|(_, w)| w.contains("compressed"))
            || (enc_fallback && password.is_some()))
    {
        // The unrar outcome IS the job outcome here: a corrupt compressed
        // set (or a wrong password) must not exit 0 with loose volumes.
        if !try_unrar(out_dir, password.as_deref()) {
            all_good = false;
            reextract_failed = Some(
                "the verified volumes could not be unpacked \
                 (compressed set, or the password is wrong)",
            );
        }
    } else if all_good && unowned_fallback && !enc_fallback {
        if !try_unrar(out_dir, password.as_deref()) {
            all_good = false;
            reextract_failed =
                Some("the verified volumes could not be unpacked after a fallback");
        }
    } else if all_good && enc_fallback {
        println!(
            "🔒 archive is password-protected and no password was found - \
             verified volumes kept in the output directory. Supply one with \
             --password, a <meta type=\"password\"> in the NZB, or a \
             {{{{password}}}} suffix on the NZB filename, then retry."
        );
    }
    // Post-extraction pass: nested archives (a RAR whose payload is one
    // more RAR), 7z sets, and SFX payloads unpack here - the inner layer
    // only exists once the outer extraction produced it, so this is
    // inherently a second pass over the output dir. Volumes of the
    // DOWNLOADED set deliberately remain in some flows (encrypted-no-
    // password, unrar-fallback leftovers) and must never be re-processed:
    // when nothing else needs the pass they simply skip it, and when the
    // fallback unpack itself produced a nested archive beside them
    // (compressed outer wrapping a RAR/7z) they are parked in a scratch
    // hold for the pass's duration instead, so the payload still denests.
    let outer_vols_on_disk = || -> bool {
        use nzbkit::extract::release_stem;
        match std::fs::read_dir(out_dir) {
            Ok(it) => it.flatten().any(|e| {
                let p = e.path();
                looks_like_named_rar(&p)
                    && p.file_name().is_some_and(|n| {
                        outer_vol_stems.contains(&release_stem(&n.to_string_lossy()))
                    })
            }),
            Err(_) => true, // unreadable output dir: keep the conservative skip
        }
    };
    let nested_hold: Option<Option<OuterHold>> = if !(all_good && !no_extract) {
        None
    } else if !outer_vols_on_disk() {
        Some(None) // run the pass, nothing to park
    } else if nested_archive_beside_leftovers(out_dir, &outer_vol_stems) {
        match OuterHold::park(out_dir, &outer_vol_stems) {
            Ok(h) => Some(Some(h)),
            Err(e) => {
                // Park failure degrades to the historical skip - never
                // risk the pass seeing the outer set.
                println!("⚠ could not isolate leftover volumes for the nested pass: {e}");
                None
            }
        }
    } else {
        None
    };
    if let Some(hold) = nested_hold {
        let nested_res = extract_nested(out_dir, password.as_deref(), 1);
        // Restore parked volumes before judging the result - they must be
        // back in place on every path, including the failure ones.
        drop(hold);
        match nested_res {
            Ok(NestOutcome::Produced) => {}
            Ok(outcome) => {
                // A zip we cannot unpack FAILS the job when it is the
                // payload, and is forgiven when it is a sidecar.
                //
                // This used to warn either way, reasoning that failing
                // would loop *arr retries on a download that arrived
                // fine. But it did not arrive fine: if the payload is a
                // zip we cannot open, the release delivered nothing an
                // *arr can import, and Completed is a conclusion it acts
                // on - it stops looking, and the series sits stuck
                // forever. Failed is the honest answer, and it is the one
                // that makes Sonarr blocklist this release and grab a
                // usable one. The archive itself stays on disk either way.
                //
                // (There is no third status worth having. Sonarr's
                // Warning state is reachable only by claiming a disk-full
                // failure verbatim - SAB fail_message
                // "Unpacking failed, write error or disk is full?", or
                // nzbget UnpackStatus=SPACE - which would put a lie in
                // front of the user to buy a softer badge.)
                //
                // Forgiveness keys off what the PASS stopped at, never off
                // "is there a zip somewhere in the tree": a RAR/7z we could
                // not unpack is a payload we did not deliver even when an
                // unrelated `Subs/subs.zip` sits beside it.
                let zip_gap = outcome == NestOutcome::ZipGap;
                match unsupported_archive_present(out_dir) {
                    Some(u) if zip_gap && !u.blocking => println!("{}", u.message()),
                    Some(u) if zip_gap => {
                        println!("{}", u.message());
                        all_good = false;
                        reextract_failed = Some(
                            "the payload is a zip and zip extraction is not built in",
                        );
                    }
                    _ => {
                        all_good = false;
                        reextract_failed =
                            Some("an archive in the output directory could not be unpacked");
                    }
                }
            }
            Err(e) => {
                println!("⚠ nested-archive pass failed: {e}");
                all_good = false;
                reextract_failed = Some("the nested-archive pass failed");
            }
        }
    }
    // M15 memory summary - the line benchmarks quote and budgets tune.
    let (pp_peak, pp_spilled) = verifier.partials_stats();
    println!(
        "mem: peak RSS {:.2} GB · holds peak {:.0} MB · verify partials peak {:.0} MB ({pp_spilled} blocks to read-back) · budget {:.2} GB",
        nzbkit::mem::peak_rss().unwrap_or(0) as f64 / 1e9,
        extractor.holds_peak() as f64 / 1e6,
        pp_peak as f64 / 1e6,
        budget.total as f64 / 1e9,
    );

    // Download complete and verified (or repaired): the journal's job is
    // done. Anything less is a FAILED job - the daemon parks it in history
    // (an *arr must see Failed, never import an incomplete dir) and the
    // journal stays on disk so a retry fetches only what's still missing.
    if all_good {
        if let Ok(j) = Arc::try_unwrap(journal) {
            j.remove();
        }
        Ok(())
    } else if let Some(why) = reextract_failed {
        anyhow::bail!(
            "{why} - verified files left in the output directory (the log above names the archive)"
        )
    } else if incomplete > 0 || derrs > 0 {
        anyhow::bail!("{}", incomplete_reason(incomplete, derrs))
    } else {
        anyhow::bail!("verification failed and PAR2 repair could not complete")
    }
}

/// Why a download did not come out whole - as a sentence whose OPENING
/// says which of the two it was, because the daemon's policies read it.
///
/// A missing segment is the post's problem: it earns an auto-retry (
/// propagation often fills the gap) and, with failure-link reporting on,
/// it is what the indexer wants to hear about. A decode/write error with
/// nothing missing is OUR machine's problem - a full disk, a permission
/// denied, a bad sector. Folding the two into one "download incomplete:
/// N file(s) with missing segments, M decode/write errors" told the
/// indexer a healthy release was dead and armed a retry straight back
/// onto the same full disk. Both counts still appear when both happened;
/// only the leading clause decides.
fn incomplete_reason(incomplete: usize, derrs: u64) -> String {
    if incomplete > 0 {
        format!(
            "download incomplete: {incomplete} file(s) with missing segments, \
             {derrs} decode/write errors"
        )
    } else {
        format!(
            "could not write the download: {derrs} decode/write error(s) and no missing \
             segments - every article arrived, so check free space, permissions and the \
             log above"
        )
    }
}

/// A zip an extraction pass reported and could not produce, with the
/// severity a caller needs to decide what to do about it.
pub(crate) struct UnsupportedArchive {
    /// What to show the user: the archive name, prefixed with its
    /// subdirectory when it isn't at the top of the output dir.
    pub display: String,
    /// `zip` / `spanned zip` / `split zip`.
    pub shape: &'static str,
    /// Nothing else landed, so this archive IS the payload - the user
    /// got nothing they can use. False for a sidecar (a `Subs/subs.zip`
    /// beside a feature that unpacked fine): still worth a log line,
    /// not worth alarming anyone over.
    pub blocking: bool,
}

impl UnsupportedArchive {
    /// The sentence the user reads, in the log and (when blocking) on
    /// the job in history.
    fn message(&self) -> String {
        if self.blocking {
            format!(
                "⚠ unsupported archive format: {} ({}) - zip extraction is not built in, \
                 so the payload is still packed. The verified archive is in the output \
                 directory; unpack it with your own tool.",
                self.display, self.shape
            )
        } else {
            format!(
                "note: {} ({}) left packed beside the payload - zip extraction is not \
                 built in. The rest of the download is complete.",
                self.display, self.shape
            )
        }
    }
}

/// The first zip anywhere under the output dir, if any.
///
/// This is what downgrades "zip present" from a job failure to a
/// reported gap, so it has to see everything the detection side sees -
/// which since zip joined [`is_extractable_archive`] means the whole
/// tree, not just the top level: a pass now descends into a subfolder
/// zip and reports it, and a `false` this function could not explain
/// would fail the job with the wrong reason.
///
/// Traversal skips our own scratch dirs, exactly like `snapshot_recursive`.
pub(crate) fn unsupported_archive_present(root: &std::path::Path) -> Option<UnsupportedArchive> {
    // Usenet furniture is not payload: a directory holding nothing but a
    // zip and its par2 set still means the user got nothing usable.
    const FURNITURE: &[&str] = &[
        "par2", "sfv", "nfo", "nzb", "url", "txt", "srr", "srs", "diz", "md5", "sha",
        "sha256", "website",
    ];
    let mut dirs = vec![root.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        let Ok(rd) = std::fs::read_dir(&dirs[i]) else {
            i += 1;
            continue;
        };
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir())
                && !e.file_name().to_string_lossy().starts_with(".nzbfast")
            {
                dirs.push(e.path());
            }
        }
        i += 1;
    }
    dirs.sort();

    let mut first: Option<(nzbkit::zip::Finding, PathBuf)> = None;
    let mut parts: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for d in &dirs {
        for f in nzbkit::zip::scan(d) {
            parts.extend(f.parts.iter().cloned());
            if first.is_none() {
                first = Some((f, d.clone()));
            }
        }
    }
    let (found, dir) = first?;

    // Payload = anything that isn't one of the zip parts and isn't
    // furniture. If none exists, the zip is all the user got.
    let mut payload = false;
    for d in &dirs {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten() {
            if !e.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let p = e.path();
            if parts.contains(&p) {
                continue;
            }
            // Our own bookkeeping (`.nzbfast.journal`) and the OS's
            // droppings are not the user's payload - counting the journal
            // as one made every still-packed post look like it had
            // landed something usable beside the archive.
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let ext = p
                .extension()
                .map(|x| x.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !FURNITURE.contains(&ext.as_str()) {
                payload = true;
            }
        }
    }

    let display = match dir.strip_prefix(root) {
        Ok(rel) if !rel.as_os_str().is_empty() => {
            format!("{}/{}", rel.display(), found.name)
        }
        _ => found.name.clone(),
    };
    Some(UnsupportedArchive {
        display,
        shape: found.shape.label(),
        blocking: !payload,
    })
}

/// `Release.Name{{password}}.nzb` (also `{pw}` / `password=pw`) → the
/// embedded password (the conventions SABnzbd/NZBGet users and several
/// indexers rely on). Shared parser: crate::smart::name_password.
fn braces_password(nzb_path: &std::path::Path) -> Option<String> {
    let name = nzb_path.file_name()?.to_string_lossy();
    let name = name.trim_end_matches(".nzb");
    crate::smart::name_password(name).map(|(pw, _)| pw)
}

/// Is this demote one the 7z disk post-pass already owns? A top-level `.7z`
/// chase that gives up materializes its archive into the output directory,
/// which is exactly that pass's input.
///
/// It is filtered out of the unrar ladder entirely rather than added to
/// [`fallback_needs_disk_unpack`]'s exclusions, because its reason text
/// steers all three arms of that ladder and every one of them is wrong for a
/// 7z: the retention-cap wording reads as an unowned RAR set, the
/// encrypted-7z wording reads as a locked one, and both end at `try_unrar`
/// over a directory with no RAR in it - which answers false and fails a job
/// whose payload unpacks perfectly one pass later.
pub(crate) fn sevenz_disk_fallback(why: &str) -> bool {
    why.starts_with(nzbkit::extract::SEVENZ_DISK_FALLBACK_PREFIX)
}

/// Does a level-0 extraction fallback leave its volumes UNOWNED, i.e. is the
/// on-disk unrar pass the only thing left that would unpack them?
///
/// Answered by exclusion rather than by listing the demote reasons, because
/// that list was wrong twice. Memory pressure ("held-bytes cap", "incomplete
/// mapping") once let a 2 GB NAS finish a 190 GB job with 431 loose volumes
/// and exit 0; then the integrity gate's own demotes (a BLAKE2sp-only entry,
/// a stored CRC that did not match, headers that do not describe a complete
/// file) shipped a directory of loose .rar volumes with no payload at all,
/// reported Completed. A demote says "let the disk path check it", and only
/// the unrar pass actually does that: it verifies CRC32 *and* BLAKE2sp, so a
/// set that is fine unpacks and the job still succeeds (cost: double I/O),
/// while an incomplete or header-broken one fails the job honestly. Any
/// reason added later therefore lands here by default.
///
/// The exclusions are the reasons somebody else already owns:
///   - "nested fallback:" (see `extract::nested_reason`) - the inner layer is
///     already materialized and belongs to the post-extraction pass, which
///     runs the inner PAR2 repair BEFORE unpacking; unrarring it here would
///     fail on damage that repair is about to fix.
///   - encrypted / password / compressed - the caller's own branches.
///   - "not a RAR volume", "never classified", "unclassified-holds budget" -
///     the slot never was an archive, so there is no set for unrar to open
///     and it would fail a job that is fine today.
///   - "materialized for repair" - the PAR2 path demoted the group itself so
///     par2 could see the volumes on disk, and it re-extracts them (and then
///     REMOVES them) as soon as the repair lands. Running the disk pass over
///     what it leaves behind finds no volumes at all.
///
/// A demote the 7z post-pass owns never reaches here at all - see
/// [`sevenz_disk_fallback`], which filters it out of the whole ladder.
pub(crate) fn fallback_needs_disk_unpack(why: &str) -> bool {
    !why.starts_with("nested fallback:")
        && !why.contains("encrypted")
        && !why.contains("password")
        && !why.contains("compressed")
        && !why.contains("not a RAR volume")
        && !why.contains("never classified")
        && !why.contains("unclassified-holds budget")
        && !why.contains("materialized for repair")
}

/// Unpack compressed RAR volumes with a bundled/system unrar. Volumes are
/// already PAR2-verified; without a password `-p-` refuses prompts
/// (encrypted sets are left alone), `-o+` overwrites partials from
/// aborted attempts. The daemon also calls this with a job's password
/// (mode=set_password) to unlock encrypted sets after the fact.
/// First volume of the RAR set: the lowest-numbered `.partNNN.rar` at any
/// digit width (part1 / part01 / part001 - literal ".part01."/".part1."
/// matching missed 3-digit sets and let a stray sample.rar/subs.rar shadow
/// the real first volume), else the lexically first plain `.rar`.
fn first_rar_volume(rars: &[PathBuf]) -> Option<PathBuf> {
    rars.iter()
        .min_by_key(|p| {
            let n = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            let part = n.rfind(".part").and_then(|i| {
                let d: String =
                    n[i + 5..].chars().take_while(|c| c.is_ascii_digit()).collect();
                d.parse::<u64>().ok()
            });
            (part.is_none(), part.unwrap_or(0), n)
        })
        .cloned()
}

pub(crate) fn try_unrar(dir: &std::path::Path, password: Option<&str>) -> bool {
    // Test canary: encrypted-store e2e jobs must complete WITHOUT unrar
    // (native decryption); reaching here with the canary set fails the
    // job loudly instead of quietly proving nothing.
    if std::env::var_os("NZBFAST_TEST_FORBID_UNRAR").is_some() {
        println!("⚠ unrar invocation forbidden by NZBFAST_TEST_FORBID_UNRAR");
        return false;
    }
    // Sibling binary, else the copy embedded in this executable, else
    // PATH (see tools.rs).
    let unrar = tools::resolve("unrar");
    let mut first: Option<PathBuf> = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        let paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        let rars: Vec<PathBuf> = paths
            .iter()
            .filter(|p| {
                p.extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("rar"))
            })
            .cloned()
            .collect();
        first = first_rar_volume(&rars);
        if first.is_none() {
            // Numeric-only RAR sets (Name.001, .002 …) have no `.rar` to
            // start from, so this fallback used to silently no-op. The
            // lowest-numbered volume carrying the Rar! magic is the first
            // volume - unrar handles the .001 naming itself from there.
            first = paths
                .iter()
                .filter_map(|p| {
                    let ext = p.extension()?.to_string_lossy();
                    let n: u64 = ext.parse().ok()?;
                    (ext.len() >= 2).then_some((n, p))
                })
                .filter(|(_, p)| rar_magic(p))
                .min_by_key(|(n, _)| *n)
                .map(|(_, p)| p.clone());
        }
    }
    let Some(first) = first else {
        // Obfuscated posts strip extensions and rename volumes to hex, so
        // NEITHER lookup above can see one: `extension()` is None, which
        // empties the `.rar` filter and makes the numeric-extension
        // fallback's `filter_map` drop every candidate. This used to answer
        // false, and the ladder above turns that into a FAILED job - for a
        // set the obfuscated disk path unpacks perfectly.
        //
        // Sniffing happens only here, once both name-based lookups have
        // come up empty, so a set that carries names never reaches it and
        // its behaviour is untouched.
        //
        // The set cannot be pushed down the named path even with a first
        // volume in hand, which is why this hands off rather than falling
        // through: `try_rars_native` gathers siblings by `release_stem`,
        // and each hash name is its own stem, so it would feed the
        // extractor ONE volume of a split set; and the unrar subprocess
        // derives later volume names from the first one's, which for a hash
        // name names nothing on disk. Grouping by RAR header - what
        // `extract_obfuscated_rar` does - is the only thing that works on
        // this shape. For the same reason this sits AHEAD of the
        // `NZBFAST_NO_NATIVE_UNRAR` escape hatch and ignores it: that switch
        // exists to hand a set to the unrar subprocess instead, and there is
        // no version of that which unpacks this one. It still governs every
        // named set, which is all it was ever about.
        let obf = collect_obfuscated_rar_volumes(dir).unwrap_or_default();
        if obf.is_empty() {
            return false;
        }
        // Depth 1, deliberately, where a named set here keeps its volumes:
        // every caller hands this SAME directory to the depth-1 nested pass
        // immediately afterwards, and there a named set is fenced off by
        // `outer_vol_stems` while a hash name - having no stem - is not. So
        // spent volumes left lying here are extracted a second time and
        // published beside the real payload as `extracted-1-<name>`.
        // Sweeping them reaches exactly the end state that pass produces
        // today, and it is `sweep_spent_obfuscated` doing it, so its three
        // refusals (a memberless `.rev`-shaped set, no before-snapshot,
        // nothing published) still decide each set on their own.
        return extract_obfuscated_rar(dir, &obf, password, 1);
    };
    // Native in-process extraction first (vendored rars fork - measured
    // faster than unrar on every compressed-RAR bench leg); the embedded
    // unrar subprocess stays as the escape hatch for one release.
    if std::env::var_os("NZBFAST_NO_NATIVE_UNRAR").is_none() {
        println!("unpacking archive natively…");
        match try_rars_native(dir, &first, password) {
            Ok(()) => {
                println!("native unpack complete ✔");
                return true;
            }
            Err(e) => println!("⚠ native unpack failed ({e})"),
        }
        // Real download dirs can hold decoys beside the true set: same-size
        // random `.rar` files, truncated misnamed volumes (a real gauntlet
        // from SABnzbd's suite has `par2test.part1.11.rar` shadowing
        // `par2test.part1.rar`). When the chosen first volume fails, try
        // each OTHER stem group's first volume (magic-gated) before giving
        // up on native extraction.
        if let Ok(entries) = std::fs::read_dir(dir) {
            use nzbkit::extract::release_stem;
            let mut by_stem: std::collections::HashMap<String, Vec<PathBuf>> = Default::default();
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rar"))
                    && rar_magic(&p)
                {
                    let stem = p
                        .file_name()
                        .map(|n| release_stem(&n.to_string_lossy()))
                        .unwrap_or_default();
                    by_stem.entry(stem).or_default().push(p);
                }
            }
            let first_stem = first
                .file_name()
                .map(|n| release_stem(&n.to_string_lossy()))
                .unwrap_or_default();
            let mut stems: Vec<_> = by_stem.into_iter().collect();
            stems.sort_by(|a, b| a.0.cmp(&b.0));
            for (stem, group) in stems {
                if stem == first_stem {
                    continue;
                }
                let Some(group_first) = first_rar_volume(&group) else { continue };
                println!("  retrying native unpack from {}…", group_first.display());
                if try_rars_native(dir, &group_first, password).is_ok() {
                    println!("native unpack complete ✔");
                    return true;
                }
            }
        }
        println!("falling back to unrar…");
    }
    println!("unpacking archive with unrar…");
    // `-p<pw>` must be a single argument; bare `-p` would prompt and hang.
    let parg = match password {
        Some(p) if !p.is_empty() => format!("-p{p}"),
        _ => "-p-".to_string(),
    };
    // Same staging discipline as the native path: `-o+` overwrites without
    // asking, and unrar reads the volume set by path as it goes, so a member
    // named after a volume would destroy the set mid-extraction. The
    // trailing positional argument is unrar's destination directory; it is
    // relative because cwd is `dir`, and it must end in a separator.
    let staging = match ExtractStaging::new(dir) {
        Ok(s) => s,
        Err(e) => {
            println!("⚠ could not create a staging directory ({e})");
            return false;
        }
    };
    let dest_arg = {
        let mut a = std::ffi::OsString::from(
            staging.path().file_name().unwrap_or_default(),
        );
        a.push(std::path::MAIN_SEPARATOR_STR);
        a
    };
    match std::process::Command::new(&unrar)
        .args(["x", "-y", "-o+", &parg, "-idq"])
        // `first` is dir-prefixed but cwd is already `dir`; passing it verbatim
        // makes unrar resolve `dir/dir/name` and report the archive missing (a
        // spurious "wrong password / damaged" failure). Pass `./name` instead.
        .arg(std::path::Path::new(".").join(first.file_name().unwrap_or_default()))
        .arg(&dest_arg)
        .stdin(std::process::Stdio::null())
        .current_dir(dir)
        .status()
    {
        Ok(st) if st.success() && !staging.produced_anything() => {
            println!("⚠ unrar exited 0 but extracted nothing - treating as a failure");
            false
        }
        Ok(st) if st.success() => match staging.publish_into(dir) {
            Ok(()) => {
                println!("unrar complete ✔");
                true
            }
            Err(e) => {
                println!("⚠ {e}");
                false
            }
        },
        Ok(st) if password.is_some() => {
            println!("⚠ unrar exited with {st} - wrong password, or damaged volumes");
            false
        }
        Ok(st) => {
            println!("⚠ unrar exited with {st} (encrypted or damaged?)");
            false
        }
        Err(e) => {
            println!("⚠ unrar not runnable ({e}) - volumes left on disk");
            false
        }
    }
}

/// Last resort after PAR2 is exhausted: repair damaged volumes using the
/// RAR recovery records embedded in the volumes themselves (RAR5 RR and
/// RAR2/3 old-style protect records, per volume, via the vendored rars),
/// then re-attempt extraction. Extraction is the post-repair verification:
/// RAR5 RR repair does not re-checksum rebuilt shards on its own, but the
/// native extraction path CRC-verifies every entry.
///
/// Returns true only when extraction afterwards succeeds.
pub(crate) fn try_rar_rr_repair(dir: &std::path::Path, password: Option<&str>) -> bool {
    let volumes = match collect_rar_volumes(dir) {
        Ok(volumes) if !volumes.is_empty() => volumes,
        _ => return false,
    };
    println!(
        "PAR2 exhausted - trying embedded RAR recovery records on {} volume(s)…",
        volumes.len()
    );
    let mut rewritten = 0usize;
    let mut hard_failures = 0usize;
    for path in &volumes {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        match rr_repair_volume(path, password) {
            Ok(true) => {
                println!("  ✔ {name} - rewritten from recovery record");
                rewritten += 1;
            }
            Ok(false) => println!("  – {name} - no recovery record"),
            Err(e) => {
                println!("  ✘ {name} - {e}");
                hard_failures += 1;
            }
        }
    }
    if rewritten == 0 || hard_failures > 0 {
        println!("⚠ recovery-record repair could not save the set");
        return false;
    }
    try_unrar(dir, password)
}

/// Rebuild missing or destroyed RAR5 volumes from `.rev` recovery volumes
/// (WinRAR `rar rv`). Present volumes map onto the REV metadata's slots by
/// (size, crc32); every unmatched slot is reconstructed via Reed-Solomon
/// and written under the set's `partNN` naming. Returns true when at least
/// one volume was rebuilt (caller retries extraction afterwards).
fn try_rev_reconstruct(dir: &std::path::Path) -> bool {
    use rars::recovery::stream::FileSource;

    let budget = nzbkit::mem::process_budget().repair_cap();
    sweep_stale_rev_temps(dir);

    // Gather .rev files: metadata from a bounded header read, payload
    // CRC-verified by streaming. The old shape read every .rev whole, which
    // for a 60x1 GB set is 1 GB of payload per recovery volume before a
    // single byte was repaired.
    let mut rev_sources: Vec<FileSource> = Vec::new();
    let mut rev_meta: Vec<rars::rar50::Rev5VolumeRef> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return false };
    let mut rev_paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rev")))
        .collect();
    rev_paths.sort();
    for path in &rev_paths {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let source = match FileSource::open(path) {
            Ok(source) => source,
            Err(e) => {
                println!("  – {name}: unreadable .rev ({e})");
                continue;
            }
        };
        let meta = match rars::rar50::read_rev5_meta(&source) {
            Ok(meta) => meta,
            Err(e) => {
                println!("  – {name}: unusable .rev ({e})");
                continue;
            }
        };
        match rars::rar50::verify_rev5_payload(&source, &meta) {
            Ok(true) => {}
            Ok(false) => {
                println!("  – {name}: .rev payload fails its own checksum");
                continue;
            }
            Err(e) => {
                println!("  – {name}: unreadable .rev payload ({e})");
                continue;
            }
        }
        rev_sources.push(source);
        rev_meta.push(meta);
    }
    // Group the verified .rev files by the SET each describes, and try every
    // group.
    //
    // A directory can hold two unrelated releases' recovery volumes - usenet
    // posts land side by side, and nothing separates them by name. This used
    // to take whichever .rev enumerated first, keep the ones matching it, and
    // discard the rest, so the second set was never attempted even when it
    // was perfectly recoverable on its own. (Before that it failed the whole
    // vector on any mismatch, making NEITHER set recoverable.) Normal RAR
    // extraction already groups by release stem; this path now groups too -
    // by the metadata signature rather than the name, because REV metadata
    // carries no filenames.
    let same_set = |a: &rars::rar50::Rev5VolumeRef, b: &rars::rar50::Rev5VolumeRef| {
        a.meta.data_count == b.meta.data_count
            && a.meta.recovery_count == b.meta.recovery_count
            && a.meta.data_volumes == b.meta.data_volumes
            && a.payload.end - a.payload.start == b.payload.end - b.payload.start
    };
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for index in 0..rev_meta.len() {
        match groups
            .iter_mut()
            .find(|g| same_set(&rev_meta[g[0]], &rev_meta[index]))
        {
            Some(g) => g.push(index),
            None => groups.push(vec![index]),
        }
    }
    if groups.is_empty() {
        return false;
    }
    if groups.len() > 1 {
        println!(
            "  – {} independent .rev sets in this folder; trying each",
            groups.len()
        );
    }
    // rev_paths is sorted, so the grouping and the order they are tried are
    // both deterministic - a rerun reports the same thing.
    //
    // EVERY group is tried, not just up to the first that rebuilds something.
    // Stopping at the first success is the same fault this grouping exists to
    // fix, moved one level up: two damaged releases side by side would leave
    // the second unrepaired, extraction would fail on it anyway, and the .rev
    // volumes that could have saved it are never consulted again. The groups
    // are independent, so there is nothing to gain by stopping early.
    let mut rebuilt_any = false;
    for keep in &groups {
        rebuilt_any |= try_rev_group(dir, budget, keep, &rev_sources, &rev_meta);
    }
    rebuilt_any
}

/// Remove `.rev` staging temps abandoned by an earlier run.
///
/// Rebuilds are staged beside the set and renamed into place only once every
/// one of them verifies, so a crash between those renames leaves temps behind.
/// Nothing mistakes them for volumes - `collect_rar_volumes` wants a
/// `.rar`/`.rNN` name and the obfuscated path is unreachable from here - so
/// they are litter rather than a hazard, but they accumulate across crashes.
///
/// Age, not the embedded pid, decides: pids are reused, and a live repair in
/// this directory belongs to a process we must not interfere with. A repair
/// finishes in minutes even for a very large set on slow storage, so anything
/// this old is abandoned by definition.
fn sweep_stale_rev_temps(dir: &std::path::Path) {
    const ABANDONED_AFTER: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("revtmp") {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .and_then(|t| t.elapsed().map_err(std::io::Error::other))
            .is_ok_and(|age| age > ABANDONED_AFTER);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Last case-insensitive occurrence of an ASCII `needle`, as a byte offset
/// that is valid in `hay` itself. Searching a `to_lowercase()` copy instead
/// would shift every offset past a character whose lowercase form has a
/// different byte length (U+0130 lowercases to two chars), which then either
/// panics on a non-boundary slice or cuts the name in the wrong place.
fn rfind_ascii_ci(hay: &str, needle: &str) -> Option<usize> {
    let (hay, needle) = (hay.as_bytes(), needle.as_bytes());
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    // An ASCII byte never appears inside a multi-byte UTF-8 sequence, so a
    // match of an all-ASCII needle always starts on a char boundary.
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// Name for `slot` (0-based) derived from `known`, the on-disk name of the
/// volume filling slot `known_slot`: same `.partNN` pattern, same
/// zero-padding, same casing. `None` when `known` does not carry a `.part`
/// number matching its own slot, in which case we cannot infer the series.
fn derive_part_name(known: &str, known_slot: usize, slot: usize) -> Option<String> {
    let p = rfind_ascii_ci(known, ".part")?;
    let tail = &known[p + 5..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.parse::<usize>().ok()? != known_slot + 1 {
        return None;
    }
    Some(format!(
        "{}{}{:0width$}{}",
        &known[..p],
        &known[p..p + 5],
        slot + 1,
        &tail[digits.len()..],
        width = digits.len()
    ))
}

/// Rebuild what one coherent .rev set can. `keep` indexes the members of a
/// single set within `rev_sources`/`rev_meta`; returns true when at least one
/// volume was rebuilt.
fn try_rev_group(
    dir: &std::path::Path,
    budget: u64,
    keep: &[usize],
    rev_sources: &[rars::recovery::stream::FileSource],
    rev_meta: &[rars::rar50::Rev5VolumeRef],
) -> bool {
    use rars::recovery::stream::{FileSource, RangeSource};

    let first = &rev_meta[keep[0]];
    let slots = first.meta.data_volumes.clone();
    println!(
        "trying .rev recovery volumes ({} rev file(s), {} data volume slot(s))…",
        keep.len(),
        slots.len()
    );

    // Match on-disk volumes to slots by size + crc32, streamed (REV metadata
    // carries no filenames; a damaged volume simply fails to match and its
    // slot is rebuilt).
    let volumes = collect_rar_volumes(dir).unwrap_or_default();
    let mut slot_path: Vec<Option<std::path::PathBuf>> = vec![None; slots.len()];
    let mut slot_name: Vec<Option<String>> = vec![None; slots.len()];
    for path in &volumes {
        let Ok((crc, len)) = rars::recovery::stream::crc32_of(path) else { continue };
        for (i, meta) in slots.iter().enumerate() {
            if slot_path[i].is_none() && meta.file_size == len && meta.crc32 == crc {
                slot_name[i] = path.file_name().map(|n| n.to_string_lossy().into_owned());
                slot_path[i] = Some(path.clone());
                break;
            }
        }
    }
    let missing: Vec<usize> = (0..slots.len()).filter(|&i| slot_path[i].is_none()).collect();
    if missing.is_empty() {
        println!("  – all data volumes verify; .rev not needed");
        return false;
    }
    if missing.len() > keep.len() {
        println!(
            "  ✘ {} volume(s) missing but only {} usable .rev file(s) - unrepairable",
            missing.len(),
            keep.len()
        );
        return false;
    }

    // Derive names for the rebuilt slots from a matched neighbour's
    // `partNN` pattern (same zero-padding, slot index + 1).
    let derive_name = |slot: usize| -> Option<String> {
        let (i, known) = slot_name
            .iter()
            .enumerate()
            .find_map(|(i, n)| n.as_ref().map(|n| (i, n.as_str())))?;
        derive_part_name(known, i, slot)
    };

    // Intact volumes stay on disk and are read by range; only the missing
    // ones are reconstructed, each into its own temp beside the set.
    let mut intact_sources: Vec<Option<FileSource>> = Vec::with_capacity(slots.len());
    for path in &slot_path {
        intact_sources.push(match path {
            Some(path) => match FileSource::open(path) {
                Ok(source) => Some(source),
                Err(e) => {
                    println!("  ✘ {} became unreadable ({e})", path.display());
                    return false;
                }
            },
            None => None,
        });
    }
    let intact: Vec<Option<&dyn RangeSource>> = intact_sources
        .iter()
        .map(|source| source.as_ref().map(|source| source as &dyn RangeSource))
        .collect();
    let recovery: Vec<rars::rar50::Rev5RecoverySource<'_>> = keep
        .iter()
        .filter_map(|&index| {
            Some(rars::rar50::Rev5RecoverySource {
                row: rev_meta[index].row().ok()?,
                source: &rev_sources[index],
                payload: rev_meta[index].payload.clone(),
            })
        })
        .collect();

    // One temp per missing slot, created exclusively so nothing beside the
    // set is truncated and two concurrent repairs cannot share a name.
    let mut temps: Vec<(std::path::PathBuf, std::fs::File)> = Vec::new();
    let cleanup_temps = |temps: &[(std::path::PathBuf, std::fs::File)]| {
        for (path, _) in temps {
            let _ = std::fs::remove_file(path);
        }
    };
    for (slot, &index) in missing.iter().enumerate() {
        let mut made = None;
        for n in 0..1024 {
            let candidate = dir.join(format!("revtmp{}-{}-{n}", std::process::id(), slot));
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => {
                    made = Some((candidate, file));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    println!("  ✘ cannot stage a rebuild for slot {} ({e})", index + 1);
                    cleanup_temps(&temps);
                    return false;
                }
            }
        }
        let Some(made) = made else {
            println!("  ✘ no free temp name for slot {}", index + 1);
            cleanup_temps(&temps);
            return false;
        };
        temps.push(made);
    }

    let mut write_error: Option<std::io::Error> = None;
    let result = rars::rar50::repair_rev5_volumes_streaming(
        &slots,
        &intact,
        &recovery,
        first.meta.recovery_count as usize,
        budget,
        &mut |slot, offset, bytes| {
            use std::io::{Seek, Write};
            let file = &mut temps[slot].1;
            let outcome = file
                .seek(std::io::SeekFrom::Start(offset))
                .and_then(|_| file.write_all(bytes));
            if let Err(e) = outcome {
                let message = e.to_string();
                write_error = Some(e);
                return Err(rars::Error::from(std::io::Error::other(message)));
            }
            Ok(())
        },
    );
    if let Err(e) = result {
        println!("  ✘ .rev reconstruction failed ({e})");
        cleanup_temps(&temps);
        return false;
    }
    if let Some(e) = write_error {
        println!("  ✘ .rev reconstruction could not be written ({e})");
        cleanup_temps(&temps);
        return false;
    }

    // Verify every rebuild against the metadata's own checksum BEFORE any of
    // them is published. A rebuild that does not match is not a volume, and
    // publishing one would replace a known-bad file with an unknown-bad one.
    for (slot, &index) in missing.iter().enumerate() {
        let (path, file) = &mut temps[slot];
        if let Err(e) = file.sync_all() {
            println!("  ✘ could not flush the rebuild for slot {} ({e})", index + 1);
            cleanup_temps(&temps);
            return false;
        }
        match rars::recovery::stream::crc32_of(path) {
            Ok((crc, len)) if crc == slots[index].crc32 && len == slots[index].file_size => {}
            Ok(_) => {
                println!("  ✘ rebuilt slot {} fails its checksum - discarded", index + 1);
                cleanup_temps(&temps);
                return false;
            }
            Err(e) => {
                println!("  ✘ cannot verify the rebuild for slot {} ({e})", index + 1);
                cleanup_temps(&temps);
                return false;
            }
        }
    }

    // Every rebuild verified: publish them by rename, which is atomic per
    // file. Until this point nothing in the set has been touched.
    let mut rebuilt = 0usize;
    for (slot, &index) in missing.iter().enumerate() {
        let name =
            derive_name(index).unwrap_or_else(|| format!("rebuilt.part{:02}.rar", index + 1));
        let target = dir.join(&name);
        match std::fs::rename(&temps[slot].0, &target) {
            Ok(()) => {
                println!("  ✔ {name} - rebuilt from .rev");
                rebuilt += 1;
            }
            Err(e) => println!("  ✘ {name} - could not be published ({e})"),
        }
    }
    cleanup_temps(&temps);
    rebuilt > 0
}

/// Repair one volume in place from its own recovery record.
/// Ok(true) = rewritten (atomic rename), Ok(false) = no RR / unsupported
/// family (clean skip), Err = volume has RR but repair failed.
fn rr_repair_volume(path: &std::path::Path, password: Option<&str>) -> Result<bool> {
    // A UNIQUE temp we provably created, not `path.with_extension("rrtmp")`.
    //
    // The deterministic name was opened with `File::create` - truncating, and
    // symlink-following - before this code had established the archive even
    // carries a recovery record. So a legitimate `release.rrtmp` sitting
    // beside `release.rar` was destroyed and then unlinked by the cleanup
    // path, and if it was a symlink the truncation landed on whatever it
    // pointed at, outside the job entirely. Two concurrent repairs in one
    // directory also shared the name and clobbered each other.
    //
    // `create_new` means we hold a name nobody else has, and refuses to
    // follow an existing symlink; the cleanup below can then only ever
    // delete a file this invocation made.
    let (tmp, tmp_file) = {
        let mut made = None;
        for n in 0..1024 {
            let candidate = path.with_extension(format!("rrtmp{n}"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(f) => {
                    made = Some((candidate, f));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        made.ok_or_else(|| anyhow::anyhow!("no free repair temp name beside {}", path.display()))?
    };
    let cleanup = |tmp: &std::path::Path| {
        let _ = std::fs::remove_file(tmp);
    };
    let options =
        rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes));
    // Both branches below stream: the volume is read by range and the
    // repaired copy is built in the temp, so peak memory is this budget
    // rather than the volume. The old shape read the whole volume, cloned
    // it to repair into, and returned a third copy for the caller to write
    // - over 2x an 8-20 GB volume resident, none of it inside the budget.
    let budget = nzbkit::mem::process_budget().repair_cap();
    let repair_result = match rars::ArchiveReader::read_path_with_options(path, options) {
        Ok(archive) => {
            let mut dest = tmp_file;
            archive
                .repair_recovery_to_file(&mut dest, password.map(str::as_bytes), budget)
                .map(|_| ())
        }
        Err(_) => {
            // Headers too damaged to parse: raw RAR5 recovery-chunk scan,
            // over the FILE rather than a resident copy of it.
            //
            // Pass the password through: this fallback validates its own
            // reconstruction by re-parsing it, and a passwordless parse
            // reports a header-encrypted archive as NeedPassword - throwing
            // away a repair that had actually worked.
            drop(tmp_file);
            match rars::rar50::repair_inline_recovery_path(path, &tmp, options, budget) {
                Ok(_) => Ok(()),
                Err(rars::Error::UnsupportedSignature) => {
                    cleanup(&tmp);
                    anyhow::bail!("unparseable and not a RAR5 volume");
                }
                Err(e) => Err(e),
            }
        }
    };
    match repair_result {
        Ok(()) => {
            std::fs::rename(&tmp, path)?;
            Ok(true)
        }
        Err(e) => {
            cleanup(&tmp);
            // Clean skips: family has no RR support, or the volume simply
            // carries no recovery record (RAR5 "inline recovery record",
            // RAR2 "PROTECT_HEAD", RAR3 old-style all phrase it as
            // "does not contain … recovery record").
            let text = e.to_string();
            let no_record =
                text.contains("does not contain") && text.contains("recovery record");
            if no_record || matches!(e, rars::Error::UnsupportedFamilyFeature { .. }) {
                return Ok(false);
            }
            // Too large is the one failure the operator can actually act on:
            // the repair is arithmetically possible, it just needs a wider
            // working set than the configured budget allows.
            if matches!(
                e,
                rars::Error::Rar5Recovery(rars::recovery::rar5::Error::RepairTooLarge)
            ) {
                return Err(anyhow::anyhow!(
                    "{text} - raise --mem-limit (or the mem_limit setting) to repair this volume"
                ));
            }
            Err(anyhow::anyhow!("{text}"))
        }
    }
}

/// All RAR volume files in `dir`, natural volume order - same name grammar
/// as reextract_dir (.rar/.rNN by name; rollover and numeric extensions
/// only with the Rar! magic).
fn collect_rar_volumes(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    use nzbkit::extract::{release_stem, vol_sort_key};
    let mut volumes = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        let by_name = name.ends_with(".rar")
            || (name.rfind('.').is_some_and(|p| {
                let t = &name[p + 1..];
                t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
            }));
        let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            (t.len() >= 3
                && (b's'..=b'z').contains(&t.as_bytes()[0])
                && t[1..].bytes().all(|c| c.is_ascii_digit()))
                || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
        });
        if by_name || (rollover_or_numeric && rar_magic(&path)) {
            volumes.push(path);
        }
    }
    volumes.sort_by_cached_key(|p| {
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        (release_stem(&name), vol_sort_key(&name))
    });
    Ok(volumes)
}

/// Post-repair: run the store-mode extraction over repaired volume files
/// on disk (a straight remap copy - repair already verified the bytes).
fn try_rars_native(
    dir: &std::path::Path,
    first: &std::path::Path,
    password: Option<&str>,
) -> Result<()> {
    use nzbkit::extract::{release_stem, vol_sort_key};
    let first_name = first.file_name().unwrap_or_default().to_string_lossy().to_string();
    let stem = release_stem(&first_name);
    let mut volumes: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        // Same volume-name grammar as reextract_dir: .rar/.rNN by name,
        // rollover (.sNN..) and numeric (.001) only with the Rar! magic.
        let by_name = name.ends_with(".rar")
            || (name.rfind('.').is_some_and(|p| {
                let t = &name[p + 1..];
                t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
            }));
        let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            (t.len() >= 3
                && (b's'..=b'z').contains(&t.as_bytes()[0])
                && t[1..].bytes().all(|c| c.is_ascii_digit()))
                || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
        });
        if (by_name || (rollover_or_numeric && rar_magic(&path)))
            && release_stem(&name) == stem
        {
            volumes.push(path);
        }
    }
    volumes.sort_by_cached_key(|p| {
        vol_sort_key(&p.file_name().unwrap_or_default().to_string_lossy())
    });
    if volumes.is_empty() {
        anyhow::bail!("no volumes found for {first_name}");
    }
    // Parse WITH the password: header-encrypted (-hp) volumes need it just
    // to read their headers - without it every -hp set silently fell back
    // to the unrar subprocess (and failed outright where unrar is absent).
    let options = rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes));
    let archives = volumes
        .iter()
        .map(|path| rars::ArchiveReader::read_path_with_options(path, options))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing volumes: {e}"))?;
    write_archives_to(dir, &archives, password)
}

/// Stream a parsed RAR volume set out to `dir` under each entry's real
/// name, path-sanitized and bounded by the decompression-bomb guard.
/// Shared by the named-set path and the obfuscated-set path.
///
/// Output lands in an `ExtractStaging` dir and is published into `dir`
/// only once the whole set has decoded - the volumes being read are
/// reopened by path for every range, so nothing may be created beside
/// them while extraction runs.
fn write_archives_to(
    dir: &std::path::Path,
    archives: &[rars::Archive],
    password: Option<&str>,
) -> Result<()> {
    // Decompression-bomb guard: bound total extracted bytes at the target
    // filesystem's free space minus a reserve, so a crafted archive that
    // unpacks to far more than it downloaded (a store-mode "zip bomb")
    // can't fill the disk. It never trips on a legitimate large extract
    // that actually fits. Active wherever disk_stat answers, which is now
    // every platform we ship - windows included, since GetDiskFreeSpaceExW
    // landed; before that free_bytes was None there and this guard silently
    // did nothing.
    let budget = crate::serve::free_bytes(dir)
        .map(|free| free.saturating_sub(EXTRACT_RESERVE))
        .unwrap_or(u64::MAX);
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let staging = ExtractStaging::new(dir)?;
    let stage_dir = staging.path().to_path_buf();
    rars::extract_volumes_to(archives, password.map(str::as_bytes), move |meta| {
        let target = sanitized_entry_path(&stage_dir, &meta.name_lossy()).ok_or_else(|| {
            rars::Error::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "archive entry escapes output directory",
            ))
        })?;
        if meta.is_directory {
            std::fs::create_dir_all(&target)?;
            return Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>);
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::io::BufWriter::new(std::fs::File::create(target)?);
        Ok(Box::new(BombGuardWriter { inner: file, written: written.clone(), budget })
            as Box<dyn std::io::Write>)
    })
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    staging.publish_into(dir)
}

/// If `name` is a split 7-Zip part (`<base>.7z.<NNN>`), return the shared
/// base and the numeric part index.
fn split_7z_part(name: &str) -> Option<(String, u32)> {
    let (head, tail) = name.rsplit_once('.')?;
    if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    head.to_lowercase()
        .ends_with(".7z")
        .then(|| (head.to_string(), tail.parse().ok().unwrap_or(u32::MAX)))
}

/// Every 7-Zip job in `dir`: single `.7z` (or extensionless 7z-magic)
/// containers, plus `.7z.NNN` split sets grouped and ordered by part index.
/// Each job is the ordered list of on-disk parts that form one container.
fn collect_sevenz_archives(dir: &std::path::Path) -> Result<Vec<Vec<PathBuf>>> {
    use std::collections::BTreeMap;
    let mut singles: Vec<PathBuf> = Vec::new();
    let mut splits: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        if let Some((base, num)) = split_7z_part(&name) {
            splits.entry(base).or_default().insert(num, path);
        } else if name.ends_with(".7z") {
            singles.push(path);
        } else if path.extension().is_none() && sevenz_magic(&path) {
            // Obfuscated single-container 7z (extension stripped).
            singles.push(path);
        }
    }
    let mut jobs: Vec<Vec<PathBuf>> = singles.into_iter().map(|p| vec![p]).collect();
    for (_base, parts) in splits {
        jobs.push(parts.into_values().collect());
    }
    Ok(jobs)
}

/// Extract every 7-Zip job in `dir`. Split sets are concatenated into a
/// scratch container first (7z multipart is a raw byte split). Returns
/// true only if every job extracted.
///
/// Two separate scratch dirs per job, both outside the output namespace:
/// one holds the joined container, the other collects members until the
/// whole container has decoded. A `release.7z` carrying a member named
/// `release.7z` would otherwise truncate the inode still backing its own
/// reader - and putting the join temp beside the members would move that
/// same hazard onto the joined copy.
fn extract_sevenz(dir: &std::path::Path, jobs: &[Vec<PathBuf>], password: Option<&str>) -> bool {
    let mut all_ok = true;
    for parts in jobs.iter() {
        // `join` stays alive for the whole iteration: dropping it removes
        // the joined container the reader is still using.
        let (out, join, container) = match prepare_sevenz_job(dir, parts) {
            Ok(v) => v,
            Err(e) => {
                println!("⚠ {e}");
                all_ok = false;
                continue;
            }
        };
        println!("unpacking 7z archive natively…");
        let unpacked = extract_one_sevenz(out.path(), &container, password);
        match unpacked.and_then(|()| out.publish_into(dir)) {
            Ok(()) => println!("7z unpack complete ✔"),
            Err(e) => {
                println!("⚠ 7z unpack failed ({e})");
                all_ok = false;
            }
        }
        drop(join);
    }
    all_ok
}

/// Staging dirs + container path for one 7-Zip job: the output dir, the
/// scratch dir holding the joined container (multipart sets only), and the
/// container to read.
fn prepare_sevenz_job(
    dir: &std::path::Path,
    parts: &[PathBuf],
) -> Result<(ExtractStaging, Option<ExtractStaging>, PathBuf)> {
    let out = ExtractStaging::new(dir)?;
    if parts.len() == 1 {
        return Ok((out, None, parts[0].clone()));
    }
    let scratch = ExtractStaging::new(dir)?;
    let container = scratch.path().join("joined.7z");
    concat_files(parts, &container)
        .map_err(|e| anyhow::anyhow!("joining 7z split parts failed ({e})"))?;
    Ok((out, Some(scratch), container))
}

/// Concatenate `parts` (already in order) into `dest`.
fn concat_files(parts: &[PathBuf], dest: &std::path::Path) -> Result<()> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(dest)?);
    for p in parts {
        let mut f = std::fs::File::open(p)?;
        std::io::copy(&mut f, &mut out)?;
    }
    use std::io::Write as _;
    out.flush()?;
    Ok(())
}

/// Extract one 7-Zip container into `out` (an `ExtractStaging` dir, never
/// the directory holding the container), path-sanitized and bounded by the
/// same decompression-bomb guard as the RAR path.
fn extract_one_sevenz(
    out: &std::path::Path,
    container: &std::path::Path,
    password: Option<&str>,
) -> Result<()> {
    use sevenz_rust2::{ArchiveReader, Password};
    let pw = match password {
        Some(p) if !p.is_empty() => Password::from(p),
        _ => Password::empty(),
    };
    let mut reader = ArchiveReader::open(container, pw)
        .map_err(|e| anyhow::anyhow!("opening 7z: {e}"))?;
    // Staging sits on the same filesystem as the job directory, so this
    // still measures the volume the payload lands on.
    let budget = crate::serve::free_bytes(out)
        .map(|free| free.saturating_sub(EXTRACT_RESERVE))
        .unwrap_or(u64::MAX);
    let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    reader
        .for_each_entries(|entry, rd| {
            let target = sanitized_entry_path(out, &entry.name).ok_or_else(|| {
                sevenz_rust2::Error::Other("archive entry escapes output directory".into())
            })?;
            if entry.is_directory {
                std::fs::create_dir_all(&target)?;
                return Ok(true);
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut w = BombGuardWriter {
                inner: std::io::BufWriter::new(std::fs::File::create(&target)?),
                written: written.clone(),
                budget,
            };
            std::io::copy(rd, &mut w)?;
            use std::io::Write as _;
            w.flush()?;
            Ok(true)
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Headroom the decompression-bomb guard leaves free on the target
/// volume: extraction may use everything but this. Shared by the disk
/// sink, the 7z sink and the in-stream extractor so all three read the
/// same line.
const EXTRACT_RESERVE: u64 = 256 * 1024 * 1024;

/// A writer that aborts once cumulative extracted bytes cross `budget`
/// (shared across all entries of an archive set) - the decompression-bomb
/// backstop for native RAR extraction.
struct BombGuardWriter<W: std::io::Write> {
    inner: W,
    written: std::sync::Arc<std::sync::atomic::AtomicU64>,
    budget: u64,
}
impl<W: std::io::Write> std::io::Write for BombGuardWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use std::sync::atomic::Ordering;
        let n = self.inner.write(buf)?;
        let total = self.written.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
        if total > self.budget {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "extraction exceeded available disk space (possible decompression bomb)",
            ));
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Join an archive-entry name onto `dir`, rejecting traversal: absolute
/// paths, drive/UNC prefixes, and `..` components all return None.
fn sanitized_entry_path(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    sanitized_entry_path_for(dir, name, cfg!(windows))
}

/// `sanitized_entry_path` with the host as a parameter, so the Windows-only
/// guarantee is asserted by the suite on the Mac and Linux boxes we develop
/// and run CI on.
fn sanitized_entry_path_for(dir: &std::path::Path, name: &str, windows: bool) -> Option<PathBuf> {
    use std::path::Component;
    // RAR4-era archives store Windows-style separators; normalize so the
    // name splits into components on every platform.
    let name = name.replace('\\', "/");
    let entry = std::path::Path::new(name.trim_start_matches('/'));
    let mut target = dir.to_path_buf();
    let mut pushed = false;
    for component in entry.components() {
        match component {
            Component::Normal(part) => {
                // `Components` only parses a drive/UNC prefix at byte 0, so a
                // LATER component can still carry one ("sub/C:evil.dll") - and
                // `PathBuf::push` re-parses what it is given and CLEARS the
                // buffer when the pushed piece has a prefix, dropping the
                // staging dir entirely. Sanitize every component (which maps
                // ':' on Windows) so no entry name can escape.
                let part = nzbkit::disk::sanitize_filename_for(&part.to_string_lossy(), windows);
                target.push(part);
                pushed = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    // Belt and braces: nothing above may leave `dir`.
    (pushed && target.starts_with(dir)).then_some(target)
}

/// Post-repair: run the store-mode extraction over repaired volume files
/// on disk (a straight remap copy - repair already verified the bytes).
///
/// Returns `true` only when the end state is usable output: extraction
/// succeeded (volumes removed), unrar unpacked the verified volumes, or
/// the set is password-protected (verified volumes ARE the deliverable).
/// The extractor runs in protect-sources mode - a fallback must never
/// write a "materialized volume" over the very file it is reading (that
/// truncate destroyed a repaired 62-volume set in the 2026-07 damaged-post
/// bench) - and volumes feed in natural volume order so split-continuation
/// bases resolve as they arrive instead of piling into the holds cap.
/// Does the file start with the RAR marker (`Rar!`, v4 or v5)?
fn rar_magic(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .map(|_| &b == b"Rar!")
        .unwrap_or(false)
}

pub(crate) fn reextract_dir(dir: &std::path::Path, password: Option<&str>) -> Result<bool> {
    use nzbkit::extract::{Extractor, release_stem, vol_sort_key};
    let mut rars: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        // .rar / .rNN by name alone (as before). Letter-rollover
        // continuations past .r99 (.sNN/.tNN…) and WinRAR numeric volumes
        // (.001) additionally require the Rar! magic - those extensions
        // collide with subtitles/hjsplit/zip splits, and a wrongly
        // included file would flip the whole set to the unrar fallback.
        let by_name = name.ends_with(".rar")
            || (name.rfind('.').is_some_and(|p| {
                let t = &name[p + 1..];
                t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
            }));
        let rollover_or_numeric = name.rfind('.').is_some_and(|p| {
            let t = &name[p + 1..];
            (t.len() >= 3
                && (b's'..=b'z').contains(&t.as_bytes()[0])
                && t[1..].bytes().all(|c| c.is_ascii_digit()))
                || ((2..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()))
        });
        if by_name || (rollover_or_numeric && rar_magic(&path)) {
            rars.push(path);
        }
    }
    if rars.is_empty() {
        // An obfuscated set has no extension at all, so the grammar above
        // sees nothing and this used to answer Ok(true) - "extracted
        // successfully" for a pass that did no work, on a set that unpacks
        // perfectly. A later nested pass happens to rescue the daemon's own
        // callers; `smart::unlock` has no pass behind it and reports the
        // job unlocked with the payload still packed.
        //
        // Recognising the shape (rather than inventing a third outcome) is
        // both the smaller change and the honest one: the only remaining
        // empty case really has nothing to do. It also keeps the signature,
        // so no caller can read a new state wrongly.
        let obf = collect_obfuscated_rar_volumes(dir)?;
        if !obf.is_empty() {
            println!("re-extracting {} obfuscated volume(s) by header order…", obf.len());
            // Depth 1 = sweep the volumes this consumed, which is already
            // this function's contract for a set it extracted (the named
            // branch below removes its own on the same terms) and what the
            // nested pass does with them today.
            return Ok(extract_obfuscated_rar(dir, &obf, password, 1));
        }
        // Genuinely nothing packed: a bare recreated payload, an already
        // extracted directory. That IS a legitimate no-op and stays a
        // success - but it is said out loud, so no log or reader can take
        // it for "extracted".
        println!("no archive volumes on disk - nothing to re-extract");
        return Ok(true);
    }
    rars.sort_by_cached_key(|p| {
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        (release_stem(&name), vol_sort_key(&name))
    });
    println!("re-extracting {} repaired volume(s)…", rars.len());
    let ex = Extractor::new(dir, rars.len(), true);
    ex.set_protect_sources();
    // Same two bounds as the download path, with the on-disk volume set
    // standing in for the NZB's posted bytes: an inner file's declared
    // unpacked_size is still an untrusted header vint after a repair.
    let posted: u64 = rars
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .fold(0u64, u64::saturating_add);
    // 0 would mean "reserve nothing", a silent de-optimisation rather
    // than a bound - leave the ceiling off if we could not stat anything.
    if posted > 0 {
        ex.set_prealloc_ceiling(posted);
    }
    if let Some(free) = crate::serve::free_bytes(dir) {
        ex.set_extract_budget(free.saturating_sub(EXTRACT_RESERVE));
    }
    if let Some(pw) = password {
        ex.set_password(pw);
    }
    let mut buf = vec![0u8; 4 << 20];
    for (si, path) in rars.iter().enumerate() {
        use std::io::Read;
        let mut f = std::fs::File::open(path)?;
        let size = f.metadata()?.len();
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let mut off = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ex.write(si, &name, size, off, &buf[..n])?;
            off += n as u64;
        }
    }
    let rep = ex.finish()?;
    for (name, size) in &rep.extracted {
        println!("  ▶ {name} ({:.1} MB)", *size as f64 / 1e6);
    }
    for (group, why) in &rep.fallbacks {
        println!("  ⚠ '{group}': not re-extractable ({why})");
    }
    if rep.fallbacks.is_empty() && !rep.extracted.is_empty() {
        // Extraction verified (repair pass vouched for the volume bytes) -
        // the volumes served their purpose.
        for path in &rars {
            let _ = std::fs::remove_file(path);
        }
        println!("  removed {} volume file(s) after extraction", rars.len());
        return Ok(true);
    }
    if rep
        .fallbacks
        .iter()
        .all(|(_, w)| w.contains("password"))
        && !rep.fallbacks.is_empty()
        && password.is_none()
    {
        println!("  volumes are verified on disk - password required to unpack");
        return Ok(true);
    }
    println!("  falling back to unrar on the verified volumes…");
    Ok(try_unrar(dir, password))
}

/// `.volNNN+MM.par2` / `.volNNN-MMM.par2` → declared recovery-slice count.
fn vol_count_from_name(name: &str) -> Option<usize> {
    nzbkit::nzb::par2_vol_count(name)
}

/// Download the chosen recovery volumes to `out_dir` (same decode→pwrite
/// path as the main run). Shared by the disk repair path and the mapped
/// (into-the-output) path.
async fn fetch_volumes(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &PathBuf,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    file_indexes: &[usize],
) -> Result<()> {
    let mut ids: Vec<nzbkit::pool::ArticleReq> = Vec::new();
    let mut id_to_file: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for &fi in file_indexes {
        let age_days = nzb_age_days(nzb.files[fi].date);
        for seg in &nzb.files[fi].segments {
            let b = format!("<{}>", seg.message_id);
            id_to_file.insert(b.clone(), fi);
            ids.push(nzbkit::pool::ArticleReq { id: b, age_days });
        }
    }
    fetch_volume_articles(servers, ids, id_to_file, out_dir, buf_pool, volume_prealloc_cap(nzb))
        .await
        .map(|_| ())
}

/// Reservation ceiling for a recovery-volume side-fetch, the same bound
/// `main` hands the extractor: a recovery volume cannot legitimately
/// exceed the whole post, and the yEnc `size=` it declares is a poster-
/// controlled number that on Linux turns into a real `fallocate`. 0
/// posted bytes means the NZB carried no byte attributes at all - unknown,
/// not zero, so no ceiling (matching the `total_bytes() > 0` gate on
/// `set_prealloc_ceiling`).
fn volume_prealloc_cap(nzb: &Nzb) -> u64 {
    match nzb.total_bytes() {
        0 => u64::MAX,
        posted => posted,
    }
}

/// Shrink the download fleet to the one-connection-per-server side pool the
/// M2c.5 speculative prefetch runs on. The main pool already holds this
/// account's grants, so the prefetch may add exactly one connection per
/// server or the provider starts refusing them.
fn side_pool_servers(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
) -> Vec<(ServerConfig, nzbkit::pool::PoolConfig)> {
    servers
        .iter()
        .map(|(sc, pc)| {
            let mut sc = sc.clone();
            sc.connections = 1;
            let mut pc = pc.clone();
            // The POOL config is what spawns workers (pool::fetch_all_multi);
            // ServerConfig.connections was consumed when this config was
            // built, far above. Setting only that one leaves the "tiny side
            // pool" a full second fleet, opened mid-download.
            pc.connections = 1;
            // Same reason it must stay small: side-pool workers are not part
            // of the download, so they must not move the dashboard's
            // per-server gauges either.
            pc.live = None;
            (sc, pc)
        })
        .collect()
}

/// Inner driver for recovery-volume side-fetches: downloads the given
/// article set on its own small pool and assembles the volume file(s)
/// in `out_dir`. Returns the paths written (the M2c.5 prefetch counts
/// their on-disk recovery slices for the exact-fit discount).
async fn fetch_volume_articles(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    ids: Vec<nzbkit::pool::ArticleReq>,
    id_to_file: std::collections::HashMap<String, usize>,
    out_dir: &PathBuf,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    // Ceiling on what one volume writer may RESERVE - see
    // [`volume_prealloc_cap`]. u64::MAX = no ceiling.
    prealloc_cap: u64,
) -> Result<Vec<PathBuf>> {
    use nzbkit::pool::{FetchOutcome, fetch_all_multi};
    // Side-fetch: small volume sets, fast disk-writer consumer - a
    // modest fixed depth (≈25 MB) instead of the old 256 (~200 MB of
    // budget-exempt bytes on a box that may only have 256 MB total).
    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(32);
    let out_dir2 = out_dir.clone();
    let pool2 = buf_pool.clone();
    let consumer = tokio::spawn(async move {
        consume_volume_articles(rx, id_to_file, out_dir2, pool2, prealloc_cap).await
    });
    let t0 = Instant::now();
    let stats = fetch_all_multi(servers, ids, tx).await;
    let (failures, paths) = consumer.await?;
    let raw: u64 = stats.iter().map(|s| s.bytes).sum();
    println!(
        "  fetched {:.1} MB of recovery data in {:.2?}{}",
        raw as f64 / 1e6,
        t0.elapsed(),
        if failures > 0 {
            format!(" ({failures} article failures)")
        } else {
            String::new()
        }
    );
    Ok(paths)
}

/// Decode side-fetched articles onto their volume files. Returns
/// (article failures, paths actually written) - split out of
/// [`fetch_volume_articles`] so the writer-failure path is reachable from
/// a test without a server.
///
/// A volume whose writer cannot be created is DROPPED, not fatal: the
/// declared name is attacker-influenced (it may sanitise to something
/// unopenable) and the disk may be full or read-only. Panicking here took
/// the consumer task down and, with it, every other volume in the same
/// side-fetch. Absent from the returned paths means "we did not get that
/// volume", which every caller already handles - the slices are counted
/// from the files that actually landed, so nothing is over-credited.
async fn consume_volume_articles(
    mut rx: tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>,
    id_to_file: std::collections::HashMap<String, usize>,
    out_dir: PathBuf,
    buf_pool: Arc<nzbkit::pool::BufPool>,
    prealloc_cap: u64,
) -> (u32, Vec<PathBuf>) {
    use nzbkit::disk::{FileWriter, sanitize_filename};
    use nzbkit::pool::FetchOutcome;
    use std::collections::hash_map::Entry;
    use std::collections::{HashMap, HashSet};

    let mut writers: HashMap<usize, (PathBuf, Arc<FileWriter>)> = HashMap::new();
    // Volumes whose writer could not be opened. Remembered so the create
    // is attempted ONCE per volume rather than once per article - on a
    // full disk that would be thousands of failing opens - and so the
    // failure is reported once.
    let mut unwritable: HashSet<usize> = HashSet::new();
    let mut failures = 0u32;
    while let Some(outcome) = rx.recv().await {
        match outcome {
            FetchOutcome::Done { id, raw } => {
                let Some(&fi) = id_to_file.get(&id) else {
                    buf_pool.give(raw);
                    continue;
                };
                match nzbkit::yenc_simd::decode(&raw) {
                    Ok(dec) if !unwritable.contains(&fi) => {
                        let w = match writers.entry(fi) {
                            Entry::Occupied(e) => Some(&e.into_mut().1),
                            Entry::Vacant(slot) => {
                                let path = out_dir.join(sanitize_filename(&dec.name));
                                // The declared `size=` is the poster's
                                // number and on Linux preallocation is a
                                // real fallocate, so it reserves only up
                                // to the ceiling. `size` itself stays
                                // unclamped (the writer reports it).
                                match FileWriter::create_capped(
                                    &path,
                                    dec.file_size,
                                    prealloc_cap,
                                ) {
                                    Ok(f) => Some(&slot.insert((path, Arc::new(f))).1),
                                    Err(e) => {
                                        println!(
                                            "  ⚠ cannot write recovery volume {} ({e}) - skipping it",
                                            path.display()
                                        );
                                        unwritable.insert(fi);
                                        None
                                    }
                                }
                            }
                        };
                        match w {
                            Some(w) if w.write_at(dec.offset(), &dec.data).is_ok() => {}
                            _ => failures += 1,
                        }
                    }
                    _ => failures += 1,
                }
                buf_pool.give(raw);
            }
            _ => failures += 1,
        }
    }
    (failures, writers.into_values().map(|(p, _)| p).collect())
}

#[cfg(test)]
mod recovery_volume_tests {
    use super::*;
    use nzbkit::pool::{BufPool, FetchOutcome};
    use std::collections::HashMap;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbfast-vol-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// One complete single-part yEnc article body, exactly as the fetch
    /// pool hands it to the consumer. `declared` is the `size=` field -
    /// the number the POSTER controls, which is the whole point here.
    fn article(name: &str, declared: u64, data: &[u8]) -> Vec<u8> {
        nzbkit::yenc::encode(name, declared, Some((1, 1)), 1, data)
    }

    /// Drive the real consumer over `arts` = (file index, article body).
    async fn consume(
        dir: &PathBuf,
        arts: Vec<(usize, Vec<u8>)>,
        cap: u64,
    ) -> (u32, Vec<PathBuf>) {
        let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(16);
        let mut id_to_file = HashMap::new();
        for (n, (fi, body)) in arts.into_iter().enumerate() {
            let id = format!("<a{n}@test>");
            id_to_file.insert(id.clone(), fi);
            tx.send(FetchOutcome::Done { id, raw: body }).await.unwrap();
        }
        drop(tx);
        // Spawned, so a panic in the consumer surfaces as a JoinError
        // instead of unwinding the test itself - that is the assertion
        // for the panic regression below.
        tokio::spawn(consume_volume_articles(
            rx,
            id_to_file,
            dir.clone(),
            BufPool::new(4),
            cap,
        ))
        .await
        .expect("the recovery-volume consumer task must not panic")
    }

    /// BUG (HIGH): the PAR2 recovery-volume side-fetch preallocated the
    /// attacker-declared yEnc `size=` with NO ceiling - `FileWriter::create`
    /// -> `create_capped(.., u64::MAX)` -> `set_len` plus a real Linux
    /// `fallocate`. It bypassed the ceiling the extractor already had, so a
    /// small post could reserve the victim's free space on ext4/XFS.
    #[tokio::test]
    async fn a_recovery_volume_cannot_reserve_past_the_posted_ceiling() {
        let dir = temp_dir("cap");
        const HUGE: u64 = 8 << 40; // 8 TiB "declared"
        const POSTED: u64 = 1 << 20; // what the NZB actually posted
        let payload = vec![0x5Au8; 4096];

        let (failures, paths) =
            consume(&dir, vec![(0, article("set.vol000+01.par2", HUGE, &payload))], POSTED).await;

        assert_eq!(failures, 0);
        assert_eq!(paths.len(), 1);
        let len = std::fs::metadata(&paths[0]).unwrap().len();
        assert_eq!(
            len, POSTED,
            "a poster-declared volume size must not reserve past the posted ceiling"
        );
        // The cap bounds the RESERVATION only - the article's bytes still
        // land at their offset, byte for byte.
        assert_eq!(&std::fs::read(&paths[0]).unwrap()[..payload.len()], &payload[..]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// THE test that matters: a wrong fix here silently de-optimises every
    /// real download. A genuine recovery volume, whose declared size fits
    /// under the posted ceiling, must still be reserved IN FULL from the
    /// first article - not clamped to the bytes that have arrived.
    #[tokio::test]
    async fn a_legitimate_recovery_volume_still_preallocates_in_full() {
        let dir = temp_dir("cap-ok");
        const SIZE: u64 = 4_000_000; // the volume's real size
        const POSTED: u64 = 64_000_000; // the NZB's posted bytes
        let first_part = vec![0x11u8; 8192];

        let (failures, paths) =
            consume(&dir, vec![(0, article("set.vol000+02.par2", SIZE, &first_part))], POSTED)
                .await;
        assert_eq!(failures, 0);
        assert_eq!(
            std::fs::metadata(&paths[0]).unwrap().len(),
            SIZE,
            "a legitimate volume under the ceiling must be preallocated in full, \
             not clamped to the bytes received so far"
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // And with no ceiling at all: byte-for-byte the old behaviour.
        let dir = temp_dir("cap-none");
        let (_, paths) =
            consume(&dir, vec![(0, article("set.vol000+02.par2", SIZE, &first_part))], u64::MAX)
                .await;
        assert_eq!(std::fs::metadata(&paths[0]).unwrap().len(), SIZE);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The ceiling is the NZB's own posted byte count, and 0 posted bytes
    /// means "the NZB carried no byte attributes" - unknown, not zero. A
    /// 0 ceiling would reserve nothing for every volume of such a post.
    #[test]
    fn an_nzb_without_byte_attributes_gets_no_ceiling() {
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment number="1">a@test</segment></segments>
 </file>
</nzb>"#;
        let nzb = nzbkit::nzb::Nzb::parse(xml).unwrap();
        assert_eq!(nzb.total_bytes(), 0);
        assert_eq!(volume_prealloc_cap(&nzb), u64::MAX);
    }

    /// BUG (LOW): the writer was created with `.expect("create recovery
    /// volume")` inside the consumer task, so a volume that could not be
    /// opened - a name that sanitises to something unopenable, a full or
    /// read-only disk - panicked the task and took every OTHER volume in
    /// the same side-fetch with it. An unwritable volume is a volume we
    /// did not get, nothing more.
    #[tokio::test]
    async fn an_unwritable_recovery_volume_does_not_panic_the_consumer() {
        let dir = temp_dir("unwritable");
        // A directory sitting exactly where the volume file must go: the
        // create fails, deterministically, on every platform.
        std::fs::create_dir_all(dir.join("set.vol000+01.par2")).unwrap();
        let good = vec![0x22u8; 2048];

        let (failures, paths) = consume(
            &dir,
            vec![
                (0, article("set.vol000+01.par2", 1 << 20, &[1u8; 512])),
                // A second article for the SAME dead volume: the create
                // must not be retried per article, and it must still not
                // panic.
                (0, article("set.vol000+01.par2", 1 << 20, &[2u8; 512])),
                (1, article("set.vol001+02.par2", 2048, &good)),
            ],
            1 << 30,
        )
        .await;

        assert_eq!(failures, 2, "both articles of the dead volume count as failures");
        assert_eq!(paths.len(), 1, "the healthy volume of the same fetch still lands");
        assert!(paths[0].ends_with("set.vol001+02.par2"));
        assert_eq!(std::fs::read(&paths[0]).unwrap(), good);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Candidate recovery volumes of the NZB: (file idx, declared slices,
/// encoded bytes). Unknown counts get a conservative size-based estimate.
fn recovery_candidates(
    nzb: &Nzb,
    set: &nzbkit::par2::Par2Set,
    already_fetched: &[usize],
) -> Vec<(usize, usize, u64)> {
    let mut vols: Vec<(usize, usize, u64)> = Vec::new();
    for (fi, f) in nzb.files.iter().enumerate() {
        if f.kind() != FileKind::Par2Volume || already_fetched.contains(&fi) {
            continue;
        }
        let name = f.filename_hint().unwrap_or(&f.subject);
        // Blocks are block_size + ~100 bytes of packet overhead each,
        // yEnc ~2% inflation.
        let est = (f.bytes() as f64 * 0.98 / (set.block_size as f64 + 100.0)) as usize;
        let count = vol_count_from_name(name).unwrap_or(est.max(1));
        vols.push((fi, count, f.bytes()));
    }
    vols
}

/// M2c.1 - repair INTO the extracted output. When every damaged file is
/// a mapped store-mode slot, skip volume materialization entirely: read
/// present blocks through the extractor's volume view (header stash +
/// block→payload mapping over the already-extracted files), reconstruct
/// the bad ones, and patch them straight through the mapping - then the
/// whole-file MD5 self-verify runs over that same view. Success means
/// the output file is already correct: no re-extract, no volume files
/// on disk, ever.
///
/// Returns Ok(false) for every declined case (gate miss, verify fail,
/// I/O error) - the caller falls through to the materialize +
/// `repair_dir` path unchanged, which re-fetches at worst one round of
/// recovery volumes we already pulled (rare: only after a post-fetch
/// failure).
#[allow(clippy::too_many_arguments)]
async fn try_mapped_repair(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &PathBuf,
    set: &nzbkit::par2::Par2Set,
    needed: usize,
    already_fetched: &[usize],
    buf_pool: Arc<nzbkit::pool::BufPool>,
    extractor: &nzbkit::extract::Extractor,
    reports: &[(usize, nzbkit::live::SlotReport)],
    missing_files: &[String],
) -> Result<bool> {
    use nzbkit::par2repair::{VolumeIo, recovery_slice_locators, repair_mapped};
    // Gate: no whole-file losses, every set file has a verified slot
    // with a sane ledger, and every DAMAGED file is mapped (clean plain
    // files are fine - read_at serves them from their writer).
    if !missing_files.is_empty() {
        return Ok(false);
    }
    let bs = set.block_size as usize;
    let mut files: Vec<(nzbkit::par2::Par2File, Vec<bool>)> =
        Vec::with_capacity(set.files.len());
    let mut slot_of: Vec<usize> = Vec::with_capacity(set.files.len());
    for f in &set.files {
        let n = f.length.div_ceil(set.block_size) as usize;
        let Some((sidx, r)) = reports
            .iter()
            .find(|(_, r)| r.par2_name.as_deref() == Some(f.name.as_str()))
        else {
            return Ok(false);
        };
        if r.total_blocks != n || r.bad_blocks.iter().any(|&b| b >= n) {
            return Ok(false);
        }
        if !r.bad_blocks.is_empty() && !extractor.is_mapped(*sidx) {
            return Ok(false);
        }
        let mut present = vec![true; n];
        for &b in &r.bad_blocks {
            present[b] = false;
        }
        files.push((f.clone(), present));
        slot_of.push(*sidx);
    }

    // Exact-fit recovery fetch - same knapsack + margin as the disk path.
    let mut fetched_files: Vec<usize> = Vec::new();
    if needed > 0 {
        let vols = recovery_candidates(nzb, set, already_fetched);
        let have: usize = vols.iter().map(|v| v.1).sum();
        if have < needed {
            return Ok(false); // the disk path prints the unrepairable warning
        }
        let target = (needed + (needed / 10).max(2)).min(have);
        let chosen = pick_volumes(&vols, target);
        let dl_bytes: u64 = chosen.iter().map(|&i| vols[i].2).sum();
        let dl_blocks: usize = chosen.iter().map(|&i| vols[i].1).sum();
        println!(
            "repair: need {needed} block(s) → fetching {} volume(s), {} block(s), {:.1} MB",
            chosen.len(),
            dl_blocks,
            dl_bytes as f64 / 1e6
        );
        fetched_files = chosen.iter().map(|&vi| vols[vi].0).collect();
        fetch_volumes(servers, nzb, out_dir, &buf_pool, &fetched_files).await?;
    }

    // Harvest every recovery slice on disk (bootstrap + fetched volumes).
    let t0 = Instant::now();
    let mut recovery: Vec<(u32, Vec<u8>)> = Vec::new();
    for e in std::fs::read_dir(out_dir)? {
        let p = e?.path();
        if p.is_file()
            && p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
        {
            let bytes = std::fs::read(&p)?;
            for (exp, off, len) in recovery_slice_locators(&bytes, &set.recovery_set_id) {
                if len == bs {
                    recovery.push((exp, bytes[off..off + len].to_vec()));
                }
            }
        }
    }

    struct Io<'a> {
        ex: &'a nzbkit::extract::Extractor,
        slot_of: &'a [usize],
    }
    impl VolumeIo for Io<'_> {
        fn read(&self, file: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
            self.ex.read_at(self.slot_of[file], off, buf)
        }
        fn write(&self, file: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
            self.ex.patch_volume_span(self.slot_of[file], off, data)
        }
    }
    let io = Io {
        ex: extractor,
        slot_of: &slot_of,
    };
    match repair_mapped(&files, bs, &recovery, &io) {
        Ok(n) => {
            println!(
                "repair complete in {:.2?} ✔ (native, mapped: {n} block(s) rebuilt directly into the output)",
                t0.elapsed(),
            );
            Ok(true)
        }
        Err(e) => {
            println!("⚠ mapped repair declined ({e}) - falling back to volume materialization");
            Ok(false)
        }
    }
}

/// Damaged path: fetch the cheapest set of recovery volumes covering
/// `needed` blocks (exact-fit by declared slice counts), then hand the
/// directory to par2cmdline for Reed-Solomon repair.
#[allow(clippy::too_many_arguments)]
async fn fetch_and_repair(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &PathBuf,
    set: &nzbkit::par2::Par2Set,
    needed: usize,
    main_par2: Option<PathBuf>,
    already_fetched: &[usize],
    buf_pool: Arc<nzbkit::pool::BufPool>,
) -> Result<bool> {
    let mut fetched_files: Vec<usize> = Vec::new();
    if needed > 0 {
        let vols = recovery_candidates(nzb, set, already_fetched);
        let have: usize = vols.iter().map(|v| v.1).sum();
        if have < needed {
            println!(
                "⚠ unrepairable: {needed} blocks needed, only {have} recovery blocks in the NZB"
            );
            return Ok(false);
        }

        // Min-bytes subset with slice sum ≥ needed - plus ~10% margin:
        // par2's own damage count can exceed the block ledger's (a hole
        // invalidates boundary blocks under its scan), and coming up
        // short costs a whole second round-trip.
        let target = (needed + (needed / 10).max(2)).min(have);
        let chosen = pick_volumes(&vols, target);
        let dl_bytes: u64 = chosen.iter().map(|&i| vols[i].2).sum();
        let dl_blocks: usize = chosen.iter().map(|&i| vols[i].1).sum();
        println!(
            "repair: need {needed} block(s) → fetching {} volume(s), {} block(s), {:.1} MB",
            chosen.len(),
            dl_blocks,
            dl_bytes as f64 / 1e6
        );

        fetched_files = chosen.iter().map(|&vi| vols[vi].0).collect();
        fetch_volumes(servers, nzb, out_dir, &buf_pool, &fetched_files).await?;
    }

    // Reed-Solomon repair: native in-process GF(2^16) first - verifies the
    // set from disk, reconstructs missing blocks, and patches files IN
    // PLACE (no volume rewrite). Self-proving: success requires every
    // patched file to match its PAR2 whole-file MD5, so a native bug can
    // never ship bad bytes - it falls through to par2cmdline instead.
    let native_repair = || -> bool {
        if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_some() {
            return false;
        }
        let t0 = Instant::now();
        use nzbkit::par2repair::{RepairStatus, repair_dir};
        match repair_dir(out_dir) {
            Ok(RepairStatus::NoDamage) => {
                println!(
                    "repair complete in {:.2?} ✔ (native - set already verifies on disk)",
                    t0.elapsed()
                );
                true
            }
            Ok(RepairStatus::Repaired(r)) => {
                println!(
                    "repair complete in {:.2?} ✔ (native, in place: {} block(s) rebuilt across {} file(s){}{})",
                    t0.elapsed(),
                    r.blocks_rebuilt,
                    r.files_patched.len(),
                    if r.files_created.is_empty() {
                        String::new()
                    } else {
                        format!(", {} recreated", r.files_created.len())
                    },
                    if r.blocks_adopted == 0 {
                        String::new()
                    } else {
                        format!(
                            ", {} block(s) adopted from {}",
                            r.blocks_adopted,
                            r.adopted_from.join(", ")
                        )
                    },
                );
                true
            }
            Ok(RepairStatus::Unrepairable { needed, have }) => {
                println!(
                    "⚠ native repair: {needed} block(s) damaged, only {have} recovery block(s) on disk"
                );
                false
            }
            Err(e) => {
                println!("⚠ native repair failed ({e}) - falling back to par2cmdline");
                false
            }
        }
    };
    if native_repair() {
        return Ok(true);
    }

    // par2cmdline fallback - the escape hatch for anything the native
    // path declines (see par2repair.rs module docs).
    let Some(main_par2) = main_par2 else {
        println!("⚠ no main .par2 on disk - cannot invoke par2cmdline");
        return Ok(false);
    };
    let t0 = Instant::now();
    // Sibling binary, else PATH (see tools.rs).
    let par2_bin = tools::resolve("par2");
    // par2cmdline 1.2.0 rejects absolute par2 paths ("failed to set the
    // main par file") - pass the bare name and set cwd.
    let par2_name = main_par2
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_else(|| main_par2.clone().into_os_string());
    // Every non-par2 file in the dir rides along as an extra file so
    // par2cmdline's sliding scan can adopt misnamed/shifted data - bare
    // `par2 repair <set>` never looks at files it wasn't told about.
    let extra_files: Vec<std::ffi::OsString> = std::fs::read_dir(out_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let e = e.ok()?;
            let p = e.path();
            (e.file_type().ok()?.is_file()
                && !p
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("par2")))
            .then(|| p.file_name().map(|n| n.to_owned()))?
        })
        .take(1000)
        .collect();
    // par2cmdline parses any leading-dash argument as a SWITCH, and both the
    // set name and every extra filename are attacker-controlled (they come
    // from yEnc/subject names; sanitize_filename keeps a leading '-'). A file
    // named `-p` would trigger "purge", `-B<path>` would redirect the
    // basepath, etc. Prefix each with `./` (platform-correct via Path::join,
    // cwd is out_dir) so they can only ever be read as paths.
    let dot = std::path::Path::new(".");
    let par2_arg = dot.join(&par2_name);
    let extra_args: Vec<std::path::PathBuf> = extra_files.iter().map(|f| dot.join(f)).collect();
    match std::process::Command::new(&par2_bin)
        .arg("repair")
        .arg("-q")
        .arg(&par2_arg)
        .args(&extra_args)
        .current_dir(out_dir)
        .status()
    {
        Ok(st) if st.success() => {
            println!("repair complete in {:.2?} ✔", t0.elapsed());
            return Ok(true);
        }
        Ok(st) => println!("⚠ par2 repair exited with {st}"),
        Err(e) => {
            // par2 is no longer embedded - native repair covers real
            // sets, so reaching this needs both an exotic failure AND
            // no external par2 on PATH or next to the executable.
            println!(
                "⚠ this set needs an external par2 (native repair could not handle it), \
                 but none was runnable ({e}) - install par2cmdline (e.g. brew install par2) \
                 or place a par2 binary next to nzbfast"
            );
            return Ok(false);
        }
    }

    // Escalation: par2's own damage accounting can exceed the ledger's -
    // fetch every remaining recovery volume and try once more.
    let remaining: Vec<usize> = recovery_candidates(nzb, set, already_fetched)
        .iter()
        .map(|v| v.0)
        .filter(|fi| !fetched_files.contains(fi))
        .collect();
    if remaining.is_empty() {
        return Ok(false);
    }
    println!("repair short - fetching all {} remaining volume(s)", remaining.len());
    fetch_volumes(servers, nzb, out_dir, &buf_pool, &remaining).await?;
    if native_repair() {
        return Ok(true);
    }
    match std::process::Command::new(&par2_bin)
        .arg("repair")
        .arg("-q")
        .arg(&par2_arg)
        .args(&extra_args)
        .current_dir(out_dir)
        .status()
    {
        Ok(st) if st.success() => {
            println!("repair complete (second pass) ✔");
            Ok(true)
        }
        _ => {
            println!("⚠ repair failed even with every recovery volume");
            Ok(false)
        }
    }
}

/// Indexes into `vols` = (file, slices, bytes) minimizing downloaded bytes
/// subject to Σ slices ≥ needed. Exact 0/1 knapsack with an explicit
/// chosen-set bitmask (recovery sets virtually never exceed 64 volumes);
/// beyond 64, greedy by cost-per-slice.
fn pick_volumes(vols: &[(usize, usize, u64)], needed: usize) -> Vec<usize> {
    if vols.len() > 64 {
        let mut order: Vec<usize> = (0..vols.len()).collect();
        order.sort_by(|&a, &b| {
            (vols[a].2 * vols[b].1 as u64).cmp(&(vols[b].2 * vols[a].1 as u64))
        });
        let mut chosen = Vec::new();
        let mut got = 0usize;
        for vi in order {
            if got >= needed {
                break;
            }
            chosen.push(vi);
            got += vols[vi].1;
        }
        return chosen;
    }
    // dp[d] = (bytes, mask) - cheapest way to cover a deficit of ≥ d blocks.
    let n = needed;
    const INF: u64 = u64::MAX;
    let mut dp: Vec<(u64, u64)> = vec![(INF, 0); n + 1];
    dp[0] = (0, 0);
    for (vi, &(_, slices, bytes)) in vols.iter().enumerate() {
        for d in (0..=n).rev() {
            let (cost, mask) = dp[d];
            if cost == INF {
                continue;
            }
            let nd = (d + slices).min(n);
            let ncost = cost + bytes;
            if ncost < dp[nd].0 {
                dp[nd] = (ncost, mask | (1u64 << vi));
            }
        }
    }
    let mask = dp[n].1;
    (0..vols.len()).filter(|vi| mask & (1u64 << vi) != 0).collect()
}

#[cfg(test)]
mod rev_recovery_tests {
    use super::*;
    use rars::recovery::rar5::encode_parity_shards;
    use std::path::Path;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-rev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Writes a synthetic RAR volume set plus its `.rev` recovery volumes
    /// into `dir`, and returns the data volumes' bytes in slot order.
    ///
    /// The "volumes" are opaque byte blobs: `try_rev_reconstruct` matches
    /// them to REV slots by size and CRC32 alone and never parses them, so
    /// real RAR framing would only slow the test down. `mangle_parity`
    /// builds a `.rev` whose payload checksum is self-consistent but whose
    /// parity is wrong, to exercise the verify-before-publish gate.
    fn build_set(dir: &Path, sizes: &[usize], recovery_count: usize, mangle_parity: bool)
    -> Vec<Vec<u8>> {
        build_named_set(dir, "set", sizes, recovery_count, mangle_parity)
    }

    /// As `build_set`, under an explicit release name so a test can put two
    /// independent sets in one directory.
    fn build_named_set(
        dir: &Path,
        release: &str,
        sizes: &[usize],
        recovery_count: usize,
        mangle_parity: bool,
    ) -> Vec<Vec<u8>> {
        let data: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(index, &len)| {
                (0..len).map(|byte| (byte * 7 + index * 29 + 11) as u8).collect()
            })
            .collect();
        for (index, volume) in data.iter().enumerate() {
            std::fs::write(dir.join(format!("{release}.part{:02}.rar", index + 1)), volume).unwrap();
        }

        let mut shard_len = *sizes.iter().max().unwrap();
        shard_len += shard_len & 1;
        let padded: Vec<Vec<u8>> = data
            .iter()
            .map(|volume| {
                let mut shard = vec![0u8; shard_len];
                shard[..volume.len()].copy_from_slice(volume);
                shard
            })
            .collect();
        let refs: Vec<&[u8]> = padded.iter().map(Vec::as_slice).collect();
        let mut parity = encode_parity_shards(&refs, recovery_count).unwrap();
        if mangle_parity {
            for row in &mut parity {
                row[0] ^= 0xff;
            }
        }

        let data_count = data.len() as u16;
        for row in 0..recovery_count {
            let payload = &parity[row];
            let mut body = Vec::new();
            body.push(1u8);
            body.extend_from_slice(&data_count.to_le_bytes());
            body.extend_from_slice(&(recovery_count as u16).to_le_bytes());
            body.extend_from_slice(&((data_count as usize + row) as u16).to_le_bytes());
            body.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
            for volume in &data {
                body.extend_from_slice(&(volume.len() as u64).to_le_bytes());
                body.extend_from_slice(&crc32fast::hash(volume).to_le_bytes());
            }
            let mut rev = Vec::new();
            rev.extend_from_slice(b"Rar!\x1aRev");
            rev.extend_from_slice(&[0u8; 4]);
            rev.extend_from_slice(&(body.len() as u32).to_le_bytes());
            rev.extend_from_slice(&body);
            let header_crc = crc32fast::hash(&rev[12..16 + body.len()]);
            rev[8..12].copy_from_slice(&header_crc.to_le_bytes());
            rev.extend_from_slice(payload);
            std::fs::write(dir.join(format!("{release}.part{:02}.rev", row + 1)), &rev).unwrap();
        }
        data
    }

    /// Every file in `dir` with its bytes, for asserting nothing moved.
    fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn rev_reconstruct_rebuilds_a_missing_volume_and_leaves_the_others_alone() {
        let dir = temp_dir("rebuild");
        let data = build_set(&dir, &[600, 512, 480, 640], 2, false);
        let gone = dir.join("set.part02.rar");
        std::fs::remove_file(&gone).unwrap();
        let before = snapshot(&dir);

        assert!(try_rev_reconstruct(&dir));

        assert_eq!(
            std::fs::read(&gone).unwrap(),
            data[1],
            "the rebuilt volume must be byte-exact"
        );
        for (name, bytes) in &before {
            assert_eq!(
                &std::fs::read(dir.join(name)).unwrap(),
                bytes,
                "{name} was modified by a repair that did not concern it"
            );
        }
        assert!(
            !snapshot(&dir).keys().any(|name| name.starts_with("revtmp")),
            "no staging temp may survive a successful repair"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_rebuilds_two_missing_volumes_from_two_recovery_volumes() {
        let dir = temp_dir("rebuild-two");
        let data = build_set(&dir, &[600, 512, 480, 640], 2, false);
        std::fs::remove_file(dir.join("set.part01.rar")).unwrap();
        std::fs::remove_file(dir.join("set.part04.rar")).unwrap();

        assert!(try_rev_reconstruct(&dir));

        assert_eq!(std::fs::read(dir.join("set.part01.rar")).unwrap(), data[0]);
        assert_eq!(std::fs::read(dir.join("set.part04.rar")).unwrap(), data[3]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_repairs_a_damaged_volume_in_place() {
        let dir = temp_dir("damaged");
        let data = build_set(&dir, &[600, 512, 480], 1, false);
        // Present but corrupt: it fails the slot's CRC, so its slot is
        // rebuilt and the bad file is replaced.
        let damaged = dir.join("set.part03.rar");
        let mut bytes = std::fs::read(&damaged).unwrap();
        bytes[10..60].fill(0x5a);
        std::fs::write(&damaged, &bytes).unwrap();

        assert!(try_rev_reconstruct(&dir));
        assert_eq!(std::fs::read(&damaged).unwrap(), data[2]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_leaves_everything_alone_when_there_is_too_much_damage() {
        let dir = temp_dir("too-much");
        build_set(&dir, &[600, 512, 480, 640], 1, false);
        // Two gone, one recovery volume: unrepairable arithmetic.
        std::fs::remove_file(dir.join("set.part01.rar")).unwrap();
        std::fs::remove_file(dir.join("set.part03.rar")).unwrap();
        let before = snapshot(&dir);

        assert!(!try_rev_reconstruct(&dir));

        assert_eq!(snapshot(&dir), before, "a refused repair must change nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_publishes_nothing_when_a_rebuild_fails_its_checksum() {
        let dir = temp_dir("bad-parity");
        // The .rev's payload checksum is self-consistent, so it survives
        // every earlier gate - but the parity is wrong, so the rebuild it
        // produces cannot match the slot. Publishing that would replace a
        // known-missing volume with a silently wrong one.
        build_set(&dir, &[600, 512, 480], 1, true);
        std::fs::remove_file(dir.join("set.part02.rar")).unwrap();
        let before = snapshot(&dir);

        assert!(!try_rev_reconstruct(&dir));

        assert_eq!(snapshot(&dir), before, "nothing may be published or left behind");
        assert!(!dir.join("set.part02.rar").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_ignores_a_corrupt_recovery_volume() {
        let dir = temp_dir("corrupt-rev");
        build_set(&dir, &[600, 512, 480], 1, false);
        std::fs::remove_file(dir.join("set.part02.rar")).unwrap();
        // Corrupt the .rev payload itself: it fails its own declared CRC and
        // must be dropped rather than solved against.
        let rev = dir.join("set.part01.rev");
        let mut bytes = std::fs::read(&rev).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&rev, &bytes).unwrap();
        let before = snapshot(&dir);

        assert!(!try_rev_reconstruct(&dir));
        assert_eq!(snapshot(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_repairs_every_independent_set_in_one_folder() {
        // Two unrelated releases' recovery volumes side by side, BOTH with a
        // volume missing. Grouping alone is not enough: stopping at the first
        // group that rebuilds something leaves the second release broken, its
        // extraction fails anyway, and the .rev files that could have saved it
        // are never consulted again.
        let dir = temp_dir("two-sets");
        // Different slot geometry, so the two sets cannot be confused.
        let alpha = build_named_set(&dir, "alpha", &[600, 512, 480], 1, false);
        let beta = build_named_set(&dir, "beta", &[300, 256, 240, 288], 1, false);
        std::fs::remove_file(dir.join("alpha.part02.rar")).unwrap();
        std::fs::remove_file(dir.join("beta.part03.rar")).unwrap();

        assert!(try_rev_reconstruct(&dir));

        assert_eq!(
            std::fs::read(dir.join("alpha.part02.rar")).unwrap(),
            alpha[1],
            "the first set was not rebuilt"
        );
        assert_eq!(
            std::fs::read(dir.join("beta.part03.rar")).unwrap(),
            beta[2],
            "the second set was skipped once the first succeeded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_repairs_the_healthy_set_when_another_is_unrecoverable() {
        // One set beyond saving must not stop the other from being repaired.
        let dir = temp_dir("one-doomed");
        let alpha = build_named_set(&dir, "alpha", &[600, 512, 480], 1, false);
        build_named_set(&dir, "beta", &[300, 256, 240, 288], 1, false);
        std::fs::remove_file(dir.join("alpha.part02.rar")).unwrap();
        // Two gone from beta against a single recovery volume: unrepairable.
        std::fs::remove_file(dir.join("beta.part01.rar")).unwrap();
        std::fs::remove_file(dir.join("beta.part03.rar")).unwrap();

        assert!(try_rev_reconstruct(&dir));
        assert_eq!(std::fs::read(dir.join("alpha.part02.rar")).unwrap(), alpha[1]);
        assert!(!dir.join("beta.part01.rar").exists());
        assert!(!dir.join("beta.part03.rar").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_sweeps_temps_abandoned_by_an_earlier_crash() {
        // A crash between the verify and the renames leaves staging temps.
        // Old ones are abandoned by definition and get cleared; a fresh one
        // may belong to a repair running right now and must be left alone.
        let dir = temp_dir("stale-temps");
        build_set(&dir, &[600, 512, 480], 1, false);
        let stale = dir.join("revtmp999999-0-0");
        let fresh = dir.join("revtmp999998-0-0");
        std::fs::write(&stale, b"abandoned").unwrap();
        std::fs::write(&fresh, b"in flight").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();

        // Nothing is missing, so this returns false - the sweep still runs.
        assert!(!try_rev_reconstruct(&dir));
        assert!(!stale.exists(), "an abandoned temp must be cleared");
        assert!(fresh.exists(), "a temp that may be in flight must be left");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rev_reconstruct_does_nothing_when_the_set_is_already_whole() {
        let dir = temp_dir("whole");
        build_set(&dir, &[600, 512, 480], 1, false);
        let before = snapshot(&dir);

        assert!(!try_rev_reconstruct(&dir));
        assert_eq!(snapshot(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The neighbour's name is sliced at offsets found by a case-insensitive
    /// search, so characters whose lowercase form is a different byte length
    /// must not shift them. U+0130 (İ, 2 bytes) lowercases to 3 bytes and
    /// U+1E9E (ẞ, 3 bytes) to 2, one shift in each direction; a `to_lowercase()`
    /// copy would put `.part` at the wrong offset and panic or mangle the name.
    #[test]
    fn derived_part_names_survive_length_changing_case() {
        // "İstanbul" + "ẞ" - two chars whose lowercase byte length differs.
        for stem in ["\u{130}stanbul", "Gru\u{1e9e}e", "\u{130}\u{1e9e}x", "Plain"] {
            let known = format!("{stem}.part03.rar");
            let got = derive_part_name(&known, 2, 6).expect("neighbour names its own slot");
            assert_eq!(got, format!("{stem}.part07.rar"));
            // The prefix must come out of the original string untouched.
            assert!(got.starts_with(stem), "{got} lost the original bytes of {stem}");
        }

        // A length-changing char inside the extension side of the split too,
        // and mixed casing on `.part` itself, which is preserved.
        let known = "Se\u{130}t.PART002.r\u{130}r";
        assert_eq!(
            derive_part_name(known, 1, 11).unwrap(),
            "Se\u{130}t.PART012.r\u{130}r"
        );

        // A neighbour that does not number its own slot tells us nothing.
        assert!(derive_part_name("x.part03.rar", 0, 1).is_none());
        assert!(derive_part_name("x.rar", 0, 1).is_none());
        assert!(derive_part_name("\u{130}.part", 0, 1).is_none());
    }
}

#[cfg(test)]
mod native_unrar_tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbfast-native-unrar-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn native_path_extracts_compressed_multivolume_set() {
        use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
        let dir = temp_dir("multivol");
        let payload: Vec<u8> = (0..200_000u32)
            .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"inner/data.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644, // Unix host: attributes are the file mode
            host_os: 1,
        }];
        let volumes = Rar50VolumeWriter::new(WriterOptions::default())
            .compressed_entries(&entries)
            .max_payload_per_volume(64 * 1024)
            .finish()
            .unwrap();
        assert!(volumes.len() > 1, "expected a multivolume set");
        for (index, bytes) in volumes.iter().enumerate() {
            std::fs::write(dir.join(format!("set.part{:02}.rar", index + 1)), bytes).unwrap();
        }

        assert!(try_unrar(&dir, None));
        let extracted = std::fs::read(dir.join("inner").join("data.bin")).unwrap();
        assert_eq!(extracted, payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_rescues_corrupted_volume_and_extracts() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-repair");
        let payload: Vec<u8> = (0..150_000u32)
            .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let mut archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(20))
            .finish()
            .unwrap();
        // Corrupt a run of payload bytes well inside the archive.
        let start = archive.len() / 3;
        for byte in &mut archive[start..start + 2048] {
            *byte ^= 0x5a;
        }
        let path = dir.join("set.rar");
        std::fs::write(&path, &archive).unwrap();

        assert!(try_rar_rr_repair(&dir, None));
        let extracted = std::fs::read(dir.join("video.bin")).unwrap();
        assert_eq!(extracted, payload);
        assert!(!dir.join("set.rrtmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_raw_scan_rescues_a_volume_whose_headers_are_destroyed() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-raw-scan");
        let payload: Vec<u8> = (0..80_000u32)
            .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(20))
            .finish()
            .unwrap();

        // Wreck the headers so the archive cannot be parsed at all: this is
        // the last-chance path that used to read the whole volume, clone it,
        // and hand back a third copy.
        let mut damaged = archive.clone();
        for byte in &mut damaged[8..400] {
            *byte ^= 0xa5;
        }
        let path = dir.join("set.rar");
        std::fs::write(&path, &damaged).unwrap();
        assert!(
            rars::ArchiveReader::read_path_with_options(
                &path,
                rars::ArchiveReadOptions::default()
            )
            .is_err(),
            "the test must actually exercise the raw-scan fallback"
        );

        assert!(try_rar_rr_repair(&dir, None));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            archive,
            "the raw scan must restore the volume byte for byte"
        );
        assert!(
            !std::fs::read_dir(&dir).unwrap().flatten().any(|e| e
                .file_name()
                .to_string_lossy()
                .contains("rrtmp")),
            "no repair temp may survive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_raw_scan_leaves_the_original_alone_when_it_cannot_repair() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-raw-fail");
        let payload: Vec<u8> = (0..80_000u32)
            .flat_map(|i| (i.wrapping_mul(2246822519)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(1))
            .finish()
            .unwrap();

        // Headers destroyed AND far more damage than 1% can cover.
        let mut damaged = archive.clone();
        let end = damaged.len() * 3 / 4;
        for byte in &mut damaged[8..end] {
            *byte ^= 0xa5;
        }
        let path = dir.join("set.rar");
        std::fs::write(&path, &damaged).unwrap();

        assert!(!try_rar_rr_repair(&dir, None));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            damaged,
            "a failed repair must leave the volume exactly as it found it"
        );
        assert!(
            !std::fs::read_dir(&dir).unwrap().flatten().any(|e| e
                .file_name()
                .to_string_lossy()
                .contains("rrtmp")),
            "no repair temp may survive a failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_leaves_unrepairable_volume_untouched() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-unrepairable");
        let payload: Vec<u8> = (0..100_000u32)
            .flat_map(|i| (i.wrapping_mul(374761393)).to_le_bytes())
            .collect();
        let entries = [CompressedEntry {
            name: b"video.bin",
            data: &payload,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let mut archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .recovery_percent(Some(1))
            .finish()
            .unwrap();
        // Corrupt far more than 1% RR can cover.
        let end = archive.len() * 3 / 4;
        for byte in &mut archive[64..end] {
            *byte ^= 0xa5;
        }
        let corrupted = archive.clone();
        let path = dir.join("set.rar");
        std::fs::write(&path, &archive).unwrap();

        assert!(!try_rar_rr_repair(&dir, None));
        assert_eq!(std::fs::read(&path).unwrap(), corrupted, "original untouched");
        assert!(!dir.join("set.rrtmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rr_repair_skips_volumes_without_recovery_records() {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let dir = temp_dir("rr-none");
        let entries = [CompressedEntry {
            name: b"data.bin",
            data: b"hello recovery-less world",
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        }];
        let archive = Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .finish()
            .unwrap();
        std::fs::write(dir.join("set.rar"), &archive).unwrap();

        assert!(!try_rar_rr_repair(&dir, None));
        assert!(!dir.join("set.rrtmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn entry_paths_cannot_escape_output_dir() {
        let dir = std::path::Path::new("/tmp/out");
        assert!(sanitized_entry_path(dir, "../evil").is_none());
        assert!(sanitized_entry_path(dir, "a/../../evil").is_none());
        assert!(sanitized_entry_path(dir, "/abs/path").map(|p| p.starts_with(dir)) == Some(true));
        // Windows rejects the drive prefix outright; Unix keeps it as a
        // benign "C:" subdirectory. Either way it must stay under dir.
        let drive = sanitized_entry_path(dir, "C:\\evil");
        assert!(drive.is_none() || drive.is_some_and(|p| p.starts_with(dir)));
        assert_eq!(
            sanitized_entry_path(dir, "sub\\file.bin"),
            Some(dir.join("sub").join("file.bin"))
        );
        assert!(sanitized_entry_path(dir, "").is_none());
    }

    #[test]
    fn drive_relative_component_cannot_escape_on_windows() {
        let dir = std::path::Path::new("/tmp/out");
        // A drive prefix only parses at byte 0, so these forms reach `push`
        // as ordinary components and used to wipe the staging dir.
        for name in ["sub/C:evil.dll", "x/D:payload.exe", "a\\b\\C:evil.dll"] {
            let p = sanitized_entry_path_for(dir, name, true).expect("kept, not escaped");
            assert!(p.starts_with(dir), "{name} escaped to {p:?}");
            assert!(!p.to_string_lossy().contains(':'), "{name} kept a drive-relative colon");
        }
        // Unix keeps ':' (legal and common in release names) but still may
        // not escape, and the ordinary success path is untouched.
        let p = sanitized_entry_path_for(dir, "Movie: The Sequel/a.mkv", false).unwrap();
        assert_eq!(p, dir.join("Movie: The Sequel").join("a.mkv"));
    }
}

#[cfg(test)]
mod repair_tests {
    use super::*;

    #[test]
    fn trunc_respects_char_boundaries() {
        // `&stem[..60]` panicked mid-char on non-ASCII release names.
        let s = "é".repeat(40); // 80 bytes; byte 60 is mid-char
        let t = trunc(&s, 60);
        assert!(t.len() <= 60 && s.starts_with(t));
        assert_eq!(trunc("short", 60), "short");
        assert_eq!(trunc("exactly!", 8), "exactly!");
    }

    #[test]
    fn first_rar_volume_picks_lowest_part_any_width() {
        let paths = |names: &[&str]| -> Vec<PathBuf> {
            names.iter().map(PathBuf::from).collect()
        };
        let pick = |names: &[&str]| {
            first_rar_volume(&paths(names)).map(|p| p.to_string_lossy().into_owned())
        };
        // 3-digit set with a stray sample: part001 must win.
        assert_eq!(
            pick(&["Movie.sample.rar", "Movie.part002.rar", "Movie.part001.rar"]),
            Some("Movie.part001.rar".to_string())
        );
        // 2- and 1-digit conventions still work.
        assert_eq!(
            pick(&["X.part02.rar", "X.part01.rar"]),
            Some("X.part01.rar".to_string())
        );
        assert_eq!(pick(&["X.part2.rar", "X.part1.rar"]), Some("X.part1.rar".to_string()));
        // No part-numbered files → lexically first plain .rar.
        assert_eq!(pick(&["b.rar", "a.rar"]), Some("a.rar".to_string()));
        // ".part" without digits is not a part number.
        assert_eq!(pick(&["The.Party.rar"]), Some("The.Party.rar".to_string()));
        assert_eq!(pick(&[]), None);
    }

    #[test]
    fn vol_counts_parse() {
        assert_eq!(vol_count_from_name("x.vol063+64.par2"), Some(64));
        assert_eq!(vol_count_from_name("x.vol0+1.par2"), Some(1));
        assert_eq!(vol_count_from_name("X.VOL127+53.PAR2"), Some(53));
        assert_eq!(vol_count_from_name("x.par2"), None);
        assert_eq!(vol_count_from_name("x.vol1.par2"), None);
        // par2cmdline at -b32768 emits zero-count volumes and 5-digit
        // exponents (par2cmdline#205) - both must parse, never panic.
        assert_eq!(vol_count_from_name("disk1.vol34529+00000.par2"), Some(0));
        assert_eq!(vol_count_from_name("x.vol10000+12345.par2"), Some(12345));
    }

    /// A demoted group whose volumes nobody else unpacks must reach the
    /// on-disk pass, or the job "completes" over a directory of loose .rar
    /// volumes with no payload in it. Both directions matter: the reasons
    /// somebody else owns must stay out, because sending those to unrar
    /// fails jobs that are fine today.
    #[test]
    fn demoted_volumes_nobody_owns_reach_the_disk_unpack() {
        // Reason strings as extract.rs emits them.
        for why in [
            // The f9983fa tiling gate: headers that do not describe a whole
            // file. Note "complete file" is IN this string - the near-miss
            // that made it look handled by the old "incomplete mapping" arm.
            "inner file's headers do not describe a complete file",
            // MapBlocker::Corrupt, via blocker_reason.
            "data area exceeds volume",
            "block length does not advance",
            // The reasons the ladder already knew.
            "inner file failed its stored CRC",
            "inner file carries only a hash the fast path can't verify",
            "held-bytes cap: header stash",
            "incomplete mapping at end of download",
            "routed span lost its destination",
            "chase failed: worker died",
        ] {
            assert!(
                fallback_needs_disk_unpack(why),
                "'{why}' would ship a job with no payload and exit 0"
            );
        }
        // Owned by somebody else - handing these to unrar breaks jobs that
        // work today.
        for why in [
            // The caller's own encrypted/password/compressed branches.
            "encrypted headers (password required)",
            "wrong archive password",
            "compressed or encrypted entries",
            "encrypted data incomplete",
            // The nested post-pass repairs the inner layer before unpacking.
            "nested fallback: inner file failed its stored CRC",
            "nested fallback: inner mapping unfinished at end of download",
            // Not an archive at all: there is no set for unrar to open.
            "not a RAR volume",
            "never classified",
            "unclassified-holds budget",
            // The PAR2 path re-extracts these itself and removes them.
            "materialized for repair",
        ] {
            assert!(
                !fallback_needs_disk_unpack(why),
                "'{why}' is already owned - unpacking it again fails a good job"
            );
        }
    }

    /// A top-level 7z chase that demoted is owned by the 7z post-pass,
    /// and its reason must not reach the RAR ladder at all - not the
    /// unowned arm, not the encrypted arm. Both wordings are pinned
    /// because both occur (the retention cap, and an archive whose
    /// header needs a password), and both would otherwise end at
    /// `try_unrar` over a directory holding one .7z, which fails.
    #[test]
    fn a_demoted_top_level_7z_stays_out_of_the_rar_ladder() {
        for why in [
            "held-bytes cap: chase memory",
            "inner 7z is encrypted (no password)",
            "inner 7z codec unsupported: 30101",
            "materialized for repair",
        ] {
            let marked =
                format!("{}{why}", nzbkit::extract::SEVENZ_DISK_FALLBACK_PREFIX);
            assert!(sevenz_disk_fallback(&marked), "'{marked}'");
            // The underlying reason stays readable inside it - the
            // "held-bytes cap" substring other callers key off included.
            assert!(marked.contains(why));
        }
        // A RAR volume demote is untouched by the marker check.
        assert!(!sevenz_disk_fallback("held-bytes cap: chase memory"));
        assert!(!sevenz_disk_fallback("nested fallback: inner 7z decode failed"));
    }

    /// The speculative recovery prefetch promises "a tiny side pool (1
    /// conn/server)": the main pool already holds this account's grants, so
    /// a second full fleet mid-download runs the provider's connection cap
    /// over and gets the whole job refused. The pool sizes itself from
    /// PoolConfig, so setting only ServerConfig.connections leaves it
    /// full-size.
    #[test]
    fn speculative_prefetch_side_pool_is_one_connection_per_server() {
        let server = |host: &str| nzbkit::config::ServerConfig {
            host: host.into(),
            port: 119,
            tls: false,
            username: None,
            password: None,
            connections: 50,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
        };
        let live = nzbkit::pool::LiveStats::for_servers(&[
            (server("a.example"), nzbkit::pool::PoolConfig::default()),
            (server("b.example"), nzbkit::pool::PoolConfig::default()),
        ]);
        let main: Vec<_> = ["a.example", "b.example"]
            .iter()
            .map(|h| {
                (
                    server(h),
                    nzbkit::pool::PoolConfig {
                        connections: 50,
                        window: 8,
                        live: Some(live.clone()),
                        ..Default::default()
                    },
                )
            })
            .collect();
        let side = side_pool_servers(&main);
        assert_eq!(side.len(), 2, "every server keeps a side connection");
        for (sc, pc) in &side {
            assert_eq!(pc.connections, 1, "{}: side pool opened a full fleet", sc.host);
            assert_eq!(sc.connections, 1, "{}: server config not shrunk", sc.host);
            // Side-pool workers are not the download; they must not move
            // the dashboard's per-server gauges.
            assert!(pc.live.is_none(), "{}: side pool feeds the dashboard", sc.host);
            // Everything else about the fleet is preserved.
            assert_eq!(pc.window, 8, "{}: unrelated pool settings dropped", sc.host);
        }
        // The download's own fleet is untouched.
        assert_eq!(main[0].1.connections, 50, "main pool shrunk");
        assert_eq!(main[0].0.connections, 50, "main server config shrunk");
    }

    #[test]
    fn braces_password_convention() {
        let p = |s: &str| braces_password(std::path::Path::new(s));
        assert_eq!(p("Movie.2026{{s3cret}}.nzb"), Some("s3cret".into()));
        assert_eq!(p("/spool/Show{{p w!d}}.nzb"), Some("p w!d".into()));
        assert_eq!(p("Movie.2026.nzb"), None);
        assert_eq!(p("Odd{{}}.nzb"), None);
    }

    #[test]
    fn exact_fit_beats_greedy() {
        // Need 5. Volumes: 1+2+4 series (bytes ∝ slices).
        let vols = vec![(0, 1, 100), (1, 2, 200), (2, 4, 400), (3, 8, 800)];
        let chosen = pick_volumes(&vols, 5);
        let blocks: usize = chosen.iter().map(|&i| vols[i].1).sum();
        let bytes: u64 = chosen.iter().map(|&i| vols[i].2).sum();
        assert!(blocks >= 5);
        // Optimal is 1+4 = 500 bytes (not 8 = 800, not 1+2+4 = 700).
        assert_eq!(bytes, 500, "chosen {chosen:?}");
    }

    #[test]
    fn single_oversize_when_cheapest() {
        let vols = vec![(0, 1, 900), (1, 10, 500)];
        let chosen = pick_volumes(&vols, 2);
        assert_eq!(chosen, vec![1]);
    }

    fn reex_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-reex-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The hold exists to protect the outer volume set during nested
    /// extraction, so "the restore failed, therefore delete what we were
    /// protecting" is the one response it must never have. It used to swallow
    /// every rename error and then `remove_dir_all` the hold regardless.
    #[test]
    fn outer_hold_never_deletes_a_volume_it_could_not_put_back() {
        let dir = reex_dir("holdstrand");
        let hold = dir.join(".nzbfast-hold");
        std::fs::create_dir_all(&hold).unwrap();
        std::fs::write(hold.join("parked.rar"), b"the only copy").unwrap();
        // Something already occupies the destination name as a DIRECTORY, so
        // renaming the file back over it cannot succeed.
        std::fs::create_dir_all(dir.join("parked.rar")).unwrap();
        std::fs::write(dir.join("parked.rar/blocker"), b"x").unwrap();

        drop(super::OuterHold { dir: dir.clone(), hold: hold.clone() });

        assert!(
            hold.join("parked.rar").exists(),
            "a volume that could not be restored was deleted with the hold"
        );
        assert_eq!(
            std::fs::read(hold.join("parked.rar")).unwrap(),
            b"the only copy"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and the ordinary path still cleans up after itself.
    #[test]
    fn outer_hold_restores_and_removes_itself_when_it_can() {
        let dir = reex_dir("holdclean");
        let hold = dir.join(".nzbfast-hold");
        std::fs::create_dir_all(&hold).unwrap();
        std::fs::write(hold.join("vol.rar"), b"payload").unwrap();

        drop(super::OuterHold { dir: dir.clone(), hold: hold.clone() });

        assert_eq!(std::fs::read(dir.join("vol.rar")).unwrap(), b"payload");
        assert!(!hold.exists(), "an emptied hold should be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn reex_vols(total: &[u8]) -> [Vec<u8>; 2] {
        use nzbkit::rar::fixtures;
        let n = total.len() as u64;
        let half = total.len() / 2;
        [
            fixtures::rar5_volume_n(&[("film.mkv", n, &total[..half], false, true)], 0),
            fixtures::rar5_volume_n(&[("film.mkv", n, &total[half..], true, false)], 1),
        ]
    }

    /// The nest lift-back must merge produced subdirs into pre-existing
    /// ones and disambiguate file collisions instead of silently
    /// overwriting - the old blind rename-then-sweep swallowed the
    /// ENOTEMPTY failure and then deleted the stranded payload.
    #[test]
    fn lift_nest_outputs_merges_and_never_overwrites() {
        let dir = reex_dir("liftback");
        let sub = dir.join(".nzbfast-nest");
        std::fs::create_dir_all(sub.join("Sub")).unwrap();
        std::fs::create_dir_all(dir.join("Sub")).unwrap();
        std::fs::write(dir.join("Sub").join("keep.bin"), b"keep").unwrap();
        std::fs::write(dir.join("a.bin"), b"original").unwrap();
        std::fs::write(sub.join("Sub").join("inner.bin"), b"inner").unwrap();
        std::fs::write(sub.join("a.bin"), b"produced").unwrap();
        std::fs::write(sub.join("fresh.bin"), b"fresh").unwrap();
        assert!(lift_nest_outputs(&sub, &dir));
        // Pre-existing content survives untouched…
        assert_eq!(std::fs::read(dir.join("Sub").join("keep.bin")).unwrap(), b"keep");
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), b"original");
        // …and produced content all arrives (collision disambiguated).
        assert_eq!(std::fs::read(dir.join("Sub").join("inner.bin")).unwrap(), b"inner");
        assert_eq!(std::fs::read(dir.join("nested-1-a.bin")).unwrap(), b"produced");
        assert_eq!(std::fs::read(dir.join("fresh.bin")).unwrap(), b"fresh");
        // The scratch dir is fully emptied - safe for the caller to sweep.
        assert!(std::fs::read_dir(&sub).unwrap().next().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Only the operator-supplied job password may pay for a hostile-depth
    /// KDF; harvested candidates stop at the ceiling.
    #[test]
    fn kdf_gate_spares_structured_candidates_only() {
        assert!(kdf_candidate_allowed(24, true));
        assert!(!kdf_candidate_allowed(24, false));
        assert!(kdf_candidate_allowed(PW_KDF_MAX_LG2, false));
        assert!(kdf_candidate_allowed(15, false));
    }

    /// A zip is a real archive as far as descent is concerned, but a
    /// `.cbz` payload never is.
    #[test]
    fn zip_counts_as_an_archive_for_descent() {
        let dir = reex_dir("zipdescent");
        std::fs::write(dir.join("a.zip"), b"PK\x03\x04zip").unwrap();
        std::fs::write(dir.join("comic.cbz"), b"PK\x03\x04zip").unwrap();
        assert!(is_extractable_archive(&dir.join("a.zip")));
        assert!(!is_extractable_archive(&dir.join("comic.cbz")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The shape that used to complete SILENTLY: a byte-split zip matched
    /// no detector at all, so the pass reported "nothing to extract" and
    /// the job succeeded with its whole payload still packed.
    #[test]
    fn byte_split_zip_is_reported_not_silently_passed() {
        let dir = reex_dir("zipsplit");
        std::fs::write(dir.join("movie.zip.001"), b"PK\x03\x04first part").unwrap();
        std::fs::write(dir.join("movie.zip.002"), b"second part").unwrap();
        assert_eq!(
            extract_nested(&dir, None, 0).unwrap(),
            NestOutcome::ZipGap,
            "must not report success"
        );
        let u = unsupported_archive_present(&dir).expect("the split set must be found");
        assert_eq!(u.display, "movie.zip.001");
        assert_eq!(u.shape, "split zip");
        assert!(u.blocking, "the zip is all there is - the user got nothing usable");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A zip in a release subfolder used to be invisible: descent only
    /// seeded subdirs holding RAR or 7z magic, so nothing ever looked.
    #[test]
    fn subfolder_zip_is_found_and_ranked_against_the_payload() {
        let dir = reex_dir("zipsub");
        std::fs::create_dir_all(dir.join("Subs")).unwrap();
        std::fs::write(dir.join("Subs/subs.zip"), b"PK\x03\x04subtitles").unwrap();
        // Sidecar: the feature landed, so the zip is a note, not a problem.
        std::fs::write(dir.join("movie.mkv"), b"the actual payload").unwrap();
        let u = unsupported_archive_present(&dir).expect("subfolder zip must be found");
        assert_eq!(u.display, "Subs/subs.zip");
        assert!(!u.blocking, "a subs zip beside a feature is not a blocker");
        // ...and an offline `extract` must NOT fail over it.
        assert!(extract_local(&dir, None).unwrap(), "a sidecar zip must not fail the extract");

        // Take the payload away and the same zip becomes the whole story.
        std::fs::remove_file(dir.join("movie.mkv")).unwrap();
        assert!(unsupported_archive_present(&dir).unwrap().blocking);
        assert!(!extract_local(&dir, None).unwrap(), "a payload zip must fail loudly");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A sidecar zip must not absolve an UNRELATED extraction failure.
    /// The forgiving arm keyed off "is there a non-blocking zip anywhere",
    /// so a 7z we could not unpack plus any `Subs/subs.zip` exited 0 with
    /// nothing importable on disk (and the daemon reported Completed).
    #[test]
    fn failed_sevenz_is_not_forgiven_by_a_sidecar_zip() {
        let dir = reex_dir("zipalibi");
        // Not a real 7z: extraction is guaranteed to fail.
        std::fs::write(dir.join("movie.7z"), b"7z\xbc\xaf\x27\x1cnot really").unwrap();
        std::fs::create_dir_all(dir.join("Subs")).unwrap();
        std::fs::write(dir.join("Subs/subs.zip"), b"PK\x03\x04subtitles").unwrap();
        // The zip finding on its own reads as a harmless sidecar: the .7z
        // itself counts as payload, so nothing here is "blocking".
        assert!(!unsupported_archive_present(&dir).unwrap().blocking);
        // The pass stopped at the 7z, not the zip, so it must still fail.
        assert_eq!(extract_nested(&dir, None, 0).unwrap(), NestOutcome::Failed);
        assert!(!extract_local(&dir, None).unwrap(), "a failed 7z must fail the extract");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same alibi on the early-return path: a zip found FIRST must not
    /// end the pass while a supported archive still sits unattempted in a
    /// subfolder. `extract_one_level` only ever sees one level, so the
    /// descent has to run before the forgivable zip cause may be reported -
    /// otherwise the job completed with nothing but two packed archives.
    #[test]
    fn a_top_level_zip_does_not_skip_the_subfolder_archive() {
        let dir = reex_dir("zipfirst");
        std::fs::write(dir.join("extras.zip"), b"PK\x03\x04extras").unwrap();
        std::fs::create_dir_all(dir.join("CD1")).unwrap();
        // Not a real 7z: the subfolder extraction is guaranteed to fail.
        std::fs::write(dir.join("CD1/movie.7z"), b"7z\xbc\xaf\x27\x1cnot really").unwrap();
        // The zip on its own reads as a harmless sidecar - the still-packed
        // .7z counts as payload - so the heuristic cannot be what decides it.
        assert!(!unsupported_archive_present(&dir).unwrap().blocking);
        assert_eq!(extract_nested(&dir, None, 0).unwrap(), NestOutcome::Failed);
        assert!(
            !extract_local(&dir, None).unwrap(),
            "a subfolder archive we could not unpack must fail the extract"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// PAR2 sets and scene furniture are not payload: a directory holding
    /// only a zip and its recovery files still leaves the user empty.
    #[test]
    fn furniture_does_not_count_as_payload() {
        let dir = reex_dir("zipfurniture");
        std::fs::write(dir.join("movie.zip"), b"PK\x03\x04packed").unwrap();
        std::fs::write(dir.join("movie.par2"), b"PAR2\x00PKT").unwrap();
        std::fs::write(dir.join("movie.nfo"), b"scene notes").unwrap();
        assert!(unsupported_archive_present(&dir).unwrap().blocking);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn extract_nested_seeds_preexisting_subdir_archives() {
        // CD1/CD2 layout: the archives are already IN subdirs when the
        // pass starts, so the after/before diff never sees them - only
        // the pre-existing-subdir seeding reaches them.
        let dir = reex_dir("presub");
        let store = |name: &'static [u8], data: &[u8]| -> Vec<u8> {
            rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::new(
                rars::ArchiveVersion::Rar50,
                rars::FeatureSet::store_only(),
            ))
            .stored_entries(&[rars::rar50::StoredEntry {
                name,
                data,
                mtime: None,
                attributes: 0,
                host_os: 0,
            }])
            .finish()
            .unwrap()
        };
        let d1: Vec<u8> = (0..80_000u32).map(|i| (i as u8).wrapping_mul(31)).collect();
        let d2: Vec<u8> = (0..60_000u32)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
            .collect();
        std::fs::create_dir_all(dir.join("CD1")).unwrap();
        std::fs::create_dir_all(dir.join("CD2")).unwrap();
        std::fs::write(dir.join("CD1/a.rar"), store(b"a.bin", &d1)).unwrap();
        std::fs::write(dir.join("CD2/b.rar"), store(b"b.bin", &d2)).unwrap();
        assert!(extract_nested(&dir, None, 0).unwrap().produced());
        assert_eq!(std::fs::read(dir.join("CD1/a.bin")).unwrap(), d1);
        assert_eq!(std::fs::read(dir.join("CD2/b.bin")).unwrap(), d2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reextract_dir_sorts_volumes_and_cleans_up() {
        let dir = reex_dir("ok");
        let total: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(13).wrapping_add(7))
            .collect();
        let vols = reex_vols(&total);
        // .rar/.r00 naming: lexical order (.r00 < .rar) is the WRONG feed
        // order - the natural volume sort must put .rar first.
        std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
        assert!(reextract_dir(&dir, None).unwrap());
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert!(!dir.join("x.rar").exists(), "volumes removed after extraction");
        assert!(!dir.join("x.r00").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b): the disk post-pass classifies and tallies a nested
    /// layer. `nested_inner_kind` names the shape from the head (store vs
    /// compressed), and `extract_one_level` at depth 1 (a nested level)
    /// extracts it and bumps the `disk` + `rar_store` counters. The tally
    /// is process-global under the parallel runner, so the counter checks
    /// are lower-bound deltas; the classifier checks are exact.
    #[test]
    fn nested_prevalence_classifies_and_counts_disk_layer() {
        use nzbkit::rar::fixtures;
        let data: Vec<u8> = (0..90_000u32).map(|i| (i as u8).wrapping_mul(7)).collect();

        // Compressed inner classifies distinctly (no extraction, no count).
        let cdir = reex_dir("nestprev-comp");
        let comp = {
            use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
            Rar50Writer::new(WriterOptions::default())
                .compressed_entries(&[CompressedEntry {
                    name: b"c.bin",
                    data: &data,
                    mtime: None,
                    attributes: 0,
                    host_os: 0,
                }])
                .finish()
                .unwrap()
        };
        std::fs::write(cdir.join("c.rar"), &comp).unwrap();
        assert_eq!(nested_inner_kind(&cdir), Some("rar-compressed"));
        std::fs::remove_dir_all(&cdir).unwrap();

        // Store inner: classify, then run the disk post-pass at depth 1.
        let before = nzbkit::extract::nested_prevalence();
        let dir = reex_dir("nestprev-store");
        let vol =
            fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
        std::fs::write(dir.join("inner.rar"), &vol).unwrap();
        assert_eq!(nested_inner_kind(&dir), Some("rar-store"));
        assert_eq!(extract_one_level(&dir, None, 1).unwrap(), Some(NestOutcome::Produced));
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        let after = nzbkit::extract::nested_prevalence();
        assert!(
            after.disk >= before.disk + 1,
            "disk counter did not advance ({} -> {})",
            before.disk,
            after.disk
        );
        assert!(
            after.rar_store >= before.rar_store + 1,
            "rar_store counter did not advance ({} -> {})",
            before.rar_store,
            after.rar_store
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `reex_vols` with a chosen member name - the alias fixtures below
    /// need the archived member to be named after a source volume.
    fn reex_vols_named(total: &[u8], member: &str) -> [Vec<u8>; 2] {
        use nzbkit::rar::fixtures;
        let n = total.len() as u64;
        let half = total.len() / 2;
        [
            fixtures::rar5_volume_n(&[(member, n, &total[..half], false, true)], 0),
            fixtures::rar5_volume_n(&[(member, n, &total[half..], true, false)], 1),
        ]
    }

    /// Sweep finding 8: a member named exactly like the FIRST source
    /// volume. The decoder reopens that volume by path for every range it
    /// reads, so writing the member beside it truncated the file mid-read,
    /// failed the extraction, and handed a destroyed set to the unrar
    /// fallback. Extraction stages its output instead, so the volume is
    /// never opened for writing and both files survive.
    #[test]
    fn rar_member_named_like_first_volume_leaves_it_intact() {
        let dir = reex_dir("alias-first");
        let total: Vec<u8> = (0..300_000u32)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(5))
            .collect();
        let vols = reex_vols_named(&total, "x.rar");
        std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
        assert_eq!(extract_one_level(&dir, None, 1).unwrap(), Some(NestOutcome::Produced));
        assert_eq!(
            std::fs::read(dir.join("x.rar")).unwrap(),
            vols[0],
            "first volume was rewritten by the member named after it"
        );
        assert_eq!(std::fs::read(dir.join("x.r00")).unwrap(), vols[1]);
        // The member is still delivered, under a disambiguated name.
        assert_eq!(std::fs::read(dir.join("extracted-1-x.rar")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Same shape against a LATER volume (`x.r00`), which the decoder only
    /// reopens once it has consumed the first - the byte the old code
    /// destroyed had not even been read yet when it was truncated.
    #[test]
    fn rar_member_named_like_later_volume_leaves_it_intact() {
        let dir = reex_dir("alias-later");
        let total: Vec<u8> = (0..300_000u32)
            .map(|i| (i as u8).wrapping_mul(23).wrapping_add(9))
            .collect();
        let vols = reex_vols_named(&total, "x.r00");
        std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
        assert_eq!(extract_one_level(&dir, None, 1).unwrap(), Some(NestOutcome::Produced));
        assert_eq!(std::fs::read(dir.join("x.rar")).unwrap(), vols[0]);
        assert_eq!(
            std::fs::read(dir.join("x.r00")).unwrap(),
            vols[1],
            "later volume was rewritten by the member named after it"
        );
        assert_eq!(std::fs::read(dir.join("extracted-1-x.r00")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A native extraction that fails AFTER writing bytes (the last piece
    /// carries a wrong stored CRC) must publish nothing: every source
    /// volume keeps its bytes, and no partial output is left for a later
    /// pass - or the unrar fallback - to mistake for payload.
    #[test]
    fn failed_native_extraction_publishes_nothing() {
        use nzbkit::rar::fixtures;
        let dir = reex_dir("alias-fail");
        let total: Vec<u8> = (0..300_000u32)
            .map(|i| (i as u8).wrapping_mul(11).wrapping_add(3))
            .collect();
        let n = total.len() as u64;
        let half = total.len() / 2;
        let vols = [
            fixtures::rar5_volume_n_crc(
                &[("x.rar", n, &total[..half], false, true, None)],
                0,
            ),
            // Wrong plaintext CRC on the last piece - extraction writes
            // every byte, then rejects the entry.
            fixtures::rar5_volume_n_crc(
                &[("x.rar", n, &total[half..], true, false, Some(0xDEAD_BEEF))],
                1,
            ),
        ];
        std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
        assert!(
            try_rars_native(&dir, &dir.join("x.rar"), None).is_err(),
            "a CRC-failing entry must not report success"
        );
        assert_eq!(std::fs::read(dir.join("x.rar")).unwrap(), vols[0]);
        assert_eq!(std::fs::read(dir.join("x.r00")).unwrap(), vols[1]);
        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left.len(), 2, "staging leaked into the job dir: {left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Sweep finding A7: a `release.7z` carrying a member named
    /// `release.7z`. `ArchiveReader::open` holds the container open and
    /// reads from it as each member decodes, so writing that member beside
    /// it truncated the inode still backing its own reader - destroying the
    /// only downloaded copy of the archive. The joined-container scratch
    /// dir is separate from the output dir for the same reason.
    #[test]
    fn sevenz_member_named_like_its_own_container_leaves_it_intact() {
        let dir = reex_dir("alias-7z");
        let payload: Vec<u8> = (0..250_000u32)
            .map(|i| (i as u8).wrapping_mul(19).wrapping_add(4))
            .collect();
        let container = {
            let mut w =
                sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
            w.push_archive_entry(
                sevenz_rust2::ArchiveEntry::new_file("release.7z"),
                Some(payload.as_slice()),
            )
            .unwrap();
            w.finish().unwrap().into_inner()
        };
        let path = dir.join("release.7z");
        std::fs::write(&path, &container).unwrap();
        assert!(extract_sevenz(&dir, &[vec![path.clone()]], None));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            container,
            "the container was truncated by the member named after it"
        );
        assert_eq!(
            std::fs::read(dir.join("extracted-1-release.7z")).unwrap(),
            payload
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Sweep finding A6 (the directory half): the collision walk steps
    /// around a directory whose payload belongs to a COMPLETED job and
    /// records the canonical name to publish over. A FAILED job maps to
    /// `Free` at the call site, so its leftovers are still reused in place.
    #[test]
    fn out_dir_choice_steps_around_a_completed_payload() {
        use crate::serve::{DirClaim, choose_out_dir};
        let base = std::path::Path::new("/dl/tv/Release");
        // Free (nothing there, or a failed job's junk): reuse in place,
        // nothing to replace.
        let (d, r) = choose_out_dir(base, "Release", &|_| DirClaim::Free);
        assert_eq!(d, base);
        assert_eq!(r, None);
        // A completed payload: download beside it, publish over it later.
        let (d, r) = choose_out_dir(base, "Release", &|p| {
            if p == base { DirClaim::Payload } else { DirClaim::Free }
        });
        assert_eq!(d, std::path::Path::new("/dl/tv/Release.2"));
        assert_eq!(r, Some(base.to_path_buf()));
        // An ACTIVE job holds the canonical name: step aside as before,
        // and never replace what a running job is writing.
        let (d, r) = choose_out_dir(base, "Release", &|p| {
            if p == base { DirClaim::Active } else { DirClaim::Free }
        });
        assert_eq!(d, std::path::Path::new("/dl/tv/Release.2"));
        assert_eq!(r, None);
        // Canonical holds a payload and .2 is busy: land on .3, and still
        // replace only the canonical one.
        let (d, r) = choose_out_dir(base, "Release", &|p| match p.to_string_lossy() {
            c if c.ends_with("Release") => DirClaim::Payload,
            c if c.ends_with("Release.2") => DirClaim::Active,
            _ => DirClaim::Free,
        });
        assert_eq!(d, std::path::Path::new("/dl/tv/Release.3"));
        assert_eq!(r, Some(base.to_path_buf()));
    }

    /// A6 publication: the previous result survives a failed hand-over,
    /// and is replaced only once the new payload is in place.
    #[test]
    fn replacing_a_previous_result_never_loses_it() {
        use crate::serve::publish_over_previous;
        let root = reex_dir("a6-replace");
        let canon = root.join("Release");
        let fresh = root.join("Release.2");
        std::fs::create_dir_all(&canon).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(canon.join("payload.iso"), b"the good old copy").unwrap();
        std::fs::write(fresh.join("payload.iso"), b"the new copy").unwrap();
        assert_eq!(publish_over_previous(&fresh, &canon), Some(canon.clone()));
        assert_eq!(std::fs::read(canon.join("payload.iso")).unwrap(), b"the new copy");
        assert!(!fresh.exists(), "the staged directory was left behind");
        // Nothing aside from the canonical directory survives the swap.
        let left: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left, vec!["Release".to_string()], "leftovers: {left:?}");

        // A job that never produced its directory leaves the old result
        // exactly where it was.
        let missing = root.join("Release.3");
        assert_eq!(publish_over_previous(&missing, &canon), None);
        assert_eq!(std::fs::read(canon.join("payload.iso")).unwrap(), b"the new copy");
        // And a job that already owns the canonical name is a no-op.
        assert_eq!(publish_over_previous(&canon, &canon), None);
        assert_eq!(std::fs::read(canon.join("payload.iso")).unwrap(), b"the new copy");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Regression: a failed re-extraction must never damage the (PAR2-
    /// verified) volume files it reads - the old fallback truncated them
    /// in place and destroyed a repaired 62-volume set.
    #[test]
    fn reextract_dir_failure_preserves_source_volumes() {
        let dir = reex_dir("damaged");
        let total: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(3))
            .collect();
        let mut vols = reex_vols(&total);
        vols[1][..4].fill(0); // corrupt volume 2's signature
        std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
        assert!(!reextract_dir(&dir, None).unwrap(), "damaged set must not report success");
        assert_eq!(std::fs::read(dir.join("x.rar")).unwrap(), vols[0]);
        assert_eq!(std::fs::read(dir.join("x.r00")).unwrap(), vols[1]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Differential: an obfuscated volume set (extensionless names, filename
    /// order deliberately INVERTED against volume order) must extract
    /// byte-identically to the same set under normal names. Proves both the
    /// magic-based detection and the header-volume-number ordering.
    #[test]
    fn obfuscated_volumes_extract_like_named_ones() {
        let total: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(11))
            .collect();
        let vols = reex_vols(&total);

        let named = reex_dir("obf-named");
        std::fs::write(named.join("x.rar"), &vols[0]).unwrap();
        std::fs::write(named.join("x.r00"), &vols[1]).unwrap();
        assert!(extract_local(&named, None).unwrap());
        let want = std::fs::read(named.join("film.mkv")).unwrap();
        assert_eq!(want, total);

        let obf = reex_dir("obf-hex");
        // volume 0 gets the lexically LATER name: filename sort would feed
        // the set backwards; only the header volume number saves it.
        std::fs::write(obf.join("bb0a1f"), &vols[0]).unwrap();
        std::fs::write(obf.join("aa93c2"), &vols[1]).unwrap();
        assert!(extract_local(&obf, None).unwrap(), "obfuscated set must extract");
        assert_eq!(
            std::fs::read(obf.join("film.mkv")).unwrap(),
            want,
            "obfuscated payload differs from named-set payload"
        );

        std::fs::remove_dir_all(&named).unwrap();
        std::fs::remove_dir_all(&obf).unwrap();
    }

    /// Sorted file names directly inside `dir` (our scratch dirs excluded).
    fn names_in(dir: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| !n.starts_with(".nzbfast"))
            .collect();
        v.sort();
        v
    }

    /// A `.rev`-shaped file: the real RAR5 recovery-volume signature (so
    /// `Rar!` magic collects it as an obfuscated candidate), with a
    /// memberless RAR5 archive further in - the SFX scan latches onto that
    /// and hands back a set with nothing in it. Recovery data must survive
    /// this misdetection; sweeping it would delete the only thing that can
    /// rebuild a damaged set.
    fn rev_shaped_file() -> Vec<u8> {
        let mut out = b"Rar!\x1aRev".to_vec();
        out.extend(std::iter::repeat(0x5Au8).take(64));
        out.extend_from_slice(&nzbkit::rar::fixtures::rar5_volume(&[]));
        out
    }

    /// Run the disk extraction over `dir` the way each of its two real
    /// callers does. Depth 0 is the offline `nzbfast extract` CLI; depth 1
    /// is the daemon's post-download nested pass, which is the call that
    /// unpacked the reported job (its `reextract_dir` step is name-gated
    /// and never saw the hash-named volumes at all). Both are exercised
    /// because only depth >= 1 also runs `sweep_spent_entry`.
    fn obf_extract_at(dir: &std::path::Path, depth: usize) -> bool {
        if depth == 0 {
            extract_local(dir, None).unwrap_or(false)
        } else {
            matches!(extract_nested(dir, None, depth), Ok(NestOutcome::Produced))
        }
    }

    /// The reported bug: a completed obfuscated download left its seven
    /// extension-less hash-named volumes sitting beside the extracted
    /// video. `sweep_spent_entry`'s name grouping cannot see them (each
    /// hash name is its own `release_stem`, so its "exactly one set"
    /// guard trips), so the sweep has to happen where the volumes were
    /// actually proven spent - in the obfuscated extractor itself.
    #[test]
    fn obfuscated_extraction_removes_the_volumes_it_consumed() {
        let total: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(23).wrapping_add(5))
            .collect();
        let vols = reex_vols(&total);
        for depth in [0usize, 1] {
            let dir = reex_dir(&format!("obf-sweep-{depth}"));
            std::fs::write(dir.join("301c0186f3bbdc58ac03a8739f989391c4"), &vols[0]).unwrap();
            std::fs::write(dir.join("0a77bd41e9c2f6538ab10d47cc9021ef73"), &vols[1]).unwrap();

            assert!(obf_extract_at(&dir, depth), "depth {depth}: set must extract");
            assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
            // Depth 0 is the user's own downloaded set (or an offline
            // `extract` target): its retention belongs to finalize/policy,
            // exactly as for a NAMED set, so the volumes stay. Only a
            // deeper level is ours to clean, because it exists solely
            // because an outer pass produced it.
            let want: Vec<String> = if depth == 0 {
                vec![
                    "0a77bd41e9c2f6538ab10d47cc9021ef73".into(),
                    "301c0186f3bbdc58ac03a8739f989391c4".into(),
                    "film.mkv".into(),
                ]
            } else {
                vec!["film.mkv".into()]
            };
            assert_eq!(
                names_in(&dir),
                want,
                "depth {depth}: wrong retention for a successfully extracted set"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// ...and the mirror guarantee, which outranks it: a set that did NOT
    /// extract keeps every volume. They are the only copy on disk, and
    /// PAR2 repair, `.rev` reconstruction and a plain retry all read them.
    #[test]
    fn failed_obfuscated_extraction_keeps_every_volume() {
        use nzbkit::rar::fixtures;
        let total: Vec<u8> = (0..200_000u32)
            .map(|i| (i as u8).wrapping_mul(13).wrapping_add(7))
            .collect();
        let half = total.len() / 2;
        let n = total.len() as u64;
        // Both volumes parse and group into ONE set (so both are in the
        // extractor's source list), but the member name escapes the output
        // directory, so `write_archives_to` fails after the set is bound.
        let vols = [
            fixtures::rar5_volume_n(&[("../escape.mkv", n, &total[..half], false, true)], 0),
            fixtures::rar5_volume_n(&[("../escape.mkv", n, &total[half..], true, false)], 1),
        ];
        for depth in [0usize, 1] {
            let dir = reex_dir(&format!("obf-failkeep-{depth}"));
            std::fs::write(dir.join("c41d8fa9f00b204e98009980"), &vols[0]).unwrap();
            std::fs::write(dir.join("7215ee9c7d9dc229d2921a40"), &vols[1]).unwrap();

            assert!(
                !obf_extract_at(&dir, depth),
                "depth {depth}: an extraction that produced nothing reported success"
            );
            assert_eq!(
                std::fs::read(dir.join("c41d8fa9f00b204e98009980")).unwrap(),
                vols[0],
                "depth {depth}: volume 1 of a failed set was altered or removed"
            );
            assert_eq!(
                std::fs::read(dir.join("7215ee9c7d9dc229d2921a40")).unwrap(),
                vols[1],
                "depth {depth}: volume 2 of a failed set was altered or removed"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A `.rev` recovery volume rides along with the obfuscated set, is
    /// collected by the same `Rar!` magic test, and parses as a memberless
    /// set of its own. The real set is swept; the recovery volume is not.
    ///
    /// Depth 1 is the sharp end. Sweeping the volumes leaves the `.rev`
    /// as the only `Rar!`-magic file at the level, and `sweep_spent_entry`
    /// then reads one `release_stem` as "exactly one release set present,
    /// therefore spent" - so the new sweep must not be allowed to feed it
    /// a directory the extraction already emptied.
    #[test]
    fn obfuscated_sweep_never_touches_a_memberless_rar_file() {
        let total: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(19))
            .collect();
        let vols = reex_vols(&total);
        let rev = rev_shaped_file();
        for depth in [0usize, 1] {
            let dir = reex_dir(&format!("obf-rev-{depth}"));
            std::fs::write(dir.join("f9a2c7b1049e6d3358ff20aa"), &vols[0]).unwrap();
            std::fs::write(dir.join("18cc4d0e6b7a92f1d3e05581"), &vols[1]).unwrap();
            std::fs::write(dir.join("5b3e91da77c0416f8a2d99e4"), &rev).unwrap();

            let _ = obf_extract_at(&dir, depth);
            // The payload came out, and the volumes that made it are gone
            // at depth >= 1 (at depth 0 nothing is swept at all - the
            // user's own set is finalize/policy's call).
            assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
            let swept = depth >= 1;
            assert_eq!(!dir.join("f9a2c7b1049e6d3358ff20aa").exists(), swept, "depth {depth}");
            assert_eq!(!dir.join("18cc4d0e6b7a92f1d3e05581").exists(), swept, "depth {depth}");
            // …and at EVERY depth the recovery volume is byte-for-byte
            // where it was. This is the property that must not bend: it is
            // what a repair reads, and emptying the set around it must
            // never make some other guard think it is spent.
            assert_eq!(
                std::fs::read(dir.join("5b3e91da77c0416f8a2d99e4")).unwrap(),
                rev,
                "depth {depth}: a memberless Rar!-magic file (the .rev shape) was swept"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The fallback ladder's own entry point must see an obfuscated set.
    ///
    /// When an obfuscated download demotes WITH a recorded reason (a
    /// compressed payload, the held-bytes cap, an in-stream CRC gate), the
    /// ladder calls `try_unrar` and FAILS the job when it answers false.
    /// `try_unrar` used to look for a `.rar` extension, then a numeric one -
    /// a hash name has neither, so it answered false on a set that unpacks
    /// perfectly, and the job died with its payload still packed on disk.
    ///
    /// The second half is the reason the fix cannot simply unpack and walk
    /// away: every caller hands the SAME directory to the depth-1 nested
    /// pass straight afterwards. A named set is fenced off there by
    /// `outer_vol_stems`; hash names carry no stem, so spent volumes left
    /// behind would be extracted a SECOND time and published beside the
    /// real payload as `extracted-1-film.mkv`.
    #[test]
    fn demoted_obfuscated_set_unpacks_through_the_fallback_ladder() {
        let total: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
            .collect();
        let vols = reex_vols(&total);
        let dir = reex_dir("obf-fallback");
        std::fs::write(dir.join("a3f19c07d2b845e6"), &vols[0]).unwrap();
        std::fs::write(dir.join("0e7bd4128c9a63f5"), &vols[1]).unwrap();

        assert!(
            try_unrar(&dir, None),
            "the fallback ladder could not unpack an obfuscated set - the job fails here"
        );
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);

        // …and the pass the ladder runs next must find nothing left to do.
        assert!(
            matches!(extract_nested(&dir, None, 1), Ok(NestOutcome::Produced)),
            "the nested pass that follows the ladder failed"
        );
        assert_eq!(
            names_in(&dir),
            vec!["film.mkv".to_string()],
            "the payload was published twice (or a spent volume survived)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `reextract_dir` must never report success for a pass that extracted
    /// nothing. Its collector is name-gated, so on a RESUMED obfuscated job
    /// it found zero volumes and returned `Ok(true)` - a silent success that
    /// left the payload packed. Today a later nested pass happens to rescue
    /// it; `smart::unlock` has no such pass behind it, and reorder or skip
    /// that one and the job exits 0 with no payload at all.
    ///
    /// The property asserted is the honest one: when it says success, the
    /// payload IS on disk.
    #[test]
    fn reextract_dir_success_means_the_payload_is_on_disk() {
        let total: Vec<u8> = (0..300_000u32)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(11))
            .collect();
        let vols = reex_vols(&total);
        let dir = reex_dir("obf-reextract");
        std::fs::write(dir.join("cd8140b7e2a95f36"), &vols[0]).unwrap();
        std::fs::write(dir.join("41b0f9c635de7a28"), &vols[1]).unwrap();

        assert!(reextract_dir(&dir, None).unwrap(), "resumed obfuscated set must re-extract");
        assert!(
            dir.join("film.mkv").exists(),
            "reextract_dir reported success having extracted nothing"
        );
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert_eq!(
            names_in(&dir),
            vec!["film.mkv".to_string()],
            "spent volumes survived a successful re-extraction"
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // …and a directory with nothing packed in it is still a legitimate
        // no-op, not a failure: the par-only "recreated bare payload" flow
        // depends on it.
        let bare = reex_dir("obf-reextract-bare");
        std::fs::write(bare.join("film.mkv"), &total).unwrap();
        assert!(reextract_dir(&bare, None).unwrap(), "a bare payload is a no-op, not a failure");
        assert_eq!(std::fs::read(bare.join("film.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&bare).unwrap();
    }

    // -- nested password-chain auto-unlock -------------------------------

    fn chain_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-pwchain-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A single non-volume RAR5 store archive holding `files`, each its own
    /// AES stream under one shared `pw` - the real multi-file encrypted
    /// store shape (`rar -m0 -p`).
    fn enc_store(pw: &str, files: &[(&str, &[u8])], seed: u8) -> Vec<u8> {
        use nzbkit::rar::fixtures;
        let encs: Vec<fixtures::EncFile> = files
            .iter()
            .enumerate()
            .map(|(i, (_, b))| fixtures::encrypt_file(pw, b, seed.wrapping_add((i as u8) * 7 + 1)))
            .collect();
        let pieces: Vec<(&str, &fixtures::EncFile, std::ops::Range<usize>, bool, bool)> = files
            .iter()
            .zip(&encs)
            .map(|((name, _), f)| (*name, f, 0..f.cipher.len(), false, false))
            .collect();
        fixtures::rar5_volume_enc(&pieces, None)
    }

    /// Recursively find the first file named `name` under `dir`.
    fn find_file(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(p);
                } else if p.file_name().is_some_and(|n| n == name) {
                    return Some(p);
                }
            }
        }
        None
    }

    /// The gauntlet: a 3-level encrypted chain where each level carries the
    /// NEXT level's password in a sibling text file. From only the outermost
    /// password on disk, the whole stack auto-extracts with zero manual
    /// unlocks and byte-exact final output.
    #[test]
    fn password_chain_auto_unlocks_three_levels() {
        let dir = chain_dir("unlock");
        let payload: Vec<u8> = (0..120_000u32)
            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(9))
            .collect();
        // Innermost first, then wrap outward.
        let stage3 = enc_store("charlie", &[("movie.mkv", &payload)], 40);
        let stage2 = enc_store(
            "bravo",
            &[("stage3.rar", &stage3), ("pw3.txt", b"charlie\n")],
            20,
        );
        let stage1 = enc_store("alpha", &[("stage2.rar", &stage2), ("pw2.txt", b"bravo\n")], 10);
        // On disk, as if the level above had just produced them.
        std::fs::write(dir.join("stage1.rar"), &stage1).unwrap();
        std::fs::write(dir.join("pw1.txt"), b"alpha\n").unwrap();

        // No job password: every level's key must come from the chain.
        let ok = extract_nested(&dir, None, 0).expect("extract_nested");
        assert!(ok.produced(), "3-level password chain must auto-extract (rc=0), zero parks");

        let found = find_file(&dir, "movie.mkv").expect("final payload produced");
        assert_eq!(std::fs::read(&found).unwrap(), payload, "payload bytes differ");

        // A clean nest leaves ONLY the final payload plus the extracted
        // siblings the chain rode in on (the password notes) - the spent
        // intermediate archives must not litter the output dir.
        assert!(
            find_file(&dir, "stage2.rar").is_none(),
            "consumed intermediate stage2.rar must be swept"
        );
        assert!(
            find_file(&dir, "stage3.rar").is_none(),
            "consumed intermediate stage3.rar must be swept"
        );
        // Legitimately-extracted siblings survive the sweep.
        assert!(find_file(&dir, "pw2.txt").is_some(), "extracted sibling pw2.txt kept");
        assert!(find_file(&dir, "pw3.txt").is_some(), "extracted sibling pw3.txt kept");
        // The outer downloaded archive (in `before`, not produced by the
        // nest) is out of scope for this sweep - stage1.rar is the ONLY
        // archive that may remain.
        let leftover_archives: Vec<String> = {
            let mut v = Vec::new();
            let mut stack = vec![dir.clone()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let p = e.path();
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        stack.push(p);
                    } else if p.extension().is_some_and(|x| {
                        let x = x.to_ascii_lowercase();
                        x == "rar" || x == "7z"
                    }) {
                        v.push(p.file_name().unwrap().to_string_lossy().into_owned());
                    }
                }
            }
            v.sort();
            v
        };
        assert_eq!(
            leftover_archives,
            vec!["stage1.rar".to_string()],
            "only the outer downloaded archive may remain, got {leftover_archives:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Negative: when no harvested candidate matches, the level fails loudly
    /// (rc=1 -> the daemon parks for a manual 🔑) exactly as before this
    /// feature, and never writes garbage output.
    #[test]
    fn password_chain_parks_when_no_candidate_matches() {
        let dir = chain_dir("nomatch");
        let payload = vec![0x5au8; 48_000];
        let locked = enc_store("password-not-on-disk", &[("movie.mkv", &payload)], 12);
        std::fs::write(dir.join("stage1.rar"), &locked).unwrap();
        // A decoy sidecar that does not contain the password.
        std::fs::write(dir.join("readme.nfo"), b"enjoy the release\nripped by nobody\n").unwrap();

        let ok = extract_nested(&dir, None, 0).expect("extract_nested");
        assert_eq!(ok, NestOutcome::Failed, "unmatched password must fail loudly, not exit 0");
        // The extractor may create-then-abort an output file on a wrong
        // password, but it must never yield the real plaintext (rc=1 tells
        // the daemon to park and keep the volumes for a manual 🔑).
        if let Some(p) = find_file(&dir, "movie.mkv") {
            assert_ne!(std::fs::read(&p).unwrap(), payload, "must not decrypt without the key");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store chain deeper than the cap must NOT hard-fail (the old rc=1
    /// bug). The disk post-pass unpacks to the cap, leaves the deepest
    /// reached archive materialized on disk, and returns success (rc=0) -
    /// the design guarantee that a too-deep chain degrades, never fails.
    #[test]
    fn nested_chain_deeper_than_cap_materializes_rc0() {
        use nzbkit::rar::fixtures;
        let cap = nzbkit::extract::nested_depth_cap();
        assert_eq!(cap, 5, "test assumes the default cap; env override active?");
        let dir = chain_dir("deepcap");
        let payload: Vec<u8> = (0..80_000u32).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
        let wrap = |name: &str, inner: &[u8]| {
            fixtures::rar5_volume(&[(name, inner.len() as u64, inner, false, false)])
        };
        // a1 < a2 < a3 < a4 < a5 < a6 < payload: 6 store levels, one deeper
        // than the cap. Extracting akN yields ak(N+1).
        let a6 = wrap("payload.bin", &payload);
        let a5 = wrap("a6.rar", &a6);
        let a4 = wrap("a5.rar", &a5);
        let a3 = wrap("a4.rar", &a4);
        let a2 = wrap("a3.rar", &a3);
        let a1 = wrap("a2.rar", &a2);
        std::fs::write(dir.join("release.rar"), &a1).unwrap();

        let ok = extract_nested(&dir, None, 0).expect("extract_nested");
        assert!(ok.produced(), "a chain deeper than the cap must exit rc=0, not fail");
        // The deepest reached layer (a6.rar = wrap of the payload) is left
        // materialized as a healthy archive; the payload itself is NOT
        // produced (that needs a deeper cap), but the job did not fail.
        let left = find_file(&dir, "a6.rar").expect("deepest layer left materialized");
        assert_eq!(std::fs::read(&left).unwrap(), a6, "materialized archive must be byte-exact");
        assert!(find_file(&dir, "payload.bin").is_none(), "payload is past the cap - not yet produced");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Harvest is bounded: a sidecar with far more lines than the cap yields
    /// at most MAX_PW_CANDIDATES candidates, and the job password leads.
    #[test]
    fn harvest_password_candidate_cap() {
        let dir = chain_dir("cap");
        let mut big = String::new();
        for i in 0..500 {
            big.push_str(&format!("candidate-{i}\n"));
        }
        std::fs::write(dir.join("list.txt"), big).unwrap();
        let cands = harvest_password_candidates(&dir, Some("job-pw"));
        assert!(cands.len() <= MAX_PW_CANDIDATES, "harvest exceeded cap: {}", cands.len());
        assert_eq!(cands[0].value, "job-pw");
        assert_eq!(cands[0].source, "job password");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Harvest reads sidecar lines (raw AND label-stripped), dedupes, and
    /// includes the release/sibling stems.
    #[test]
    fn harvest_reads_lines_labels_and_stems() {
        let dir = chain_dir("harvest");
        std::fs::write(dir.join("password.txt"), b"Password: hunter2\n").unwrap();
        std::fs::write(dir.join("The.Release.Name.rar"), b"Rar!\x1a\x07\x01\x00junk").unwrap();
        // Oversized sidecar is ignored (payload, not a hint).
        std::fs::write(dir.join("big.txt"), vec![b'x'; (PW_SIDECAR_MAX + 1) as usize]).unwrap();
        let cands = harvest_password_candidates(&dir, None);
        let vals: Vec<&str> = cands.iter().map(|c| c.value.as_str()).collect();
        assert!(vals.contains(&"Password: hunter2"), "raw line: {vals:?}");
        assert!(vals.contains(&"hunter2"), "label-stripped value: {vals:?}");
        assert!(
            cands.iter().any(|c| c.source == "release/sibling stem"),
            "stems harvested: {vals:?}"
        );
        assert!(!vals.iter().any(|v| v.starts_with("xxxx")), "oversized sidecar must be skipped");
        let mut uniq = vals.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), vals.len(), "candidates must be deduped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The provided password, when it already works, is kept as-is: no
    /// harvest, no override.
    #[test]
    fn resolve_keeps_working_provided_password() {
        let dir = chain_dir("provided");
        let vol = enc_store("rightpw", &[("a.bin", b"data bytes")], 30);
        std::fs::write(dir.join("s.rar"), &vol).unwrap();
        assert_eq!(resolve_level_password(&dir, Some("rightpw")), None);
        // A wrong provided password with a matching sidecar gets corrected.
        std::fs::write(dir.join("key.txt"), b"rightpw\n").unwrap();
        assert_eq!(
            resolve_level_password(&dir, Some("wrongpw")).as_deref(),
            Some("rightpw")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// bench-cpu - per-stage compute ceilings (network/compute/disk balance)
// ---------------------------------------------------------------------------

fn bench_cpu(mb: usize) {
    let cores = std::thread::available_parallelism().map_or(8, |n| n.get());
    let bytes = mb * 1024 * 1024;
    let payload: Vec<u8> = (0..bytes).map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 11) as u8)).collect();
    // One realistic article for decode benches: 700 KB part.
    let part = &payload[..700 * 1024];
    let article = nzbkit::yenc::encode("bench.bin", part.len() as u64, Some((1, 2)), 1, part);
    println!("bench-cpu: {mb} MB per stage, {cores} cores\n");
    println!("{:<26} {:>10} {:>10} {:>8}", "stage", "1-core", "all-core", "scale");

    let mut stage = |name: &str, f: &(dyn Fn(&[u8]) + Sync)| {
        // Single core.
        let t0 = Instant::now();
        f(&payload);
        let one = bytes as f64 / t0.elapsed().as_secs_f64() / 1e9;
        // All cores: each thread runs the same volume (measures aggregate).
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..cores {
                s.spawn(|| f(&payload));
            }
        });
        let all = (bytes * cores) as f64 / t0.elapsed().as_secs_f64() / 1e9;
        println!("{:<26} {:>7.2} GB/s {:>7.2} GB/s {:>7.1}x", name, one, all, all / one);
        (one, all)
    };

    let (one_memcpy, _) = stage("memcpy (baseline)", &|p: &[u8]| {
        let mut dst = vec![0u8; 4 << 20];
        for c in p.chunks(4 << 20) {
            dst[..c.len()].copy_from_slice(c);
            std::hint::black_box(&dst);
        }
    });
    let art = article.clone();
    stage("yEnc decode (scalar)", &move |p: &[u8]| {
        let iters = p.len() / (700 * 1024);
        for _ in 0..iters.max(1) {
            std::hint::black_box(nzbkit::yenc::decode(&art).unwrap());
        }
    });
    let art2 = article.clone();
    stage("yEnc decode (SIMD)", &move |p: &[u8]| {
        let iters = p.len() / (700 * 1024);
        for _ in 0..iters.max(1) {
            std::hint::black_box(nzbkit::yenc_simd::decode(&art2).unwrap());
        }
    });
    stage("crc32 (1 MB blocks)", &|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            std::hint::black_box(crc32fast::hash(c));
        }
    });
    let (_, md5_all) = stage("md5 (1 MB blocks)", &|p: &[u8]| {
        use md5::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box(d);
        }
    });
    let (_, verify_all) = stage("par2 verify (md5+crc32)", &|p: &[u8]| {
        use md5::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box((d, crc32fast::hash(c)));
        }
    });
    // Every provider is TLS, so the AEAD runs over every downloaded
    // byte - it belongs in this budget as much as md5 does. Same
    // implementation the download path uses (aws-lc-rs, rustls'
    // provider) and the same suite the connection would pin, at the
    // 16 KB TLS record size. Seal rather than open because open
    // consumes its ciphertext; for GCM and ChaCha the two directions
    // are the same work.
    let (_, aead_all) = stage(nzbkit::sysbench::tls_aead_name(), &|p: &[u8]| {
        nzbkit::sysbench::tls_aead_seal(p)
    });

    println!("\npipeline compute ceiling ≈ min stage all-core = {:.2} GB/s ({:.1} Gbps)",
        verify_all.min(aead_all), verify_all.min(aead_all) * 8.0);
    println!("(md5 alone: {:.2} GB/s all-core; every downloaded byte is decrypted once, decoded once, verified once)", md5_all);
    // The memory-traffic view. On a fast desktop memcpy is ~40 GB/s and
    // copies vanish into the noise; on a single-channel N100 or an A53
    // NAS it is ~10x slower and the SAME copies become the budget. This
    // prints the wire-path traffic in units of the machine's own memcpy
    // so the two regimes are directly comparable.
    let recv_passes = 2.0; // rustls plaintext to_vec, then append to the body buffer
    println!(
        "\nreceive-path memory traffic: {recv_passes:.0} userspace copies per wire byte \
         (rustls plaintext chunk, then the article buffer)"
    );
    println!(
        "  at this box's memcpy ({:.1} GB/s 1-core) that is {:.3} cpu-s/GB of pure copying",
        one_memcpy, recv_passes / one_memcpy
    );
    println!("compare: the network ceiling (soak) and disk ceiling (dd bs=16m)");
}

async fn sysbench_cmd(config: &PathBuf, group: &str) -> Result<()> {
    let cfg = Config::load(config)?;
    println!("== system benchmark ==");
    let compute = nzbkit::sysbench::compute(128);
    println!("compute: verify ceiling {:.1} Gbps ({} cores, SIMD decode {:.0} GB/s all-core)",
        compute.ceiling_gbps, compute.cores, compute.decode_simd.all_core);
    let out = std::env::temp_dir();
    let disk = nzbkit::sysbench::disk_write(&out, 512).unwrap_or(0.0);
    println!("disk:    {:.2} GB/s sequential write ({:.1} Gbps)", disk, disk * 8.0);
    let srv = &cfg.servers[0];
    // The probe group is the --group argument, never `ServerConfig.group`:
    // that field is a MIRROR LABEL (servers sharing it are backbone twins,
    // and the pool dedups 430s by it), freeform text from the dashboard and
    // not a newsgroup at all. Sending it as a GROUP argument answered 411 -
    // which network_probe folded into a "0.00 Gbps" verdict, and which made
    // the diversity phase below hard-error - while also overriding the group
    // the user explicitly asked for.
    let grp = group.to_string();
    print!("network: probing {} for 8s… ", srv.host);
    use std::io::Write as _;
    std::io::stdout().flush().ok();
    let (net, _probe_bytes) =
        nzbkit::sysbench::network_probe(srv, &grp, 8, 8).await.unwrap_or((0.0, 0));
    println!("{:.2} Gbps", net);
    let v = nzbkit::sysbench::verdict(net, &compute, disk);
    // The verdict leads: the sustainable speed, then a bar per subsystem -
    // the shortest bar is the limit; the others show their headroom.
    println!(
        "\n>>> expected max download: {:.2} Gbps (≈ {:.0} MB/s) - limited by {} <<<",
        v.expected_gbps,
        v.expected_gbps * 125.0,
        v.bottleneck
    );
    let rows = [
        ("network", "Network         ", v.network_gbps),
        ("compute", "Compute (verify)", v.compute_gbps),
        ("disk", "Disk write      ", v.disk_gbps),
    ];
    let mx = rows.iter().map(|r| r.2).fold(0.01f64, f64::max);
    for (key, label, val) in rows {
        let w = ((val / mx * 30.0).round() as usize).max(1);
        let tail = if key == v.bottleneck {
            " ⟵ your limit".to_string()
        } else {
            format!("  ×{:.1} headroom", val / v.expected_gbps.max(0.01))
        };
        println!("  {label} {:<30} {val:7.2} Gbps{tail}", "█".repeat(w));
    }
    println!("{}", v.advice);

    if cfg.servers.len() >= 2 {
        println!("\n== server diversity ==");
        // Age-spanning sample from server 0.
        use nzbkit::nntp::Connection;
        let (mut conn, _) = Connection::connect(srv).await?;
        let g = conn.group(&grp).await?;
        let span = g.high.saturating_sub(g.low).max(1);
        let mut ids = Vec::new();
        for band in 0..5u64 {
            let center = g.high.saturating_sub(span * band / 5);
            let from = center.saturating_sub(2_000).max(g.low);
            if let Ok(es) = conn.over(from, center).await {
                for e in es.into_iter().filter(|e| !e.message_id.is_empty()).take(20) {
                    ids.push(nzbkit::sysbench::bracket_id(&e.message_id));
                }
            }
        }
        conn.quit().await;
        let rep = nzbkit::sysbench::diversity(&cfg.servers, &ids, &grp).await;
        for s in &rep.servers {
            println!("  {:<28} {:>5.0}% avail · {:>5.2} Gbps · {:.0} ms",
                s.host, s.availability * 100.0, s.speed_gbps, s.rtt_ms);
        }
        for p in &rep.pairs {
            println!("  {:<20} ↔ {:<20} {:>4.0}% shared gaps - {}",
                p.a, p.b, p.missing_jaccard * 100.0, p.verdict);
        }
        println!("\n{}", rep.recommendation);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// index / search - the built-in indexer (M12)
// ---------------------------------------------------------------------------

/// "90d" / "26w" / "6m" / "2y" (bare number = days) → seconds; ""/0 = 0.
fn parse_age(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    let (num, unit) = match s.chars().last().unwrap() {
        c if c.is_ascii_digit() => (s, 'd'),
        // Slice at a char boundary: `s.len() - 1` lands inside a multi-byte
        // final char (e.g. "90д") and panics; strip the char's real width.
        c => (&s[..s.len() - c.len_utf8()], c.to_ascii_lowercase()),
    };
    let per = match unit {
        'd' => 86_400.0,
        'w' => 7.0 * 86_400.0,
        'm' => 30.44 * 86_400.0,
        'y' => 365.25 * 86_400.0,
        _ => anyhow::bail!("age unit must be d/w/m/y: {s:?}"),
    };
    let n: f64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("can't parse age {s:?}"))?;
    Ok((n * per) as u64)
}

/// First article number whose Date ≥ cutoff, found by bisecting the
/// group's number range with small OVER probes (~20 round-trips) instead
/// of fetching years of headers only to discard them. Expired holes and
/// dateless articles read as "old side", which errs toward scanning more.
async fn bisect_cutoff(conn: &mut Connection, mut lo: u64, mut hi: u64, cutoff: i64) -> u64 {
    // An empty group legitimately reports `low == high + 1` (RFC 3977), so
    // `hi < lo` reaches here on any group whose articles have all expired.
    // There is nothing to bisect, and `hi - lo` below would underflow: a
    // subtract-overflow panic in debug, ~64 OVER probes over garbage ranges
    // in release. `hi == lo` already fell straight through the loop.
    if hi <= lo {
        return lo;
    }
    async fn date_at(conn: &mut Connection, n: u64, hi: u64) -> i64 {
        match conn.over(n, (n + 999).min(hi)).await {
            Ok(es) => es.iter().map(|e| e.date).find(|d| *d > 0).unwrap_or(0),
            Err(_) => 0,
        }
    }
    if date_at(conn, lo, hi).await >= cutoff {
        return lo; // whole retention is newer than the cutoff
    }
    while hi - lo > 1000 {
        let mid = lo + (hi - lo) / 2;
        let d = date_at(conn, mid, hi).await;
        if d == 0 || d < cutoff {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

pub(crate) async fn index_scan(
    config: &PathBuf,
    group: &str,
    backfill: u64,
    max_age_secs: u64,
    gates: Option<&gates::Gates>,
    db: &PathBuf,
) -> Result<()> {
    let mut ix = nzbkit::index::Index::open(db)?;
    // CLI scans classify with the built-ins only (custom categories are
    // daemon settings); the daemon's reclassify pass reconciles any rows
    // a CLI scan ingested.
    index_scan_into(
        config, group, backfill, max_age_secs, gates, Vec::new(), &mut ix, None, 0, None, 1, true,
        true,
    )
    .await
}

/// Scan into an already-open Index - the daemon shares ONE connection
/// between the scan loop and every query handler, so committed rows are
/// visible immediately (two connections in one process don't reliably
/// share WAL state until checkpoint).
///
/// OVER fetching fans out over a few concurrent connections (headers are
/// the bottleneck at ~10-50k/s/conn; ingest keeps up on one thread). The
/// high-water mark only ever advances over a CONTIGUOUS completed prefix,
/// so an aborted pass resumes without holes.
///
/// `deep` = one-off backfill override: rescan the last n articles even
/// below the high-water mark (ingest is idempotent - message-id keyed).
/// `progress`, when given, is kept at the pass's fetched-header count.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn index_scan_into(
    config: &PathBuf,
    group: &str,
    backfill: u64,
    max_age_secs: u64,
    gates: Option<&gates::Gates>,
    // 24D user categories: applied to the ingest gate AND installed on
    // the index so classification at ingest matches the daemon's rules.
    cats: Vec<nzbkit::categories::CustomCategory>,
    ix: &mut nzbkit::index::Index,
    deep: Option<u64>,
    // Articles of HISTORY to add per pass below the low-water mark
    // (auto-deepen); 0 = off.
    deepen: u64,
    progress: Option<Arc<AtomicU64>>,
    // M28: how many group scans run concurrently (this one included) -
    // the per-scan connection budget divides the account limit by this
    // so parallel groups never exceed it.
    share: usize,
    // M30 turbo: nothing is downloading, so header fetch may use a
    // deeper per-group connection fan-out (clamp 10 instead of 5).
    turbo: bool,
    // A8: scan the OTHER eligible backbones' tips too (their own marks),
    // so propagation holes and single-backbone posts reach the index.
    coverage: bool,
) -> Result<()> {
    if let Some(g) = gates {
        let g = g.clone();
        let gc = cats.clone();
        ix.set_gate(Box::new(move |stem| g.allows_with(stem, &gc)));
    }
    ix.set_custom(cats);
    let cfg = Config::load(config)
        .with_context(|| format!("loading {} (copy config.local.json.example?)", config.display()))?;
    if cfg.servers.is_empty() {
        anyhow::bail!("no servers configured");
    }
    // Single-server-era marks rows (server='') were built against
    // whichever server was first in the config - claim them before any
    // mark is read. Idempotent, so every scan path may call it.
    let _ = ix.adopt_legacy_marks(&cfg.servers[0].host);

    // Probe every scan-eligible backbone: who carries this group, and
    // how much of it? A probe failure only drops that server from this
    // pass - its coverage resumes from its own marks next time.
    struct Probe {
        server: ServerConfig,
        key: String,
        conn: Connection,
        info: nzbkit::nntp::GroupInfo,
    }
    let mut probes: Vec<Probe> = Vec::new();
    for s in scan_servers(&cfg) {
        match Connection::connect(&s).await {
            Ok((mut c, _)) => match c.group(group).await {
                Ok(info) => probes.push(Probe {
                    key: nzbkit::index::Index::server_key(&s.host),
                    server: s,
                    conn: c,
                    info,
                }),
                Err(e) => {
                    // 411 = this server does not carry the group. Routine,
                    // and exactly what per-group provider choice is for.
                    println!("[scan] {}: {group}: {e}", s.host);
                    c.quit().await;
                }
            },
            Err(e) => println!("[scan] {}: connect: {e}", s.host),
        }
    }
    if probes.is_empty() {
        anyhow::bail!("no configured server carries {group}");
    }
    if probes.iter().all(|p| p.server.block_bytes.is_some_and(|b| b > 0)) {
        println!(
            "[scan] {group}: only block accounts are enabled - header \
             traffic is spending prepaid credit"
        );
    }
    // Primary = the probe with the largest article span: one number
    // that captures both carriage and retention depth, and comparable
    // across servers in magnitude even though the numbers themselves
    // are per-server. Ties keep the level/config-order rank. The
    // primary runs the full forward + deepen legs; every other
    // backbone contributes a cheap tip leg below.
    let pi = probes
        .iter()
        .enumerate()
        .max_by_key(|(i, p)| (p.info.high.saturating_sub(p.info.low), std::cmp::Reverse(*i)))
        .map(|(i, _)| i)
        .expect("probes is non-empty");
    let chosen = probes.remove(pi);
    // Persist the choice so the realtime tip watcher follows the same
    // server between passes (marks are only valid against their server).
    let _ = ix.kv_set(&format!("scan_primary:{group}"), &chosen.key);
    let server = chosen.server;
    let skey = chosen.key;
    let mut conn = chosen.conn;
    let g = chosen.info;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mark = ix.high_water(group, &skey);
    // Resume from the mark; first scan starts at the age cutoff when
    // one is set (Date bisection), else backfill-count from the newest.
    // A deep override starts n articles back regardless of the mark.
    let mut low = if let Some(n) = deep {
        let start = g.high.saturating_sub(n).max(g.low);
        if mark > 0 { start.min(mark.saturating_add(1)) } else { start }
    } else if mark > 0 {
        mark.saturating_add(1)
    } else if max_age_secs > 0 {
        let at = bisect_cutoff(&mut conn, g.low, g.high, now - max_age_secs as i64).await;
        println!("{group}: age cutoff at article {at} (group spans {}..{})", g.low, g.high);
        at
    } else {
        g.high.saturating_sub(backfill).max(g.low)
    };
    // Max-age still gates a deep backfill: never walk past the cutoff.
    if deep.is_some() && max_age_secs > 0 && low < g.high {
        let at = bisect_cutoff(&mut conn, g.low, g.high, now - max_age_secs as i64).await;
        low = low.max(at);
    }
    let t0 = Instant::now();
    let mut scanned = 0u64;
    let mut completed = 0u32;
    // False once a pass has been abandoned on the idle deadline: the
    // fan-out is unhealthy, so no leg after it may claim coverage.
    let mut healthy = true;
    if low > g.high {
        println!("{group}: up to date (high {})", g.high);
    } else {
        println!(
            "indexing {group}: articles {low}..{} ({})",
            g.high,
            g.high - low + 1
        );
        let pass = scan_article_range(
            &server,
            group,
            &skey,
            low,
            g.high,
            ix,
            now,
            Some(mark),
            progress.as_ref(),
            0,
            t0,
            share,
            turbo,
        )
        .await?;
        scanned += pass.scanned;
        completed += pass.completed;
        // An abandoned forward pass needs no repair here: the high-water
        // only ever advanced over the contiguous prefix, so the next pass
        // resumes exactly where coverage ends. The deepen leg is skipped
        // though - the fan-out is already unhealthy, and a second pass on
        // the same server would just spend another idle deadline.
        healthy = pass.complete;
    }
    // Seed the low-water on first sight of the group - including the
    // up-to-date branch (a group idle at scan time otherwise never
    // starts deepening). Worst case the seed sits above already-scanned
    // coverage and one slice gets rescanned; ingest is idempotent.
    if ix.low_water(group, &skey) == 0 {
        let seed = if low > g.high { mark } else { low }.max(g.low);
        if seed > 0 {
            let _ = ix.set_low_water(group, &skey, seed);
        }
    }

    // Auto-deepen: besides tracking NEW posts, each pass also extends
    // the index a bounded slice BACKWARD through group history, so
    // depth accumulates in the background (a fresh index otherwise only
    // ever covers its seed backfill - ~40k articles ≈ 2 h of a busy
    // group - plus the live trickle, and 'left overnight it barely
    // grew'). The low-water mark moves only once the WHOLE slice lands;
    // a failed slice is rescanned next pass (ingest is idempotent).
    if deepen > 0 && healthy {
        let cur = ix.low_water(group, &skey);
        let mut floor = g.low;
        if max_age_secs > 0 && cur > floor {
            floor = floor
                .max(bisect_cutoff(&mut conn, g.low, g.high, now - max_age_secs as i64).await);
        }
        if cur > floor {
            let hi2 = cur - 1;
            let lo2 = cur.saturating_sub(deepen).max(floor);
            println!("deepening {group}: articles {lo2}..{hi2} ({})", hi2 - lo2 + 1);
            let pass = scan_article_range(
                &server,
                group,
                &skey,
                lo2,
                hi2,
                ix,
                now,
                None,
                progress.as_ref(),
                scanned,
                t0,
                share,
                turbo,
            )
            .await?;
            scanned += pass.scanned;
            completed += pass.completed;
            // The low-water marks history as COVERED, and this leg tracks
            // no contiguous prefix - so an abandoned pass must not move
            // it, or the un-scanned slice is written off forever. The
            // whole slice is simply retried next pass (ingest is
            // idempotent).
            if pass.complete {
                ix.set_low_water(group, &skey, lo2)?;
                println!(
                    "  history now back to article {lo2} ({} older articles remain)",
                    lo2.saturating_sub(floor)
                );
            } else {
                println!("  deepen pass abandoned - history mark left at {cur}, slice retried next pass");
            }
        }
    }
    conn.quit().await;

    // A8 coverage legs: every other eligible backbone advances its OWN
    // forward tip under its own (grp, server) marks. Message-ids are
    // portable, so ingest merges whatever the primary's spool never
    // received - the release that looked permanently incomplete
    // completes the moment another backbone's headers land. Forward
    // only, on purpose: history depth is the primary's job (it was
    // chosen for having the most of it), and old incompletes are the
    // targeted gap-fill pass's job - re-deepening every backbone would
    // multiply the whole history cost for mostly-duplicate headers.
    // A secondary's failure never fails the pass; it resumes from its
    // own marks next time.
    if coverage {
        for p in probes {
            let Probe { server: s, key, conn: mut sconn, info } = p;
            let smark = ix.high_water(group, &key);
            let lo = if smark > 0 {
                smark.saturating_add(1)
            } else if max_age_secs > 0 {
                bisect_cutoff(&mut sconn, info.low, info.high, now - max_age_secs as i64).await
            } else {
                info.high.saturating_sub(backfill).max(info.low)
            };
            sconn.quit().await;
            if lo > info.high {
                continue;
            }
            println!(
                "coverage {group} via {}: articles {lo}..{} ({})",
                s.host,
                info.high,
                info.high - lo + 1
            );
            match scan_article_range(
                &s,
                group,
                &key,
                lo,
                info.high,
                ix,
                now,
                Some(smark),
                progress.as_ref(),
                scanned,
                t0,
                share,
                turbo,
            )
            .await
            {
                Ok(pass) => {
                    scanned += pass.scanned;
                    completed += pass.completed;
                }
                Err(e) => println!("[scan] {}: coverage leg for {group}: {e}", s.host),
            }
        }
    } else {
        for p in probes {
            p.conn.quit().await;
        }
    }

    if let Some(g) = gates {
        let (min, max) = g.size_bounds();
        if min > 0 || max > 0 {
            let n = ix.prune_size(min, max)?;
            if n > 0 {
                println!("  pruned {n} releases outside size gates");
            }
        }
    }
    let (rel, comp) = ix.stats()?;
    println!(
        "done: {scanned} headers in {:.1?} - index now {rel} releases, {comp} complete (+{completed} this run)",
        t0.elapsed()
    );
    Ok(())
}

/// A8 phase 2: targeted gap-fill. Pick up to `count` incomplete
/// releases and re-OVER each one's posting window on the OTHER eligible
/// backbones - idempotent ingest merges whatever headers the release's
/// scanning server never received, and `complete` flips the moment the
/// last part lands. Marks are untouched (out-of-band coverage, exactly
/// like the one-off deep rescan); every pick is stamped afterwards so
/// the rotation moves on whatever the outcome.
///
/// The oracle ledger RANKS the candidate backbones (best measured
/// carrier of the release's family and age first) but never skips one:
/// the ledger measures BODY availability, and headers may well still be
/// listed where bodies are gone - and an NZB indexed here is
/// downloadable from the whole pool, not just the server that indexed
/// it.
///
/// Returns (releases tried, releases now complete).
pub(crate) async fn index_gapfill_pass(
    config: &PathBuf,
    ix: &mut nzbkit::index::Index,
    count: u32,
    stop: impl Fn() -> bool,
) -> Result<(u32, u32)> {
    // The window around first_posted to re-read. first_posted is the
    // EARLIEST article date seen, and uploads run forward from there,
    // so the window leans forward. Multi-day uploads outrun this; the
    // budget below bounds the spend either way.
    const WIN_BACK: i64 = 1800;
    const WIN_FWD: i64 = 4 * 3600;
    // OVER budget per (group, server) per pass - a busy group's 4.5 h
    // window can span ~100k articles, and this is background polish
    // that must never crowd out the scan proper.
    const MAX_ARTICLES: u64 = 100_000;
    const CHUNK: u64 = 20_000;

    let cfg = Config::load(config)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let picks = ix.gapfill_pick(count, now)?;
    if picks.is_empty() {
        return Ok((0, 0));
    }
    let servers = scan_servers(&cfg);
    if servers.len() < 2 {
        // One backbone total: there is no "other" provider to ask.
        return Ok((0, 0));
    }
    let snap = ix.oracle_snapshot().unwrap_or_default();
    let mut by_grp: std::collections::BTreeMap<String, Vec<(i64, i64)>> = Default::default();
    for (id, grp, posted) in &picks {
        by_grp.entry(grp.clone()).or_default().push((*id, *posted));
    }
    let mut completed = 0u32;
    'grps: for (grp, mut rels) in by_grp {
        if stop() {
            break;
        }
        let primary = ix.kv_get(&format!("scan_primary:{grp}")).unwrap_or_default();
        let fam = nzbkit::oracle::group_family(&grp);
        rels.sort_by_key(|&(_, p)| p);
        // Cluster overlapping windows: one busy evening's picks cost one
        // bisection pair, not one per release.
        let mut windows: Vec<(i64, i64)> = Vec::new();
        for &(_, p) in &rels {
            let (s, e) = (p - WIN_BACK, p + WIN_FWD);
            match windows.last_mut() {
                Some(w) if s <= w.1 => w.1 = w.1.max(e),
                _ => windows.push((s, e)),
            }
        }
        // The ledger bucket the ranking reads: the median pick's age.
        let mid_posted = rels[rels.len() / 2].1;
        let bucket = nzbkit::oracle::age_bucket(((now - mid_posted).max(0) / 86_400) as u32);
        let mut secs: Vec<&ServerConfig> = servers
            .iter()
            .filter(|s| nzbkit::index::Index::server_key(&s.host) != primary)
            .collect();
        if secs.is_empty() {
            continue;
        }
        // Best measured carrier first; a blind spot ranks between a good
        // and a bad cell (unknown is not gone).
        let rate = |s: &ServerConfig| {
            snap.carry_rate(&nzbkit::oracle::backbone_of(&s.host), &fam, bucket)
                .unwrap_or(0.75)
        };
        secs.sort_by(|a, b| rate(b).partial_cmp(&rate(a)).unwrap_or(std::cmp::Ordering::Equal));
        for s in secs {
            if stop() {
                break 'grps;
            }
            let Ok((mut conn, _)) = Connection::connect(s).await else { continue };
            let Ok(g) = conn.group(&grp).await else {
                conn.quit().await;
                continue;
            };
            let mut budget = MAX_ARTICLES;
            for &(ws, we) in &windows {
                if budget == 0 || stop() {
                    break;
                }
                let lo = bisect_cutoff(&mut conn, g.low, g.high, ws).await;
                let hi = bisect_cutoff(&mut conn, g.low, g.high, we).await.min(g.high);
                if hi <= lo {
                    continue;
                }
                let mut at = lo;
                while at <= hi && budget > 0 && !stop() {
                    let chunk_hi = at.saturating_add(CHUNK.min(budget) - 1).min(hi);
                    match conn.over(at, chunk_hi).await {
                        Ok(entries) => {
                            let _ = ix.ingest(&grp, &entries, now);
                        }
                        Err(_) => break,
                    }
                    budget = budget.saturating_sub(chunk_hi - at + 1);
                    at = chunk_hi.saturating_add(1);
                }
            }
            conn.quit().await;
            if rels.iter().all(|&(id, _)| ix.is_complete(id)) {
                break; // every pick in this group landed - stop spending
            }
        }
        for &(id, _) in &rels {
            if ix.is_complete(id) {
                completed += 1;
            }
        }
    }
    // Stamp every pick - including ones a stop() cut short. Rotating an
    // untried pick is the lesser evil against a pause storm pinning the
    // same picks forever.
    for (id, _, _) in &picks {
        let _ = ix.gapfill_mark(*id, now);
    }
    Ok((picks.len() as u32, completed))
}

/// Connect for a header scan, opting in to RFC 8054 COMPRESS DEFLATE
/// when the server advertises it - overview text compresses ~10:1 and a
/// scan is pure OVER traffic. Scan path ONLY: the download path never
/// compresses (yEnc bodies don't compress, the CPU would be waste).
/// Provider tolerance beats the win: a refused or malformed COMPRESS
/// exchange falls back to a fresh uncompressed connection, never a
/// corrupted scan. NZBFAST_NNTP_COMPRESS=0 is the kill switch.
async fn scan_connect(
    server: &nzbkit::config::ServerConfig,
) -> Result<Connection, nzbkit::nntp::NntpError> {
    let (mut c, _) = Connection::connect(server).await?;
    if std::env::var("NZBFAST_NNTP_COMPRESS").is_ok_and(|v| v == "0") {
        return Ok(c);
    }
    match c.capabilities().await {
        Ok(caps) if nzbkit::nntp::caps_support_compress_deflate(&caps) => {
            match c.enable_compression().await {
                Ok(cc) => {
                    // Say so ONCE per host: raw deflate is invisible on
                    // the wire, and if a server's compression is slow or
                    // flaky, a user's log must show what was negotiated
                    // (NZBFAST_NNTP_COMPRESS=0 is the off switch).
                    static ANNOUNCED: std::sync::Mutex<Vec<String>> =
                        std::sync::Mutex::new(Vec::new());
                    let mut seen = ANNOUNCED.lock().unwrap();
                    if !seen.iter().any(|h| h == &server.host) {
                        seen.push(server.host.clone());
                        println!("[scan] COMPRESS DEFLATE active on {}", server.host);
                    }
                    Ok(cc)
                }
                // Advertised but the exchange failed - retry plain once,
                // and say so: a broken COMPRESS implementation costs a
                // failed handshake per scan connection to this server.
                Err(e) => {
                    println!(
                        "[scan] {} advertised COMPRESS DEFLATE but the exchange \
                         failed ({e}) - scanning uncompressed",
                        server.host
                    );
                    Ok(Connection::connect(server).await?.0)
                }
            }
        }
        // No COMPRESS on offer, or a pre-3977 server rejecting
        // CAPABILITIES outright (its status line was consumed, the
        // connection is still clean) - carry on uncompressed.
        Ok(_) | Err(nzbkit::nntp::NntpError::Unexpected { .. }) => Ok(c),
        Err(e) => Err(e),
    }
}

/// Outcome of one OVER fan-out pass.
struct ScanPass {
    scanned: u64,
    completed: u32,
    /// False when the pass was ABANDONED on the idle deadline: some chunk
    /// never came back, so coverage of `lo..=hi` is NOT complete. The
    /// caller must not claim the range - in particular the deepen leg's
    /// `set_low_water` has to be skipped, or the missing slice is written
    /// off as scanned and never revisited.
    complete: bool,
}

/// How long the collector waits for ANY worker to deliver a chunk before
/// abandoning the pass. Generous: it is idle time across the whole
/// fan-out, not per chunk.
///
/// The workers used to be detached tasks each holding a clone of the
/// result sender, and the collector was a bare `while let Some(..) =
/// rx.recv()`. One worker wedged somewhere the NNTP idle deadline does not
/// reach never dropped its sender, so `recv()` never returned None,
/// `index_scan_into` never returned, and the caller's scan JoinSet blocked
/// forever - no group indexed again until restart. Two changes close that:
/// the workers now live in a JoinSet that is aborted when this function
/// returns, and the collector is bounded by this deadline.
fn scan_idle_timeout() -> std::time::Duration {
    let secs = std::env::var("NZBFAST_SCAN_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(300);
    std::time::Duration::from_secs(secs)
}

/// Fan OVER chunks for articles lo..=hi over a few connections and
/// ingest them. `forward_mark` = Some(mark): the group's high-water
/// advances over the contiguous completed prefix (an aborted pass
/// resumes without holes). None = a backward deepen slice - no marks
/// are touched here; the caller moves the low-water once the whole
/// slice has landed.
#[allow(clippy::too_many_arguments)]
async fn scan_article_range(
    server: &nzbkit::config::ServerConfig,
    group: &str,
    // Marks identity of `server` - the high-water this pass advances
    // belongs to (group, mark_server).
    mark_server: &str,
    low: u64,
    g_high: u64,
    ix: &mut nzbkit::index::Index,
    now: i64,
    forward_mark: Option<u64>,
    progress: Option<&Arc<AtomicU64>>,
    progress_base: u64,
    t0: Instant,
    // M28: concurrent scans sharing the account's connection budget.
    share: usize,
    turbo: bool,
) -> Result<ScanPass> {
    // A few connections multiply header throughput; OVER is cheap for
    // the server, but stay well inside the account's connection budget.
    let nconn = (server.connections as u64 / share.max(1) as u64)
        .clamp(1, if turbo { 10 } else { 5 });
    // Chunk size scales INVERSELY with the fan-out: per-request server
    // latency (not RTT - measured stalls up to ~1 s before a response
    // starts streaming) dominates small requests, so a lone connection
    // wants big streaming ranges (100k articles ≈ 82-95k hdr/s vs
    // 31-54k/s at 10k measured per-request). A wide fan-out keeps the
    // old 10k chunks: there the whole pass finishes in seconds and
    // work-stealing granularity wins - the 23 Jul A/B measured 20k
    // chunks at 10 conns ~14% SLOWER by median (a straggling last
    // chunk sets the tail). Budget also bounds buffered headers and
    // keeps the contiguous-prefix resume mark reasonably fine-grained.
    let chunk: u64 = (100_000 / nconn).clamp(10_000, 100_000);
    let nconn = nconn.min(g_high.saturating_sub(low) / chunk + 1) as usize;
    let next = Arc::new(AtomicU64::new(low));
    // Bounded channel: workers stall rather than outrun SQLite ingest.
    // Bound counts CHUNKS, so it shrinks as chunks grow - queued headers
    // stay ~200k regardless of the chunk/fan-out split.
    let bound = ((100_000 / chunk) as usize).clamp(2, 8);
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<Result<(u64, u64, Vec<nzbkit::nntp::OverEntry>)>>(bound);
    // A JoinSet, not detached `tokio::spawn`: dropping it on the way out
    // ABORTS every worker, so an abandoned pass takes its wedged
    // connection with it instead of leaving it running for the life of
    // the process (see `scan_idle_timeout`).
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..nconn {
        let server = server.clone();
        let group_s = group.to_string();
        let next = next.clone();
        let tx = tx.clone();
        let mut conn: Option<Connection> = None;
        // `tx` is moved into the task, so it drops on every exit path -
        // normal return, early `break`, and panic-unwind alike (tokio
        // drops a panicked task's future). What it does NOT cover is a
        // worker that simply never returns; that is the collector's
        // idle deadline below.
        workers.spawn(async move {
            loop {
                let lo = next.fetch_add(chunk, Ordering::Relaxed);
                if lo > g_high {
                    break;
                }
                // Saturating: `g_high` is server-supplied (validated below
                // u64::MAX in `group()`), but keep the chunk-high computation
                // itself wrap-proof so a near-ceiling `lo` can never produce a
                // reversed `hi < lo` range (which would underflow the
                // `hi - lo + 1` accounting below and revisit ranges forever).
                let hi = lo.saturating_add(chunk - 1).min(g_high);
                // One reconnect-and-retry per chunk before giving up.
                let mut retried = false;
                let entries = loop {
                    if conn.is_none() {
                        // E2: compressed when the server offers it - see
                        // scan_connect for the fallback contract. A chunk
                        // RETRY reconnects PLAIN: if the first attempt
                        // died mid-stream (e.g. a server whose deflate
                        // implementation is broken past the handshake),
                        // trying compression again would just fail the
                        // chunk for good.
                        let fresh = if retried {
                            Connection::connect(&server).await.map(|(c, _)| c)
                        } else {
                            scan_connect(&server).await
                        };
                        match fresh {
                            Ok(mut c) => match c.group(&group_s).await {
                                Ok(_) => conn = Some(c),
                                Err(e) if retried => break Err(anyhow::Error::from(e)),
                                Err(_) => {
                                    retried = true;
                                    continue;
                                }
                            },
                            Err(e) if retried => break Err(anyhow::Error::from(e)),
                            Err(_) => {
                                retried = true;
                                continue;
                            }
                        }
                    }
                    match conn.as_mut().unwrap().over(lo, hi).await {
                        Ok(es) => break Ok(es),
                        Err(e) => {
                            conn = None;
                            if retried {
                                break Err(anyhow::Error::from(e));
                            }
                            retried = true;
                        }
                    }
                };
                let failed = entries.is_err();
                if tx.send(entries.map(|es| (lo, hi, es))).await.is_err() || failed {
                    break;
                }
            }
            if let Some(c) = conn {
                c.quit().await;
            }
        });
    }
    drop(tx);

    let pass = collect_scan_pass(
        &mut rx,
        ix,
        group,
        mark_server,
        low,
        g_high,
        now,
        forward_mark,
        progress,
        progress_base,
        chunk,
        t0,
        scan_idle_timeout(),
    )
    .await;
    // Dropping `workers` here aborts anything still running - including
    // the worker that wedged - which also releases its connection.
    drop(workers);
    pass
}

/// The collect half of [`scan_article_range`], split out so the abandon
/// path is reachable from a test without an NNTP server.
#[allow(clippy::too_many_arguments)]
async fn collect_scan_pass(
    rx: &mut tokio::sync::mpsc::Receiver<Result<(u64, u64, Vec<nzbkit::nntp::OverEntry>)>>,
    ix: &mut nzbkit::index::Index,
    group: &str,
    mark_server: &str,
    low: u64,
    g_high: u64,
    now: i64,
    forward_mark: Option<u64>,
    progress: Option<&Arc<AtomicU64>>,
    progress_base: u64,
    chunk: u64,
    t0: Instant,
    // How long to wait for ANY worker before abandoning (a parameter so
    // the abandon path is testable without a 5-minute test).
    idle: std::time::Duration,
) -> Result<ScanPass> {
    let mut scanned = 0u64;
    let mut completed = 0u32;
    // Chunks land out of order; the mark advances over the contiguous
    // prefix only (never regressing below a pre-existing mark).
    let mut next_expected = low;
    let mut pending: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut failure: Option<anyhow::Error> = None;
    let mut complete = true;
    loop {
        let msg = match tokio::time::timeout(idle, rx.recv()).await {
            Ok(Some(m)) => m,
            // Every worker finished and dropped its sender: the pass
            // covered the range.
            Ok(None) => break,
            Err(_) => {
                // Nothing from ANY worker for the whole deadline. Abandon
                // the pass rather than block the scan loop forever. What
                // has been ingested stays (ingest is idempotent and the
                // marks below only ever advanced over the CONTIGUOUS
                // prefix), but the range is not claimed.
                complete = false;
                let dropped = g_high.saturating_sub(low).saturating_add(1).saturating_sub(scanned);
                println!(
                    "[scan] {group}: no chunk for {}s - abandoning this pass \
                     ({scanned} headers in, ~{dropped} articles of {low}..{g_high} not scanned; \
                     they are retried next pass)",
                    idle.as_secs()
                );
                rx.close();
                break;
            }
        };
        match msg {
            Ok((lo, hi, entries)) => {
                completed += ix.ingest(group, &entries, now)?;
                scanned += hi - lo + 1;
                if let Some(p) = progress {
                    p.store(progress_base + scanned, Ordering::Relaxed);
                }
                pending.insert(lo, hi);
                while pending.first_key_value().is_some_and(|(&l, _)| l == next_expected) {
                    let (_, hi) = pending.pop_first().unwrap();
                    next_expected = hi.saturating_add(1);
                    if let Some(mark) = forward_mark {
                        if hi > mark {
                            ix.set_high_water(group, mark_server, hi)?;
                        }
                    }
                }
                if scanned % 100_000 < chunk {
                    let (rel, comp) = ix.stats()?;
                    println!(
                        "  … {scanned} headers, {rel} releases ({comp} complete), {:.0}/s",
                        scanned as f64 / t0.elapsed().as_secs_f64()
                    );
                }
            }
            Err(e) => {
                // Stop the fan-out; the contiguous mark makes the next
                // pass resume exactly where coverage ends.
                failure = Some(e);
                rx.close();
            }
        }
    }
    if let Some(e) = failure {
        return Err(e);
    }
    Ok(ScanPass {
        scanned,
        completed,
        complete,
    })
}

/// Truncate to at most `n` BYTES on a char boundary - `&s[..60]` panics
/// mid-char on non-ASCII release names (Usenet-controlled text).
fn trunc(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut i = n;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

fn search_index(query: &str, db: &PathBuf, nzb_out: Option<&std::path::Path>) -> Result<()> {
    let ix = nzbkit::index::Index::open(db)?;
    let hits = ix.search(query, 30)?;
    if hits.is_empty() {
        println!("no matches for '{query}'");
        return Ok(());
    }
    for r in &hits {
        println!(
            "{:>6}  {:<60} {:>9.2} GB  {:>3} files  {}{}",
            r.id,
            trunc(&r.stem, 60),
            r.total_bytes as f64 / 1e9,
            r.files,
            if r.complete { "complete" } else { "partial" },
            if r.has_par2 { " +par2" } else { "" },
        );
    }
    if let Some(path) = nzb_out {
        let xml = ix.make_nzb(hits[0].id)?;
        std::fs::write(path, xml)?;
        println!("wrote {} ({})", path.display(), hits[0].stem);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// spots / spot-search / spot-get - Spotnet ingestion (M14j)
// ---------------------------------------------------------------------------

async fn spots_scan(config: &PathBuf, group: &str, backfill: u64, db: &PathBuf) -> Result<()> {
    let server = load_server(config)?;
    let mut ix = nzbkit::index::Index::open(db)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let t0 = Instant::now();
    let _ = ix.adopt_legacy_marks(&server.host);
    let sum = nzbkit::spot::scan_spots(&mut conn, &mut ix, group, &server.host, backfill).await?;
    conn.quit().await;
    let total = ix.spot_stats()?;
    println!(
        "scanned {} headers in {:.1?}: {} valid spots ({} new), {} invalid{} - index now {total} spots",
        sum.scanned,
        t0.elapsed(),
        sum.valid,
        sum.new,
        sum.invalid,
        if sum.hashcash_warn > 0 {
            format!(", {} hashcash warnings", sum.hashcash_warn)
        } else {
            String::new()
        },
    );
    Ok(())
}

fn spot_search(query: &str, db: &PathBuf) -> Result<()> {
    let ix = nzbkit::index::Index::open(db)?;
    let hits = ix.spot_search(query, 30)?;
    if hits.is_empty() {
        println!("no spots match '{query}'");
        return Ok(());
    }
    for s in &hits {
        println!(
            "{:<60} {:>9.2} GB  cat {}{}  {}  {}{}",
            trunc(&s.title, 60),
            s.size as f64 / 1e9,
            s.category,
            if s.subcats.is_empty() {
                String::new()
            } else {
                format!(" [{}]", s.subcats)
            },
            s.spotter_id,
            s.msgid,
            if s.hashcash_ok { "" } else { "  (hashcash!)" },
        );
    }
    Ok(())
}

async fn spot_get(config: &PathBuf, msgid: &str, nzb: &PathBuf, db: &PathBuf) -> Result<()> {
    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let (sx, bytes) = nzbkit::spot::fetch_spot_nzb(&mut conn, msgid).await?;
    conn.quit().await;
    std::fs::write(nzb, &bytes)?;
    // Cache the segment list on the indexed spot, if we have it.
    let mid = if msgid.starts_with('<') {
        msgid.to_string()
    } else {
        format!("<{msgid}>")
    };
    if let Ok(ix) = nzbkit::index::Index::open(db) {
        let _ = ix.set_spot_nzb(&mid, &sx.nzb_segments);
    }
    println!(
        "wrote {} ({} bytes, {} payload segments) - {}",
        nzb.display(),
        bytes.len(),
        sx.nzb_segments.len(),
        if sx.title.is_empty() { msgid } else { &sx.title },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// make-release-nzb - find one complete release (data + par2) via OVER
// ---------------------------------------------------------------------------

/// Strip release-file suffixes down to the shared stem:
/// `x.part01.rar`/`x.r00`/`x.vol000+01.par2`/`x.par2`/`x.rar` → `x`.
fn release_stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut end = lower.len();
    let cut = |s: &str, end: usize, suffix_ok: &dyn Fn(&str) -> Option<usize>| -> usize {
        suffix_ok(&s[..end]).unwrap_or(end)
    };
    // .par2 first (may wrap .volNN+MM)
    end = cut(&lower, end, &|s| s.strip_suffix(".par2").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        // .volNNN+MM / range-style .volNNN-MMM
        let vol = s.rfind(".vol")?;
        let tail = &s[vol + 4..];
        let (a, b) = tail.split_once(['+', '-'])?;
        (!a.is_empty()
            && a.bytes().all(|c| c.is_ascii_digit())
            && !b.is_empty()
            && b.bytes().all(|c| c.is_ascii_digit()))
        .then_some(vol)
    });
    end = cut(&lower, end, &|s| s.strip_suffix(".rar").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        // .partNNN
        let p = s.rfind(".part")?;
        let tail = &s[p + 5..];
        (!tail.is_empty() && tail.bytes().all(|c| c.is_ascii_digit())).then_some(p)
    });
    end = cut(&lower, end, &|s| {
        // .rNN / .sNN (split archives)
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        (tail.len() >= 2
            && (tail.starts_with('r') || tail.starts_with('s'))
            && tail[1..].bytes().all(|c| c.is_ascii_digit()))
        .then_some(p)
    });
    name[..end].to_string()
}

async fn make_release_nzb(
    config: &PathBuf,
    group: &str,
    min_gb: f64,
    max_gb: f64,
    out: &PathBuf,
) -> Result<()> {
    use std::collections::BTreeMap;
    use std::collections::HashMap;

    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;

    // (poster, stem) → filename → (total parts, part → (msgid, bytes))
    type Parts = BTreeMap<u32, (String, u64)>;
    type Release = HashMap<String, (u32, Parts)>;
    let mut releases: HashMap<(String, String), Release> = HashMap::new();

    let mut high = g.high;
    let mut scanned = 0u64;
    let mut winner: Option<((String, String), Release)> = None;
    while winner.is_none() && high > g.low && scanned < 2_000_000 {
        let from = high.saturating_sub(20_000).max(g.low);
        for e in conn.over(from, high).await? {
            // Files without a (n/m) counter (nfo/sfv posts) are single-part.
            let (base, part, total) =
                split_subject(&e.subject).unwrap_or_else(|| (e.subject.clone(), 1, 1));
            if e.message_id.is_empty() || part == 0 || total == 0 {
                continue;
            }
            // Quoted filename from the counter-stripped subject.
            let Some(fname) = quoted_name(&base) else {
                continue;
            };
            let stem = release_stem(&fname);
            if stem.is_empty() {
                continue;
            }
            let rel = releases
                .entry((e.from.clone(), stem))
                .or_default();
            let entry = rel
                .entry(fname)
                .or_insert_with(|| (total, BTreeMap::new()));
            entry.1.insert(part, (e.message_id, e.bytes));
        }
        scanned += high - from;

        // A release qualifies when: every seen file is complete, it has a
        // par2 main + at least one volume + at least one data file, and the
        // total size is in range. (Volumes prove the par2 set is fetchable;
        // the main index is what activates in-stream verification.)
        for (key, rel) in &releases {
            let all_complete = rel.values().all(|(t, p)| p.len() as u32 == *t);
            if !all_complete || rel.len() < 3 {
                continue;
            }
            let has_main = rel.keys().any(|n| {
                let l = n.to_ascii_lowercase();
                l.ends_with(".par2") && vol_count_from_name(n).is_none()
            });
            let has_vol = rel.keys().any(|n| vol_count_from_name(n).is_some());
            let has_data = rel.keys().any(|n| !n.to_ascii_lowercase().ends_with(".par2"));
            let size: u64 = rel
                .values()
                .flat_map(|(_, p)| p.values())
                .map(|v| v.1)
                .sum();
            let gb = size as f64 / 1e9;
            if has_main && has_vol && has_data && gb >= min_gb && gb <= max_gb {
                println!(
                    "release: {} ({} files, {:.2} GB) by {}",
                    key.1,
                    rel.len(),
                    gb,
                    key.0
                );
                winner = Some((key.clone(), rel.clone()));
                break;
            }
        }
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    conn.quit().await;

    let Some(((poster, _stem), rel)) = winner else {
        anyhow::bail!("no complete release with par2 found in {scanned} headers");
    };
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    let mut names: Vec<&String> = rel.keys().collect();
    names.sort();
    for fname in names {
        let (total, parts) = &rel[fname];
        let size: u64 = parts.values().map(|v| v.1).sum();
        println!("  {fname}  ({total} parts, {:.1} MB)", size as f64 / 1e6);
        xml.push_str(&format!(
            "  <file poster=\"{}\" date=\"0\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
            xml_escape(&poster),
            xml_escape(&format!("\"{fname}\" yEnc (1/{total})")),
            group,
        ));
        for (num, (msgid, bytes)) in parts {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{}</segment>\n",
                xml_escape(msgid.trim_matches(['<', '>']))
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    std::fs::write(out, xml)?;
    println!("wrote {}", out.display());
    Ok(())
}

/// First quoted substring (unquoted-convention fallback included) -
/// shared with the indexer so both paths accept the same subjects.
fn quoted_name(s: &str) -> Option<String> {
    nzbkit::index::quoted_name(s)
}

// ---------------------------------------------------------------------------
// make-test-nzb - assemble a real NZB from complete posts in a group
// ---------------------------------------------------------------------------

async fn make_test_nzb(
    config: &PathBuf,
    group: &str,
    want_files: usize,
    max_file_mb: u64,
    out: &PathBuf,
) -> Result<()> {
    use std::collections::BTreeMap;
    use std::collections::HashMap;

    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;

    // (poster, base-subject) → (total parts, map part → (msgid, bytes))
    type Parts = BTreeMap<u32, (String, u64)>;
    let mut groups: HashMap<(String, String), (u32, Parts)> = HashMap::new();
    let mut complete: Vec<((String, String), (u32, Parts))> = Vec::new();

    let mut high = g.high;
    let mut scanned = 0u64;
    while complete.len() < want_files && high > g.low && scanned < 300_000 {
        let from = high.saturating_sub(8_000).max(g.low);
        for e in conn.over(from, high).await? {
            let Some((base, part, total)) = split_subject(&e.subject) else {
                continue;
            };
            if e.message_id.is_empty() || part == 0 || total < 2 {
                continue;
            }
            let entry = groups
                .entry((e.from.clone(), base))
                .or_insert_with(|| (total, BTreeMap::new()));
            entry.1.insert(part, (e.message_id, e.bytes));
            if entry.1.len() as u32 == entry.0 {
                let key = (e.from.clone(), split_subject(&e.subject).unwrap().0);
                if let Some(done) = groups.remove(&key) {
                    let size: u64 = done.1.values().map(|v| v.1).sum();
                    if size <= max_file_mb * 1_000_000 {
                        complete.push((key, done));
                    }
                }
            }
        }
        scanned += high - from;
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    conn.quit().await;
    anyhow::ensure!(
        complete.len() >= want_files,
        "only {} complete files found (wanted {want_files})",
        complete.len()
    );
    complete.truncate(want_files);

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for ((poster, base), (total, parts)) in &complete {
        let size: u64 = parts.values().map(|v| v.1).sum();
        println!("  {base}  ({total} parts, {:.1} MB)", size as f64 / 1e6);
        xml.push_str(&format!(
            "  <file poster=\"{}\" date=\"0\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
            xml_escape(poster),
            xml_escape(&format!("{base} (1/{total})")),
            group,
        ));
        for (num, (msgid, bytes)) in parts {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{}</segment>\n",
                xml_escape(msgid.trim_matches(['<', '>']))
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    std::fs::write(out, xml)?;
    println!("wrote {} ({} files)", out.display(), complete.len());
    Ok(())
}

/// Split `… "name" yEnc (n/m)` → (base subject without the counter, n, m).
/// Shared with the indexer - rightmost parsing counter, `[n/m]`/`of` forms.
fn split_subject(subject: &str) -> Option<(String, u32, u32)> {
    nzbkit::index::split_subject(subject)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// soak - multi-provider aggregate throughput
// ---------------------------------------------------------------------------

async fn soak(
    config: &PathBuf,
    group: &str,
    articles: usize,
    connections: usize,
    window: usize,
    decoders: usize,
    shards: usize,
    rcvbuf_mb: u32,
) -> Result<()> {
    use nzbkit::pool::{ArticleReq, BufPool, FetchOutcome, PoolConfig, fetch_all_sharded};

    let mut cfg_all = Config::load(config)?;
    for s in &mut cfg_all.servers {
        if rcvbuf_mb > 0 {
            s.rcvbuf = Some(rcvbuf_mb * 1024 * 1024);
        }
    }
    println!(
        "{} server(s), {} shard(s), rcvbuf {}MB:",
        cfg_all.servers.len(),
        shards,
        rcvbuf_mb
    );
    for s in &cfg_all.servers {
        println!("  {}:{} ({} conns)", s.host, s.port, connections);
    }

    // Discover once via the first server - message-IDs are universal.
    let (mut conn, _) = Connection::connect(&cfg_all.servers[0]).await?;
    let g = conn.group(group).await?;
    let ids = discover(&mut conn, &g, articles).await?;
    conn.quit().await;
    let est: u64 = ids.iter().map(|c| c.1).sum();
    println!(
        "{} articles (~{:.1} GB) on one shared queue\n",
        ids.len(),
        est as f64 / 1e9
    );

    let buf_pool = BufPool::new(nzbkit::mem::MemBudget::auto().bufpool_bufs());
    let pool_cfg = PoolConfig {
        connections,
        window,
        buf_pool: Some(buf_pool.clone()),
        ..PoolConfig::default()
    };
    let servers: Vec<_> = cfg_all
        .servers
        .iter()
        .map(|s| (s.clone(), pool_cfg.clone()))
        .collect();

    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(256);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    // Shared consumer-side counters (also feed the live ticker).
    let raw_bytes = Arc::new(AtomicU64::new(0));
    let ok = Arc::new(AtomicU64::new(0));
    let bad = Arc::new(AtomicU64::new(0));
    let gone = Arc::new(AtomicU64::new(0));

    let mut decode_tasks = Vec::new();
    for _ in 0..decoders.max(1) {
        let rx = rx.clone();
        let pool = buf_pool.clone();
        let (raw_bytes, ok, bad, gone) =
            (raw_bytes.clone(), ok.clone(), bad.clone(), gone.clone());
        decode_tasks.push(tokio::spawn(async move {
            loop {
                let outcome = { rx.lock().await.recv().await };
                match outcome {
                    Some(FetchOutcome::Done { raw, .. }) => {
                        raw_bytes.fetch_add(raw.len() as u64, Ordering::Relaxed);
                        match nzbkit::yenc_simd::decode(&raw) {
                            Ok(_) => ok.fetch_add(1, Ordering::Relaxed),
                            Err(_) => bad.fetch_add(1, Ordering::Relaxed),
                        };
                        pool.give(raw);
                    }
                    Some(_) => {
                        gone.fetch_add(1, Ordering::Relaxed);
                    }
                    None => break,
                }
            }
        }));
    }

    // Live rate ticker.
    let ticker_bytes = raw_bytes.clone();
    let ticker = tokio::spawn(async move {
        let mut last = 0u64;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = ticker_bytes.load(Ordering::Relaxed);
            println!(
                "  … {:>7.1} MB/s ({:.2} Gbps)  total {:.2} GB",
                (now - last) as f64 / 2e6,
                (now - last) as f64 * 8.0 / 2e9,
                now as f64 / 1e9
            );
            last = now;
        }
    });

    let t0 = Instant::now();
    // Discovered live off the spool - fresh by definition.
    let id_list: Vec<ArticleReq> = ids
        .into_iter()
        .map(|(id, _)| ArticleReq::fresh(id))
        .collect();
    let servers_moved = servers.clone();
    let stats = tokio::task::spawn_blocking(move || {
        fetch_all_sharded(servers_moved, id_list, tx, shards, None)
    })
    .await?;
    let elapsed = t0.elapsed();
    for t in decode_tasks {
        let _ = t.await;
    }
    ticker.abort();

    let total = raw_bytes.load(Ordering::Relaxed);
    println!("\n== aggregate: {:.2} GB in {:.2?} → {:.1} MB/s ({:.2} Gbps) ==",
        total as f64 / 1e9,
        elapsed,
        total as f64 / 1e6 / elapsed.as_secs_f64(),
        total as f64 * 8.0 / 1e9 / elapsed.as_secs_f64(),
    );
    for ((s, _), st) in servers.iter().zip(&stats) {
        println!(
            "  {:<28} {:>8.1} MB ({:>4.0} Mbps avg) · {} conns, {} reconnects",
            s.host,
            st.bytes as f64 / 1e6,
            st.bytes as f64 * 8.0 / 1e6 / elapsed.as_secs_f64(),
            st.connects,
            st.reconnects
        );
    }
    println!(
        "decoded OK {} · errors {} · missing/failed {}",
        ok.load(Ordering::Relaxed),
        bad.load(Ordering::Relaxed),
        gone.load(Ordering::Relaxed)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// fetch - pool + decoder shakeout under real conditions
// ---------------------------------------------------------------------------

async fn fetch(
    config: &PathBuf,
    group: &str,
    articles: usize,
    connections: usize,
    window: usize,
) -> Result<()> {
    use nzbkit::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all};

    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;
    let ids = discover(&mut conn, &g, articles).await?;
    conn.quit().await;
    println!(
        "{} articles from {group}; pool: {connections} conns, window {window}",
        ids.len()
    );

    let cfg = PoolConfig {
        connections,
        window,
        ..PoolConfig::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);

    // Consumer decodes concurrently with the pool's fetching - the overlap
    // the real pipeline relies on.
    let consumer = tokio::spawn(async move {
        let (mut ok, mut decoded_bytes, mut crc_bad, mut missing, mut failed) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        while let Some(outcome) = rx.recv().await {
            match outcome {
                FetchOutcome::Done { raw, .. } => match nzbkit::yenc_simd::decode(&raw) {
                    Ok(dec) => {
                        ok += 1;
                        decoded_bytes += dec.data.len() as u64;
                    }
                    Err(_) => crc_bad += 1,
                },
                FetchOutcome::Missing { .. } => missing += 1,
                FetchOutcome::Failed { .. } => failed += 1,
            }
        }
        (ok, decoded_bytes, crc_bad, missing, failed)
    });

    let t0 = Instant::now();
    let stats = fetch_all(
        &server,
        &cfg,
        ids.iter()
            .map(|(id, _)| ArticleReq::fresh(id.clone()))
            .collect(),
        tx,
    )
    .await;
    let elapsed = t0.elapsed();
    let (ok, decoded_bytes, crc_bad, missing, failed) = consumer.await?;

    println!(
        "{:.1} MB raw in {:.2?} → {:.1} MB/s ({:.0} Mbps)",
        stats.bytes as f64 / 1e6,
        elapsed,
        stats.bytes as f64 / 1e6 / elapsed.as_secs_f64(),
        stats.bytes as f64 * 8.0 / 1e6 / elapsed.as_secs_f64(),
    );
    println!(
        "decoded OK {ok} ({:.1} MB) · decode/crc errors {crc_bad} · missing {missing} · failed {failed}",
        decoded_bytes as f64 / 1e6
    );
    println!(
        "connections: {} opened, {} reconnects",
        stats.connects, stats.reconnects
    );
    Ok(())
}

pub(crate) fn load_server(config: &PathBuf) -> Result<ServerConfig> {
    let cfg = Config::load(config)
        .with_context(|| format!("loading {} (copy config.local.json.example?)", config.display()))?;
    Ok(cfg.servers[0].clone())
}

/// A8 multi-server indexing: the servers worth scanning HEADERS from.
///
/// - enabled only;
/// - never a prepaid block (`block_bytes` set): OVER traffic burns the
///   credit that exists to rescue missing bodies;
/// - one per backbone: mirrors share a spool, so a second reseller of
///   the same backbone contributes no headers the first didn't. Mirrors
///   are detected by the explicit `group` field first, else by
///   [`nzbkit::oracle::backbone_of`];
/// - ranked level-then-config-order, which is the tiebreak order the
///   per-group primary choice uses.
///
/// An all-block (but enabled) config falls back to the enabled list
/// unfiltered - a user who configured indexing gets an index; the
/// caller logs that headers are spending block credit.
/// Resolve a marks server key (see [`nzbkit::index::Index::server_key`])
/// back to its config entry - the scan loop persists only the key.
/// None = the config no longer carries that server.
pub(crate) fn find_scan_server(config: &PathBuf, key: &str) -> Option<ServerConfig> {
    let cfg = Config::load(config).ok()?;
    cfg.servers
        .iter()
        .find(|s| nzbkit::index::Index::server_key(&s.host) == key)
        .cloned()
}

pub(crate) fn scan_servers(cfg: &Config) -> Vec<ServerConfig> {
    let eligible: Vec<&ServerConfig> = {
        let flat: Vec<&ServerConfig> = cfg
            .servers
            .iter()
            .filter(|s| s.enabled && !s.block_bytes.is_some_and(|b| b > 0))
            .collect();
        if flat.is_empty() {
            cfg.servers.iter().filter(|s| s.enabled).collect()
        } else {
            flat
        }
    };
    let mut ranked = eligible;
    // Stable: config order survives within a level.
    ranked.sort_by_key(|s| s.level);
    let mut seen = std::collections::HashSet::new();
    ranked
        .into_iter()
        .filter(|s| {
            let backbone = s
                .group
                .clone()
                .unwrap_or_else(|| nzbkit::oracle::backbone_of(&s.host));
            seen.insert(backbone)
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// probe
// ---------------------------------------------------------------------------

async fn probe(config: &PathBuf) -> Result<()> {
    let cfg = Config::load(config)?;
    for server in &cfg.servers {
        print!("{:<28}", server.host);
        let t0 = Instant::now();
        match Connection::connect(server).await {
            Ok((mut conn, _)) => {
                let connected = t0.elapsed();
                let mut rtts = Vec::new();
                for _ in 0..3 {
                    let t = Instant::now();
                    conn.exec("DATE").await?;
                    rtts.push(t.elapsed());
                }
                let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                let pipelining = conn
                    .capabilities()
                    .await
                    .map(|caps| caps.iter().any(|c| c.contains("PIPELINING")))
                    .unwrap_or(false);
                let g = conn.group("alt.binaries.boneless").await;
                conn.quit().await;
                println!(
                    " ok: auth {:>4}ms · RTT {:>5.1}ms · PIPELINING {} · boneless {}",
                    connected.as_millis(),
                    avg.as_secs_f64() * 1000.0,
                    if pipelining { "yes" } else { "n/a" },
                    if g.is_ok() { "ok" } else { "MISSING" },
                );
            }
            Err(e) => println!(" FAILED: {e}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bench - the thesis test (design: Phase 2c)
// ---------------------------------------------------------------------------

struct FetchStats {
    bytes: u64,
    missing: u64,
    errors: u64,
    error_samples: Vec<String>,
    elapsed: std::time::Duration,
}

async fn bench(
    config: &PathBuf,
    group: &str,
    articles: usize,
    connections: usize,
    window: usize,
    simultaneous: bool,
    duration: u64,
) -> Result<()> {
    let server = load_server(config)?;

    // Discovery: pull OVER data until we have 2×articles usable candidates.
    println!("discovering articles in {group} …");
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;
    anyhow::ensure!(g.count > 0, "group {group} is empty on this server");

    // In duration mode, size the pool so no fleet runs dry: assume up to
    // ~30 MB/s/conn on fibre → ~45 articles/s/conn.
    let want = if duration > 0 {
        (connections * duration as usize * 45 * 2).max(articles * 2)
    } else {
        articles * 2
    };
    let candidates = discover(&mut conn, &g, want).await?;
    anyhow::ensure!(
        candidates.len() >= (articles * 2).min(want),
        "only {} usable articles found in {group}; try another group",
        candidates.len()
    );
    conn.quit().await; // free the discovery session before the fetch fleets
    let est: u64 = candidates.iter().map(|c| c.1).sum();
    println!(
        "{} candidates, ~{:.0} MB total; {} conns, window {}",
        candidates.len(),
        est as f64 / 1e6,
        connections,
        window
    );

    // Alternate assignment so both modes see the same size distribution and
    // neither benefits from provider-side caching of the other's set.
    let mut serial_set = Vec::new();
    let mut pipe_set = Vec::new();
    for (i, c) in candidates.into_iter().enumerate() {
        if i % 2 == 0 {
            serial_set.push(c.0);
        } else {
            pipe_set.push(c.0);
        }
    }

    let dur = (duration > 0).then(|| std::time::Duration::from_secs(duration));
    let (s, p) = if simultaneous {
        println!("\nrunning both modes simultaneously (paired) …");
        let (s, p) = tokio::join!(
            run_fetch(&server, serial_set, connections, 1, dur),
            run_fetch(&server, pipe_set, connections, window, dur),
        );
        (s?, p?)
    } else {
        println!("\n- serial (window 1) -");
        let s = run_fetch(&server, serial_set, connections, 1, dur).await?;
        println!("\n- pipelined (window {window}) -");
        let p = run_fetch(&server, pipe_set, connections, window, dur).await?;
        (s, p)
    };
    println!("\n- serial (window 1) -");
    report(&s);
    println!("- pipelined (window {window}) -");
    report(&p);

    let s_rate = s.bytes as f64 / s.elapsed.as_secs_f64();
    let p_rate = p.bytes as f64 / p.elapsed.as_secs_f64();
    println!(
        "\npipelining speedup at {connections} connections: {:+.1}%",
        (p_rate / s_rate - 1.0) * 100.0
    );
    Ok(())
}

fn report(s: &FetchStats) {
    println!(
        "  {:.1} MB in {:.2?}  →  {:.1} MB/s ({:.0} Mbps){}{}",
        s.bytes as f64 / 1e6,
        s.elapsed,
        s.bytes as f64 / 1e6 / s.elapsed.as_secs_f64(),
        s.bytes as f64 * 8.0 / 1e6 / s.elapsed.as_secs_f64(),
        if s.missing > 0 {
            format!("  [{} missing]", s.missing)
        } else {
            String::new()
        },
        if s.errors > 0 {
            format!("  [{} errors]", s.errors)
        } else {
            String::new()
        },
    );
    for e in &s.error_samples {
        println!("    error: {e}");
    }
}

/// Scan a group backwards collecting mid-size binary articles (comparable
/// units of work) until `want` candidates are found.
async fn discover(
    conn: &mut Connection,
    g: &nzbkit::nntp::GroupInfo,
    want: usize,
) -> Result<Vec<(String, u64)>> {
    let mut candidates: Vec<(String, u64)> = Vec::new();
    let mut high = g.high;
    let mut scanned = 0u64;
    while candidates.len() < want && high > g.low && scanned < 400_000 {
        let from = high.saturating_sub(4_000).max(g.low);
        for e in conn.over(from, high).await? {
            if (300_000..=1_200_000).contains(&e.bytes) && !e.message_id.is_empty() {
                candidates.push((e.message_id, e.bytes));
            }
        }
        scanned += high - from;
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    candidates.truncate(want);
    Ok(candidates)
}

/// Pull the next message-id, or None when the queue is dry / deadline passed.
async fn pop_id(
    queue: &tokio::sync::Mutex<std::collections::VecDeque<String>>,
    deadline: Option<Instant>,
) -> Option<String> {
    if let Some(d) = deadline
        && Instant::now() >= d
    {
        return None;
    }
    queue.lock().await.pop_front()
}

/// Fetch from a shared work queue across `connections` connections with
/// `window` commands in flight per connection. Connection setup happens
/// before the clock starts.
///
/// With `duration` set, workers stop pulling new work at the deadline and
/// only bytes received before it are counted - cold-article stragglers
/// can't skew the rate.
async fn run_fetch(
    server: &ServerConfig,
    ids: Vec<String>,
    connections: usize,
    window: usize,
    duration: Option<std::time::Duration>,
) -> Result<FetchStats> {
    let queue = Arc::new(tokio::sync::Mutex::new(
        ids.into_iter().collect::<std::collections::VecDeque<String>>(),
    ));

    let mut conns = Vec::new();
    for _ in 0..connections {
        let (c, _) = Connection::connect(server).await?;
        conns.push(c);
    }

    let bytes = Arc::new(AtomicU64::new(0));
    let missing = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let error_log = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));

    let t0 = Instant::now();
    let deadline = duration.map(|d| t0 + d);
    let mut tasks = Vec::new();
    for mut conn in conns {
        let queue = queue.clone();
        let bytes = bytes.clone();
        let missing = missing.clone();
        let errors = errors.clone();
        let error_log = error_log.clone();
        tasks.push(tokio::spawn(async move {
            let fail = |msg: String| async move {
                errors.fetch_add(1, Ordering::Relaxed);
                let mut log = error_log.lock().await;
                if log.len() < 3 {
                    log.push(msg);
                }
            };

            let mut inflight = 0usize;
            // Prime the window.
            for _ in 0..window {
                if let Some(id) = pop_id(&queue, deadline).await {
                    if let Err(e) = conn.send_body(&id).await {
                        fail(format!("send: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    inflight += 1;
                }
            }
            if let Err(e) = conn.flush().await {
                fail(format!("flush: {e}")).await;
                conn.quit().await;
                return;
            }

            while inflight > 0 {
                match tokio::time::timeout(std::time::Duration::from_secs(60), conn.read_body())
                    .await
                {
                    Ok(Ok(Some(raw))) => {
                        if deadline.is_none_or(|d| Instant::now() < d) {
                            bytes.fetch_add(raw.len() as u64, Ordering::Relaxed);
                        }
                    }
                    Ok(Ok(None)) => {
                        missing.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(e)) => {
                        fail(format!("read: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    Err(_) => {
                        // Timed out mid-response - connection state is
                        // unusable; drop without QUIT.
                        fail("read: 60s timeout".into()).await;
                        return;
                    }
                }
                inflight -= 1;
                if let Some(id) = pop_id(&queue, deadline).await {
                    if let Err(e) = conn.send_body(&id).await {
                        fail(format!("send: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    if let Err(e) = conn.flush().await {
                        fail(format!("flush: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    inflight += 1;
                }
            }
            conn.quit().await;
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    // In duration mode the rate denominator is the fixed window, not the
    // (slightly longer) drain time.
    let elapsed = duration.unwrap_or_else(|| t0.elapsed());

    Ok(FetchStats {
        bytes: bytes.load(Ordering::Relaxed),
        missing: missing.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        error_samples: std::mem::take(&mut *error_log.lock().await),
        elapsed,
    })
}

// ---------------------------------------------------------------------------
// inspect (Phase 1a)
// ---------------------------------------------------------------------------

/// `nzbfast stream`: submit an NZB (file or URL) to the running daemon
/// with stream=1 - Force priority + player-handoff links - then hand the
/// .m3u to the OS default player. The download side is the daemon's; this
/// is just the one-command front door for "watch it now".
fn stream_cmd(nzb: &str, host: &str, port: u16, apikey: Option<&str>, no_open: bool) -> Result<()> {
    use std::io::{Read as _, Write as _};
    fn urlenc(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    let key_q = apikey.map(|k| format!("&apikey={k}")).unwrap_or_default();
    const BOUNDARY: &str = "----nzbfaststream";
    let (path, body): (String, Vec<u8>) =
        if nzb.starts_with("http://") || nzb.starts_with("https://") {
            (
                format!("/api?mode=addurl&output=json&stream=1{key_q}&name={}", urlenc(nzb)),
                Vec::new(),
            )
        } else {
            let bytes = std::fs::read(nzb).with_context(|| format!("reading {nzb}"))?;
            let fname = std::path::Path::new(nzb)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let mut b = Vec::new();
            b.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n"
                )
                .as_bytes(),
            );
            b.extend_from_slice(&bytes);
            b.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
            (format!("/api?mode=addfile&output=json&stream=1{key_q}"), b)
        };
    let mut s = std::net::TcpStream::connect((host, port)).with_context(|| {
        format!("no daemon at {host}:{port} - start one with `nzbfast serve`")
    })?;
    if body.is_empty() {
        write!(s, "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n")?;
    } else {
        write!(
            s,
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary={BOUNDARY}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )?;
        s.write_all(&body)?;
    }
    let mut raw = String::new();
    s.read_to_string(&mut raw)?;
    let json_body = raw.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    let v: serde_json::Value = serde_json::from_str(json_body)
        .with_context(|| format!("bad daemon response: {json_body}"))?;
    if v["status"].as_bool() != Some(true) {
        anyhow::bail!("daemon refused: {}", v["error"].as_str().unwrap_or(json_body));
    }
    println!("queued {} at Force priority", v["nzo_ids"][0].as_str().unwrap_or("?"));
    let m3u = v["m3u"].as_str().unwrap_or_default().to_string();
    println!("  player link: {m3u}");
    println!("  raw stream:  {}", v["stream"].as_str().unwrap_or(""));
    if !no_open && !m3u.is_empty() {
        #[cfg(target_os = "macos")]
        let opened = std::process::Command::new("open").arg(&m3u).status();
        // Windows: explorer, NOT `cmd /C start` - cmd re-parses its command
        // line, so metacharacters (&, ^, %) in the string would execute. This
        // string is the daemon's `m3u` field, read over plaintext HTTP from a
        // possibly-remote `--host`, so an on-path attacker answering
        // {"m3u":"http://h/x&calc.exe"} got arbitrary execution. Same rule the
        // daemon's own os_open already follows for exactly this reason.
        #[cfg(target_os = "windows")]
        let opened = std::process::Command::new("explorer").arg(&m3u).status();
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let opened = std::process::Command::new("xdg-open").arg(&m3u).status();
        match opened {
            Ok(st) if st.success() => println!("  handed to the default player"),
            _ => println!("  (couldn't launch a player - open the link above manually)"),
        }
    }
    Ok(())
}

fn inspect(path: &PathBuf) -> Result<()> {
    let xml = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let nzb = Nzb::parse(&xml).context("parsing NZB")?;

    println!("{:<7} {:>10} {:>5}  {}", "kind", "bytes", "segs", "file");
    for f in &nzb.files {
        let kind = match f.kind() {
            FileKind::Data => "data",
            FileKind::Par2Main => "par2",
            FileKind::Par2Volume => "par2vol",
        };
        println!(
            "{:<7} {:>10} {:>5}  {}",
            kind,
            f.bytes(),
            f.segments.len(),
            f.filename_hint().unwrap_or(&f.subject),
        );
    }

    let total = nzb.total_bytes();
    let eager = nzb.eager_bytes();
    println!(
        "\n{} files, {:.1} MB total; eager set {:.1} MB ({:.1}% saved by deferring PAR2 volumes)",
        nzb.files.len(),
        total as f64 / 1e6,
        eager as f64 / 1e6,
        (total - eager) as f64 * 100.0 / total.max(1) as f64,
    );
    Ok(())
}

#[cfg(test)]
mod scan_pass_tests {
    use super::*;
    use std::time::Duration;

    fn tmp_index(tag: &str) -> (PathBuf, nzbkit::index::Index) {
        let dir = std::env::temp_dir().join(format!("nzbfast-scanpass-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = nzbkit::index::Index::open(&dir.join("index.db")).unwrap();
        (dir, ix)
    }

    /// BUG (HIGH): one wedged scan worker froze ALL indexing for the
    /// process lifetime. Each worker held a clone of the result sender and
    /// the collector was a bare `while let Some(..) = rx.recv().await`, so
    /// a worker that never reached its exit path never dropped its sender,
    /// `recv()` never returned None, `scan_article_range` and
    /// `index_scan_into` never returned, and the caller's scan JoinSet
    /// blocked forever - no further pass for ANY group until restart.
    ///
    /// The collector is now bounded: a stall abandons the pass.
    #[tokio::test]
    async fn a_wedged_worker_cannot_freeze_the_scan_collector() {
        let (dir, mut ix) = tmp_index("wedged");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // One chunk lands, then a worker wedges holding its sender.
        let wedged = tx.clone();
        tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        drop(tx);

        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                999,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("the collector must not block on a sender that never drops")
        .unwrap();

        assert!(!pass.complete, "an abandoned pass must not report complete");
        assert_eq!(pass.scanned, 100);
        // CRITICAL: the contiguous prefix stops where coverage really
        // ends. Advancing it to g_high would write the missing 200..999
        // off as scanned forever.
        assert_eq!(ix.high_water("alt.test", "srv1"), 199);
        drop(wedged);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The control: a healthy pass must still report complete, so the
    /// caller's `set_low_water` (the deepen leg) keeps running.
    #[tokio::test]
    async fn a_healthy_pass_reports_complete_and_advances_the_prefix() {
        let (dir, mut ix) = tmp_index("healthy");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // Out-of-order arrival: the prefix must still reach 299.
        tx.send(Ok((200, 299, Vec::new()))).await.unwrap();
        tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        drop(tx);

        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                299,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("a healthy pass must not hit the idle deadline")
        .unwrap();

        assert!(pass.complete);
        assert_eq!(pass.scanned, 200);
        assert_eq!(ix.high_water("alt.test", "srv1"), 299);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A HOLE in the middle must not let the mark jump the gap, abandoned
    /// or not: the prefix stops at the hole and the pass is incomplete.
    #[tokio::test]
    async fn an_abandoned_pass_never_marks_over_a_hole() {
        let (dir, mut ix) = tmp_index("hole");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let wedged = tx.clone();
        tx.send(Ok((100, 199, Vec::new()))).await.unwrap();
        // 200..299 never arrives; 300..399 does.
        tx.send(Ok((300, 399, Vec::new()))).await.unwrap();
        drop(tx);

        let pass = tokio::time::timeout(
            Duration::from_secs(10),
            collect_scan_pass(
                &mut rx,
                &mut ix,
                "alt.test",
                "srv1",
                100,
                399,
                0,
                Some(0),
                None,
                0,
                100,
                Instant::now(),
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("the collector must not block")
        .unwrap();

        assert!(!pass.complete);
        assert_eq!(
            ix.high_water("alt.test", "srv1"),
            199,
            "the mark must stop at the hole, not follow the last chunk in"
        );
        drop(wedged);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod multi_server_selection {
    use super::*;

    fn cfg(servers: serde_json::Value) -> Config {
        serde_json::from_value(serde_json::json!({ "servers": servers })).unwrap()
    }

    /// A8: header scanning never spends block credit, never reads the
    /// same backbone twice (mirrors share a spool), and ranks
    /// level-then-config-order.
    #[test]
    fn scan_servers_skip_blocks_and_dedupe_backbones() {
        let c = cfg(serde_json::json!([
            { "host": "news.eweka.nl" },
            // Same backbone (omicron reseller): contributes nothing.
            { "host": "news.newshosting.com" },
            // Prepaid block: OVER would burn rescue credit.
            { "host": "news.blocknews.net", "block_bytes": 5_000_000_000u64 },
            // Fill server, flatrate, own backbone: eligible, ranked after
            // the level-0 entries.
            { "host": "news.xsnews.nl", "level": 1 },
            { "host": "news.usenetexpress.com", "enabled": false },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.eweka.nl", "news.xsnews.nl"]);
    }

    /// The explicit mirror `group` field outranks hostname clustering:
    /// two hosts the alias map would call separate backbones are one
    /// spool when the user says so.
    #[test]
    fn scan_servers_honour_the_mirror_group_field() {
        let c = cfg(serde_json::json!([
            { "host": "news.eweka.nl", "group": "main" },
            { "host": "news.xsnews.nl", "group": "main" },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.eweka.nl"]);
    }

    /// An all-block config still gets an index: the user configured
    /// indexing, and "no index at all" is worse than spending credit.
    #[test]
    fn scan_servers_fall_back_to_blocks_when_nothing_else_exists() {
        let c = cfg(serde_json::json!([
            { "host": "news.blocknews.net", "block_bytes": 5_000_000_000u64 },
            { "host": "news.abavia.com", "enabled": false },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.blocknews.net"]);
    }
}

#[cfg(test)]
mod main_tests {
    /// BUG (MEDIUM): a full disk, a permission error or a bad sector used
    /// to bail with a message that OPENED "download incomplete: 0 file(s)
    /// with missing segments" - which the daemon read as a dead post
    /// (reporting a healthy release to the indexer) and as transient
    /// (arming an automatic retry straight back onto the same full disk).
    /// The leading clause now says which of the two it was.
    #[test]
    fn a_local_write_fault_does_not_claim_missing_segments() {
        let missing = super::incomplete_reason(3, 0);
        assert!(missing.starts_with("download incomplete"));
        assert!(missing.contains("3 file(s) with missing segments"));

        // Both happened: still the post's problem, and both counts show.
        let both = super::incomplete_reason(2, 5);
        assert!(both.starts_with("download incomplete"));
        assert!(both.contains("5 decode/write errors"));

        // Nothing missing: the articles all arrived, so this is ours.
        let local = super::incomplete_reason(0, 5);
        assert!(!local.starts_with("download incomplete"), "{local}");
        assert!(local.contains("5 decode/write error"));
        assert!(local.contains("no missing segments"));
    }
}

//! `nzbfast post` - upload files as yEnc articles to a test group and
//! emit the matching NZB (ops tool; runbook: bench/nested-corpus/POSTING.md).
//!
//! Server selection is explicit and mandatory: `--post-server` must name
//! exactly one configured server (host, or host:port when two entries
//! share a host). There is deliberately NO default - posting never picks
//! "the first server" on its own.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use nzbkit::config::{Config, ServerConfig};
use nzbkit::post::{self, PostOpts};

pub struct PostArgs {
    pub paths: Vec<PathBuf>,
    pub post_server: String,
    pub nzb: PathBuf,
    pub group: String,
    pub from: String,
    pub msgid_domain: String,
    pub article_size: usize,
    pub title: Option<String>,
    pub connections: usize,
    pub verify: bool,
}

/// Resolve `--post-server` against the config: exact host match
/// (case-insensitive), or `host:port` when one host has several entries.
/// Anything but exactly one enabled match is a hard error.
fn select_server(cfg: &Config, wanted: &str) -> Result<ServerConfig> {
    let want = wanted.trim().to_ascii_lowercase();
    let matches: Vec<&ServerConfig> = cfg
        .servers
        .iter()
        .filter(|s| {
            s.host.to_ascii_lowercase() == want
                || format!("{}:{}", s.host.to_ascii_lowercase(), s.port) == want
        })
        .collect();
    let hosts = || {
        cfg.servers
            .iter()
            .map(|s| format!("  {}:{}{}", s.host, s.port, if s.enabled { "" } else { " (disabled)" }))
            .collect::<Vec<_>>()
            .join("\n")
    };
    match matches.as_slice() {
        [] => anyhow::bail!(
            "--post-server {wanted:?} matches no configured server. Configured servers:\n{}",
            hosts()
        ),
        [one] => {
            anyhow::ensure!(
                one.enabled,
                "--post-server {wanted:?} is disabled in the config - enable it explicitly before posting"
            );
            Ok((*one).clone())
        }
        many => anyhow::bail!(
            "--post-server {wanted:?} matches {} server entries - disambiguate with host:port. Configured servers:\n{}",
            many.len(),
            hosts()
        ),
    }
}

pub async fn run(config: &PathBuf, args: PostArgs) -> Result<()> {
    anyhow::ensure!(
        !args.post_server.trim().is_empty(),
        "--post-server is required: name the ONE configured server to post through"
    );
    let cfg = Config::load(config)?;
    let server = select_server(&cfg, &args.post_server)?;

    let plan = post::plan(&args.paths, args.article_size)
        .map_err(|e| anyhow::anyhow!("planning post: {e}"))?;
    let total_bytes: u64 = plan.iter().map(|f| f.size).sum();
    let total_articles: u64 = plan.iter().map(|f| f.parts as u64).sum();

    // Validate the NZB destination BEFORE posting. Every article is uploaded
    // with a fresh RANDOM Message-ID whose only retrieval index is this NZB,
    // so a write that fails AFTER the upload orphans the whole post. Reject a
    // directory or a missing parent now, prove writability with a temp file
    // in the destination directory, and post into that temp - the real
    // destination is only (atomically) replaced once every upload succeeds,
    // so an existing NZB is never truncated on a failed run.
    if args.nzb.is_dir() {
        anyhow::bail!("--nzb {} is a directory, not a file", args.nzb.display());
    }
    let nzb_dir = match args.nzb.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !nzb_dir.is_dir() {
        anyhow::bail!(
            "--nzb parent directory {} does not exist",
            nzb_dir.display()
        );
    }
    let nzb_tmp = {
        let mut t = args.nzb.clone().into_os_string();
        t.push(".nzbtmp");
        PathBuf::from(t)
    };
    // Write-probe: prove the destination is writable before a single byte is
    // uploaded. A NON-EMPTY temp already sitting there is the rescue index of
    // an earlier run - one that uploaded fine but failed to publish, or one
    // that aborted partway with articles already accepted. Either way those
    // articles are on the server under randomly generated Message-IDs, and
    // that file is the only record of them. Truncating it here (File::create
    // truncates) would strand them permanently, so refuse instead.
    if std::fs::metadata(&nzb_tmp).is_ok_and(|m| m.len() > 0) {
        anyhow::bail!(
            "{} already holds the retrieval index of a previous upload that \
             did not publish - rename it to {} (or move it aside) before \
             posting again",
            nzb_tmp.display(),
            args.nzb.display()
        );
    }
    std::fs::File::create(&nzb_tmp)
        .with_context(|| format!("cannot write NZB next to {}", args.nzb.display()))?;

    // The confirmation block: exactly which server, and what will happen.
    println!(
        "[post] server: {}:{} ({}{})",
        server.host,
        server.port,
        if server.tls { "TLS" } else { "plain" },
        if server.username.is_some() { ", authenticated" } else { "" }
    );
    println!(
        "[post] posting {} files ({:.1} MB, {} articles of ≤{} KB) to {} as {}",
        plan.len(),
        total_bytes as f64 / 1e6,
        total_articles,
        args.article_size / 1000,
        args.group,
        args.from
    );
    println!("[post] message-id domain: {} · nzb: {}", args.msgid_domain, args.nzb.display());

    let opts = PostOpts {
        group: args.group.clone(),
        from: args.from.clone(),
        msgid_domain: args.msgid_domain.clone(),
        article_size: args.article_size,
        title: args.title.clone(),
        connections: args.connections,
    };
    let t0 = std::time::Instant::now();
    let progress: post::Progress = Arc::new(move |done, total, sent| {
        if done == total || done % 25 == 0 {
            println!(
                "[post] {done}/{total} articles · {:.1} MB on the wire",
                sent as f64 / 1e6
            );
        }
    });
    let set = match post::post_files(&server, &plan, &opts, Some(progress)).await {
        Ok(set) => set,
        // The upload stopped partway. Whatever the server already accepted
        // is PUBLIC, under random Message-IDs that exist in exactly one
        // place: this index. Persist it before reporting the failure -
        // dropping it leaves the operator with articles on their account
        // they can neither fetch, reference, nor ask an indexer to remove.
        Err(post::PostError::Aborted { message, posted }) => {
            let n: usize = posted.files.iter().map(|f| f.segments.len()).sum();
            let rescue = post::emit_nzb(&posted);
            println!(
                "[post] ABORTED - {n} articles were accepted or duplicate-reported by the server."
            );
            match std::fs::write(&nzb_tmp, &rescue) {
                Ok(()) => {
                    println!(
                        "[post] their Message-IDs are in {} - rename it to {} to use it, \
                         or delete it once you no longer need the record.",
                        nzb_tmp.display(),
                        args.nzb.display()
                    );
                    anyhow::bail!(
                        "posting failed: {message} ({n} articles are posted or may be posted; \
                         their retrieval index is at {})",
                        nzb_tmp.display()
                    );
                }
                // Last resort: the index cannot be written, so put it where
                // the operator can still copy it out of the terminal.
                Err(e) => {
                    println!(
                        "[post] cannot write {} ({e}) - printing the retrieval index instead:",
                        nzb_tmp.display()
                    );
                    println!("{rescue}");
                    anyhow::bail!(
                        "posting failed: {message} ({n} articles are posted or may be posted; \
                         their retrieval index could not be saved and was printed above)"
                    );
                }
            }
        }
        Err(e) => anyhow::bail!("posting failed: {e}"),
    };
    println!(
        "[post] upload complete in {:.1}s",
        t0.elapsed().as_secs_f64()
    );

    let xml = post::emit_nzb(&set);
    // Publish atomically: write the index into the pre-reserved temp, then
    // rename it over the destination. If the rename fails, the temp still
    // holds the full retrieval index for the just-completed upload.
    std::fs::write(&nzb_tmp, &xml)
        .with_context(|| format!("writing {}", nzb_tmp.display()))?;
    std::fs::rename(&nzb_tmp, &args.nzb).with_context(|| {
        format!(
            "publishing NZB to {} (index preserved at {})",
            args.nzb.display(),
            nzb_tmp.display()
        )
    })?;
    println!("[post] wrote {}", args.nzb.display());

    if args.verify {
        verify(&server, &args, &plan).await?;
    }
    Ok(())
}

/// Round-trip proof: parse the NZB we just wrote, download every segment
/// back through the engine's connection pool from the SAME server, decode
/// and reassemble to temp files, then compare SHA-256 against the sources.
async fn verify(
    server: &ServerConfig,
    args: &PostArgs,
    plan: &[nzbkit::post::PlanFile],
) -> Result<()> {
    use nzbkit::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all_multi};

    println!("[verify] re-downloading the post from {} …", server.host);
    // Freshly posted articles can take a moment to become retrievable
    // even on the posting server.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let xml = std::fs::read(&args.nzb)?;
    let nzb = nzbkit::nzb::Nzb::parse(&xml).context("parsing the emitted NZB")?;

    let by_name: std::collections::HashMap<&str, &nzbkit::post::PlanFile> =
        plan.iter().map(|f| (f.name.as_str(), f)).collect();

    // message-id → (per-file temp handle). Preallocate one temp file per
    // posted file, next to the NZB so cleanup is obvious on failure.
    let tmp_dir = args.nzb.with_extension("verify.tmp");
    std::fs::create_dir_all(&tmp_dir)?;
    let mut files: Vec<(String, PathBuf, std::fs::File, u64)> = Vec::new(); // (name, src, tmp, size)
    let mut id_to_file: std::collections::HashMap<String, usize> = Default::default();
    let mut reqs: Vec<ArticleReq> = Vec::new();
    for f in &nzb.files {
        let name = f
            .filename_hint()
            .ok_or_else(|| anyhow::anyhow!("NZB subject carries no filename: {}", f.subject))?;
        let src = by_name
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("NZB names {name:?} which was not in the plan"))?;
        let tmp_path = tmp_dir.join(name);
        let tmp = std::fs::File::create(&tmp_path)?;
        tmp.set_len(src.size)?;
        let idx = files.len();
        files.push((name.to_string(), src.path.clone(), tmp, src.size));
        for seg in &f.segments {
            let bracketed = format!("<{}>", seg.message_id);
            id_to_file.insert(bracketed.clone(), idx);
            reqs.push(ArticleReq::fresh(bracketed));
        }
    }
    let total = reqs.len();

    let pool_cfg = PoolConfig {
        connections: args.connections.clamp(1, 16),
        window: 4,
        ..PoolConfig::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FetchOutcome>(64);
    let servers = vec![(server.clone(), pool_cfg)];
    let fetcher = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });

    let mut got = 0usize;
    let mut problems: Vec<String> = Vec::new();
    while let Some(outcome) = rx.recv().await {
        match outcome {
            FetchOutcome::Done { id, raw } => {
                let Some(&idx) = id_to_file.get(&id) else { continue };
                match nzbkit::yenc::decode(&raw) {
                    Ok(dec) => {
                        nzbkit::disk::write_all_at(&files[idx].2, &dec.data, dec.offset())?;
                        got += 1;
                    }
                    Err(e) => problems.push(format!("{id}: decode: {e}")),
                }
            }
            FetchOutcome::Missing { id } => problems.push(format!("{id}: missing (430)")),
            FetchOutcome::Failed { id, error } => problems.push(format!("{id}: {error}")),
        }
    }
    let _ = fetcher.await;
    println!("[verify] fetched {got}/{total} articles");

    let mut failed = !problems.is_empty();
    for p in &problems {
        println!("[verify] problem: {p}");
    }
    for (name, src, tmp, _) in files {
        drop(tmp); // close the write handle before hashing
        let want = nzbkit::post::sha256_file(&src)?;
        let have = nzbkit::post::sha256_file(&tmp_dir.join(&name))?;
        let ok = want == have;
        failed |= !ok;
        println!(
            "[verify] {name}: {}",
            if ok { format!("OK sha256={want}") } else { format!("MISMATCH source={want} downloaded={have}") }
        );
    }
    if failed {
        anyhow::bail!(
            "verification FAILED - temp downloads kept in {} for inspection",
            tmp_dir.display()
        );
    }
    std::fs::remove_dir_all(&tmp_dir)?;
    println!("[verify] all files match - round trip proven");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(servers: Vec<ServerConfig>) -> Config {
        // Config has no public constructor shortcut; round-trip via JSON.
        let json = serde_json::json!({
            "servers": servers,
        });
        serde_json::from_value(json).unwrap()
    }

    fn srv(host: &str, port: u16, enabled: bool) -> ServerConfig {
        ServerConfig {
            host: host.into(),
            port,
            tls: false,
            username: None,
            password: None,
            connections: 4,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            bind_ip: None,
            socks5: None,
            enabled,
            warm_pool: false,
        }
    }

    #[test]
    fn server_selection_is_strict() {
        let c = cfg(vec![
            srv("news.alpha.example", 563, true),
            srv("news.beta.example", 563, true),
            srv("news.beta.example", 119, true),
            srv("news.off.example", 563, false),
        ]);
        // Exact single host match, case-insensitive.
        assert_eq!(select_server(&c, "News.Alpha.Example").unwrap().host, "news.alpha.example");
        // No match: hard error listing candidates.
        let e = select_server(&c, "news.nope.example").unwrap_err().to_string();
        assert!(e.contains("matches no configured server"), "{e}");
        assert!(e.contains("news.alpha.example:563"), "{e}");
        // Ambiguous host: must disambiguate with host:port.
        let e = select_server(&c, "news.beta.example").unwrap_err().to_string();
        assert!(e.contains("disambiguate"), "{e}");
        assert_eq!(select_server(&c, "news.beta.example:119").unwrap().port, 119);
        // Disabled server: refused even when named explicitly.
        let e = select_server(&c, "news.off.example").unwrap_err().to_string();
        assert!(e.contains("disabled"), "{e}");
    }

    /// The whole CLI path against the mock server: run() with --verify
    /// posts real files, writes a parseable NZB, re-downloads through the
    /// pool and passes the hash comparison.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_posts_and_verifies_against_the_mock() {
        let srv = nzbkit::mock::MockServer::start(
            Default::default(),
            nzbkit::mock::Chaos::default(),
        )
        .await;
        let dir = std::env::temp_dir().join(format!("nzbfast-postcmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..250_000).map(|i| (i * 31 + i / 255) as u8).collect();
        std::fs::write(dir.join("corpus-a.bin"), &data).unwrap();
        std::fs::write(dir.join("corpus-b.bin"), &data[..70_000]).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                srv.addr.port()
            ),
        )
        .unwrap();

        let nzb_path = dir.join("posted.nzb");
        run(
            &config_path,
            PostArgs {
                paths: vec![dir.join("corpus-a.bin"), dir.join("corpus-b.bin")],
                post_server: format!("127.0.0.1:{}", srv.addr.port()),
                nzb: nzb_path.clone(),
                group: "alt.binaries.test".into(),
                from: "corpus@nzbfast.com".into(),
                msgid_domain: "corpus.nzbfast.com".into(),
                article_size: 100_000,
                title: Some("post cmd e2e".into()),
                connections: 3,
                verify: true,
            },
        )
        .await
        .expect("post + verify");

        let nzb = nzbkit::nzb::Nzb::parse(&std::fs::read(&nzb_path).unwrap()).unwrap();
        assert_eq!(nzb.files.len(), 2);
        assert_eq!(nzb.files.iter().map(|f| f.segments.len()).sum::<usize>(), 4);
        // Verify's temp dir is cleaned up on success.
        assert!(!nzb_path.with_extension("verify.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An upload that aborts partway has already made articles public. The
    /// run must fail, and it must leave their Message-IDs on disk - that
    /// index is the operator's only handle on what they just posted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_aborted_post_leaves_the_message_ids_that_already_landed() {
        let srv = nzbkit::mock::MockServer::start(
            Default::default(),
            nzbkit::mock::Chaos {
                post: nzbkit::mock::PostChaos {
                    reject_441: Some("posting failed".into()),
                    reject_after: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let dir = std::env::temp_dir().join(format!("nzbfast-postabort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..5_000).map(|i| (i * 31 + i / 255) as u8).collect();
        std::fs::write(dir.join("corpus.bin"), &data).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                srv.addr.port()
            ),
        )
        .unwrap();
        let nzb_path = dir.join("posted.nzb");
        let args = || PostArgs {
            paths: vec![dir.join("corpus.bin")],
            post_server: format!("127.0.0.1:{}", srv.addr.port()),
            nzb: nzb_path.clone(),
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.com".into(),
            msgid_domain: "corpus.nzbfast.com".into(),
            article_size: 1_000,
            title: None,
            connections: 1,
            verify: false,
        };

        let err = run(&config_path, args()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("2 articles are posted or may be posted"), "{msg}");

        // The rescue index is a real NZB listing exactly what landed.
        let tmp = PathBuf::from(format!("{}.nzbtmp", nzb_path.display()));
        let rescue = nzbkit::nzb::Nzb::parse(&std::fs::read(&tmp).unwrap())
            .expect("the rescue index parses as an NZB");
        assert_eq!(
            rescue.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            2
        );
        // The real NZB was never written - a failed post publishes nothing.
        assert!(!nzb_path.exists());

        // And a second run refuses rather than truncating that record.
        let err = run(&config_path, args()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("already holds the retrieval index"),
            "{err:#}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

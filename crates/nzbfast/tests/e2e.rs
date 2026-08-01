//! End-to-end chaos suite (design: M4): the real `nzbfast` binary against
//! in-process mock NNTP servers, exercising the full pipeline - pipelined
//! pool, cross-server routing, live PAR2 verification, exact-fit repair,
//! store-mode direct extraction - under injected failures.
//!
//! PAR2 sets are created with the local `par2` binary (par2cmdline);
//! tests needing repair skip gracefully when it's absent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use nzbkit::rar::fixtures;

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed).wrapping_add((i >> 9) as u8))
        .collect()
}

struct Fixture {
    dir: PathBuf,
    articles: HashMap<String, Vec<u8>>,
    /// (filename, segments (id, bytes, number))
    nzb_files: Vec<(String, Vec<(String, u64, u32)>)>,
    /// Unix timestamp written to every `<file date>` (0 = undated,
    /// which the client treats as fresh). Retention tests backdate it.
    date: i64,
}

impl Fixture {
    fn new(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("nzbfast-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Fixture {
            dir,
            articles: HashMap::new(),
            nzb_files: Vec::new(),
            date: 0,
        }
    }

    /// Add a file to the release: written to disk (for par2 create) and
    /// split into yEnc articles.
    fn add_file(&mut self, name: &str, data: &[u8], art_size: usize) {
        std::fs::write(self.dir.join(name), data).unwrap();
        let tag = format!("{}-{}", name.replace('.', "_"), self.nzb_files.len());
        let segs = make_file_articles(name, data, art_size, &tag, &mut self.articles);
        self.nzb_files.push((name.to_string(), segs));
    }

    /// `add_file` with the NZB subject decoupled from the yEnc-declared
    /// name (the obfuscated norm: garbage subjects, real yEnc names).
    /// The data lands on disk under the REAL name, so `add_par2` covers
    /// the names the poster's PAR2 set would.
    fn add_file_obfuscated(&mut self, subject: &str, yenc_name: &str, data: &[u8], art_size: usize) {
        std::fs::write(self.dir.join(yenc_name), data).unwrap();
        let tag = format!("{}-{}", subject.replace('.', "_"), self.nzb_files.len());
        let segs = make_file_articles(yenc_name, data, art_size, &tag, &mut self.articles);
        self.nzb_files.push((subject.to_string(), segs));
    }

    /// Run `par2 create` over the named files and add the resulting .par2
    /// outputs as articles too. Returns false if par2 isn't available.
    fn add_par2(&mut self, redundancy: u32, files: &[&str], art_size: usize) -> bool {
        self.add_par2_opts(redundancy, None, files, art_size)
    }

    /// add_par2 with an explicit PAR2 block size (memory-budget tests use
    /// blocks far larger than articles to force partial-buffer pressure).
    fn add_par2_opts(
        &mut self,
        redundancy: u32,
        block_size: Option<u64>,
        files: &[&str],
        art_size: usize,
    ) -> bool {
        let mut cmd = Command::new("par2");
        cmd.arg("create");
        if let Some(bs) = block_size {
            cmd.arg(format!("-s{bs}"));
        }
        let st = cmd
            .arg(format!("-r{redundancy}"))
            .arg("-q")
            .arg("testset")
            .args(files)
            .current_dir(&self.dir)
            .status();
        match st {
            Ok(s) if s.success() => {}
            _ => return false,
        }
        let mut par2s: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                (p.extension().is_some_and(|x| x == "par2")).then_some(p)
            })
            .collect();
        par2s.sort();
        for p in par2s {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let data = std::fs::read(&p).unwrap();
            let tag = format!("{}-{}", name.replace('.', "_"), self.nzb_files.len());
            let segs = make_file_articles(&name, &data, art_size, &tag, &mut self.articles);
            self.nzb_files.push((name, segs));
            std::fs::remove_file(&p).unwrap();
        }
        true
    }

    /// `add_par2`, but the recovery set is posted the way an obfuscated
    /// poster posts it: hash subjects AND hash yEnc names, so nothing
    /// reaching the client - NZB subject or on-disk filename - carries a
    /// `.par2` anywhere. Issue #9's shape exactly.
    fn add_par2_obfuscated(&mut self, redundancy: u32, files: &[&str], art_size: usize) -> bool {
        let st = Command::new("par2")
            .arg("create")
            .arg(format!("-r{redundancy}"))
            .arg("-q")
            .arg("testset")
            .args(files)
            .current_dir(&self.dir)
            .status();
        match st {
            Ok(s) if s.success() => {}
            _ => return false,
        }
        let mut par2s: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                (p.extension().is_some_and(|x| x == "par2")).then_some(p)
            })
            .collect();
        par2s.sort();
        for (i, p) in par2s.iter().enumerate() {
            let data = std::fs::read(p).unwrap();
            let hash = format!("Qk7{i:02}zXm9rTb");
            let tag = format!("obf-par2-{i}");
            let segs = make_file_articles(&hash, &data, art_size, &tag, &mut self.articles);
            self.nzb_files.push((hash, segs));
            std::fs::remove_file(p).unwrap();
        }
        true
    }

    fn write_nzb(&self) -> PathBuf {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (name, segs) in &self.nzb_files {
            xml.push_str(&format!(
                "  <file poster=\"e2e@test\" date=\"{}\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>mock.group</group></groups>\n    <segments>\n",
                self.date,
                segs.len()
            ));
            for (id, bytes, num) in segs {
                xml.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        let path = self.dir.join("test.nzb");
        std::fs::write(&path, xml).unwrap();
        path
    }

    fn write_config(&self, servers: &[&MockServer]) -> PathBuf {
        let with_retention: Vec<(&MockServer, u32)> = servers.iter().map(|&s| (s, 0)).collect();
        self.write_config_retention(&with_retention)
    }

    /// Config with per-server `retention_days` (0 = unlimited).
    fn write_config_retention(&self, servers: &[(&MockServer, u32)]) -> PathBuf {
        let entries: Vec<String> = servers
            .iter()
            .map(|(s, days)| {
                format!(
                    "{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"retention_days\":{days}}}",
                    s.addr.ip(),
                    s.addr.port()
                )
            })
            .collect();
        let path = self.dir.join("config.json");
        std::fs::write(&path, format!("{{\"servers\":[{}]}}", entries.join(","))).unwrap();
        path
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    // CI installs par2 on purpose (see pr-check.yml, both legs), so there a
    // missing one is a broken job, not a reason to quietly cover less. Every
    // caller of this SKIPS when it is false, which is exactly the shape that
    // reads as a green run with silently reduced coverage - the failure mode
    // this whole Windows pass kept turning up.
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - the PAR2 tests \
         would have skipped and the run would have looked green"
    );
    ok
}

/// Run `nzbfast get` and return (stdout+stderr, success).
fn run_get(config: &Path, nzb: &Path, out: &Path, extra_env: &[(&str, &str)]) -> (String, bool) {
    run_get_args(config, nzb, out, extra_env, &[])
}

fn run_get_args(
    config: &Path,
    nzb: &Path,
    out: &Path,
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
) -> (String, bool) {
    run_get_win(config, nzb, out, extra_env, extra_args, 3)
}

fn run_get_win(
    config: &Path,
    nzb: &Path,
    out: &Path,
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
    window: u32,
) -> (String, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    // The daemon mints an API key on a genuinely first run (see
    // serve::first_run_apikey). These suites drive it keyless on purpose,
    // so they take the same deliberate opt-out an operator would.
    cmd.env("NZBFAST_OPEN", "1");
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.arg("--config")
        .arg(config)
        .arg("get")
        .arg(nzb)
        .arg("--out")
        .arg(out)
        .arg("--connections")
        .arg("4")
        .arg("--window")
        .arg(window.to_string())
        .arg("--decoders")
        .arg("4");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run nzbfast");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (text, out.status.success())
}

/// A store-mode 3-volume RAR release of one inner file + par2 over the
/// volumes. Returns (fixture, inner file bytes, volume names).
fn rar_release(tag: &str, with_par2: bool) -> (Fixture, Vec<u8>, Vec<String>) {
    let mut fx = Fixture::new(tag);
    // WinRAR-true geometry: volume 0 (no volume-number field in its main
    // header) carries one byte more data than volume 1.
    let inner = payload(900_000, 7);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[..350_001], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 900_000, &inner[350_001..700_001], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[700_001..], true, false)], 2),
    ];
    let names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    if with_par2 {
        assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    }
    (fx, inner, names.iter().map(|s| s.to_string()).collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_store_rar_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, inner, vol_names) = rar_release("clean", true);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    let extracted = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(extracted, inner, "extracted bytes differ");
    for v in &vol_names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// SPEC-onepass-obfuscated-store-sets Part A, acceptance 5: a uniform
/// single-file store set whose volume names are dotless hash garbage and
/// whose NZB file order is unrelated to volume order (the obfuscated-
/// remux norm - the live 143-volume case arrived effectively randomly).
/// Volume 0 is LAST in the NZB, so chain resolution can close nothing
/// until the end; under a tight --mem-limit the whole set used to demote
/// with "held-bytes cap" and unpack post-download. The arithmetic gate
/// places every volume off its own headers: one-pass, ~1x payload disk.
#[tokio::test(flavor = "multi_thread")]
async fn obfuscated_uniform_store_set_one_pass_shuffled_order() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("arith-obf");
    // WinRAR-true geometry: constant volume size, so volume 0 (no
    // volume-number field in its main header) carries one byte more
    // data than the rest - the arithmetic gate validates exactly this.
    let dl = 500_000usize;
    let n_full = 99usize;
    let inner = payload((dl + 1) + (n_full - 1) * dl + 300_000, 47);
    let total = inner.len() as u64;
    let mut pos = 0usize;
    let mut vols: Vec<Vec<u8>> = (0..n_full)
        .map(|k| {
            let len = if k == 0 { dl + 1 } else { dl };
            let piece = &inner[pos..pos + len];
            pos += len;
            fixtures::rar5_volume_n_crc(
                &[("bTqmovie9m9z.mkv", total, piece, k > 0, true, Some(crc32fast::hash(piece)))],
                k as u64,
            )
        })
        .collect();
    vols.push(fixtures::rar5_volume_n_crc(
        &[(
            "bTqmovie9m9z.mkv",
            total,
            &inner[pos..],
            true,
            false,
            Some(crc32fast::hash(&inner)),
        )],
        n_full as u64,
    ));
    let names: Vec<String> = (0..vols.len())
        .map(|k| format!("{:06x}fDakqqryd{k}", (k as u64 * 2654435761) & 0xffffff))
        .collect();
    // NZB order: seeded shuffle with volume 0 forced last.
    let mut order: Vec<usize> = (0..vols.len()).collect();
    let mut state = 0xDECAFu64;
    for i in (1..order.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        order.swap(i, (state >> 33) as usize % (i + 1));
    }
    let z = order.iter().position(|&v| v == 0).unwrap();
    let last = order.len() - 1;
    order.swap(z, last);
    for &vi in &order {
        fx.add_file(&names[vi], &vols[vi], 60_000);
    }
    let par2_names: Vec<&str> = order.iter().map(|&vi| names[vi].as_str()).collect();
    assert!(fx.add_par2(10, &par2_names, 60_000), "par2 create failed");
    // Synthesized segment numbering, the fully-obfuscated norm: the NZB
    // lists each volume's segments in a scrambled order with sequential
    // numbers slapped on, so "segment 1" is NOT the offset-0 article and
    // the head prefetch (M3) cannot parse any volume's headers early -
    // each volume classifies only when its true offset-0 article arrives
    // in natural order, exactly like the live 143-volume case.
    for (fi, (name, segs)) in fx.nzb_files.iter_mut().enumerate() {
        if name.ends_with(".par2") {
            continue;
        }
        let mut st = 0xBADC0DEu64 ^ (fi as u64) << 7;
        for i in (1..segs.len()).rev() {
            st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
            segs.swap(i, (st >> 33) as usize % (i + 1));
        }
        for (i, seg) in segs.iter_mut().enumerate() {
            seg.2 = i as u32 + 1;
        }
    }
    // A server that delivers at a plausible pace, not memcpy speed: the
    // decoders then keep up with arrivals, so pre-fix the unplaceable
    // spans really do pile up against the holds cap the way the live
    // 143-volume case did (at loopback speed the whole backlog drains
    // after volume 0's headers parse and nothing ever holds).
    let chaos = Chaos { delay_ms: 10, ..Default::default() };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "32M"])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(log.contains("one-pass"), "shape must say one-pass:\n{log}");
    assert!(!log.contains("partly on disk"), "set demoted:\n{log}");
    assert!(!log.contains("held-bytes cap"), "the pre-fix failure is back:\n{log}");
    let extracted = std::fs::read(fx.dir.join("out/bTqmovie9m9z.mkv")).expect("extracted file");
    assert_eq!(extracted, inner, "extracted bytes differ");
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} must not touch disk"
        );
    }
}

/// Holds paging through the REAL `get` path: a split set whose big
/// MIDDLE volume downloads first cannot resolve any base until the head
/// volume's headers arrive - and the head's segment numbering is fully
/// scrambled, so its offset-0 sniff comes late (the rotation probe has
/// nothing to guess at on a true shuffle). The middle volume's window
/// exceeds the holds cap (--mem-limit 64M -> 28.8 MB), which used to
/// demote the whole set with "held-bytes cap"; now it pages to scratch
/// (the daemon-wired ceiling), the set extracts ONE-PASS, and the
/// scratch is gone at the end.
#[tokio::test(flavor = "multi_thread")]
async fn holds_over_the_cap_page_to_scratch_and_stay_one_pass() {
    let mut fx = Fixture::new("holds-page");
    let total_len = 6_000_000 + 36_000_000 + 5_000_000;
    let film = payload(total_len, 83);
    let vols = [
        fixtures::rar5_volume_n(
            &[("bigfilm.mkv", total_len as u64, &film[..6_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "bigfilm.mkv",
                total_len as u64,
                &film[6_000_000..42_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("bigfilm.mkv", total_len as u64, &film[42_000_000..], true, false)],
            2,
        ),
    ];
    // NZB order: the 36 MB middle volume FIRST, the anchors after - the
    // middle bytes are all landed before anything can place them.
    fx.add_file("x.part2.rar", &vols[1], 60_000);
    fx.add_file("x.part3.rar", &vols[2], 60_000);
    fx.add_file("x.part1.rar", &vols[0], 60_000);
    // Scramble BOTH anchor volumes' segment numbering (the fully-
    // obfuscated norm). The head's parse resolves forward, the tail's
    // anchors the backward chain - either one arriving early (the head
    // prefetch fetches every file's declared segment 1) would place the
    // middle volume before it piles. Scrambled, each anchor classifies
    // only when its true offset-0 arrives mid-stream, well after the
    // middle volume has piled past the RAM cap. Both anchors stay under
    // the ~7.2 MB per-slot unclassified spill, so neither goes Plain.
    for (name, segs) in fx.nzb_files.iter_mut() {
        if name != "x.part1.rar" && name != "x.part3.rar" {
            continue;
        }
        let mut st = 0xFEEDBEEFu64;
        for i in (1..segs.len()).rev() {
            st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
            segs.swap(i, (st >> 33) as usize % (i + 1));
        }
        for (i, seg) in segs.iter_mut().enumerate() {
            seg.2 = i as u32 + 1;
        }
    }
    // Paced arrivals so the download follows ladder order: at memcpy
    // speed the head volume's offset-0 lands within the first moments
    // and the middle volume drains as it decodes - nothing ever holds
    // (the same loopback trap the obfuscated one-pass test documents).
    let chaos = Chaos { delay_ms: 5, ..Default::default() };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "64M"])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("paging to scratch"), "paging never engaged:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(log.contains("one-pass"), "shape must say one-pass:\n{log}");
    assert!(!log.contains("partly on disk"), "set demoted:\n{log}");
    assert!(!log.contains("held-bytes cap"), "the paged set still demoted:\n{log}");
    let extracted = std::fs::read(fx.dir.join("out/bigfilm.mkv")).expect("extracted file");
    assert_eq!(extracted, film, "extracted bytes differ");
    for n in ["x.part1.rar", "x.part2.rar", "x.part3.rar"] {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} must not touch disk (one-pass)"
        );
    }
    // The scratch died with the extractor - nothing internal left over.
    let leftovers: Vec<String> = std::fs::read_dir(fx.dir.join("out"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".nzbfast-holds."))
        .collect();
    assert!(leftovers.is_empty(), "scratch left behind: {leftovers:?}");
}

/// Synthesized segment numbering that preserved posting order but
/// started mid-sequence (the rotated shape): the NZB's declared order
/// puts the yEnc offset-0 article dead LAST, so the M3 head prefetch
/// fetches a mid-file article and the slot cannot classify. The
/// extractor's offset-0 probe must front-load the true head through the
/// promote ladder - the rotation guess (size-X) resolved against the
/// slot's own article ladder - so the set classifies within a
/// round-trip and extracts ONE-PASS. Pre-probe this run held until the
/// per-slot spill and the volume materialized for the disk post-pass.
#[tokio::test(flavor = "multi_thread")]
async fn rotated_segment_numbering_offset0_promoted_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("probe0-rot");
    let inner = payload(12_000_000, 31);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 12_000_000, &inner, false, false)]);
    fx.add_file("release.rar", &vol, 40_000);
    assert!(fx.add_par2(10, &["release.rar"], 40_000), "par2 create failed");
    // Rotate by one: declared segment k carries yEnc part k+1, and the
    // offset-0 article lands at the very end of the declared ladder;
    // sequential numbers slapped on, like the live post.
    for (name, segs) in fx.nzb_files.iter_mut() {
        if name.ends_with(".par2") {
            continue;
        }
        segs.rotate_left(1);
        for (i, seg) in segs.iter_mut().enumerate() {
            seg.2 = i as u32 + 1;
        }
    }
    // Paced arrivals, so holds really accumulate pre-classification the
    // way a real line does (at memcpy speed the run is over before the
    // probe's promote could matter either way).
    let chaos = Chaos { delay_ms: 5, ..Default::default() };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // --mem-limit 64M puts the per-slot spill at ~7.2 MB: without the
    // probe the 12 MB slot trips it and demotes to a materialized
    // volume long before its offset-0 article (dead last) arrives.
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "64M"])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(log.contains("one-pass"), "shape must say one-pass:\n{log}");
    assert!(!log.contains("partly on disk"), "set demoted:\n{log}");
    let extracted = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(extracted, inner, "extracted bytes differ");
    assert!(
        !fx.dir.join("out/release.rar").exists(),
        "volume must not touch disk (one-pass)"
    );
}

/// Follow-up to the offset-0 probe, the obfuscated MULTI-volume shape:
/// NZB subjects are garbage (no filename hint) while the yEnc names are
/// real, and every volume's segment numbering is rotated by one, so each
/// volume's offset-0 article lands dead LAST in its declared ladder. The
/// probe's promote is keyed by the yEnc name (sanitize_filename of
/// slot.name), which the subject-hint map cannot resolve; pre-fix the
/// lookup fell to the every-volume ladder fallback, scaled each probe
/// across the whole set's concatenation and front-loaded the wrong
/// file's articles - each 12 MB slot then held past the ~7.2 MB per-slot
/// spill (--mem-limit 64M) and the set demoted to a disk post-pass. The
/// decode consumers now register each slot's observed yEnc name with
/// SeekCtl before the write that fires the probe, so the promote
/// resolves against the right slot's own ladder: one-pass.
#[tokio::test(flavor = "multi_thread")]
async fn obfuscated_subjects_rotated_multivolume_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("probe0-obf-multi");
    // WinRAR-true geometry: volume 0 carries one byte more data.
    let total_len = 12_000_001 + 12_000_000 + 11_500_000;
    let film = payload(total_len, 59);
    let vols = [
        fixtures::rar5_volume_n(
            &[("realfilm.mkv", total_len as u64, &film[..12_000_001], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("realfilm.mkv", total_len as u64, &film[12_000_001..24_000_001], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("realfilm.mkv", total_len as u64, &film[24_000_001..], true, false)],
            2,
        ),
    ];
    let yenc_names = ["realpost.part1.rar", "realpost.part2.rar", "realpost.part3.rar"];
    // Dotless hash garbage, like the live obfuscated posts.
    let subjects = ["9f3ac1d2e4b5", "0817aa93c2fe", "5d64e0b17c88"];
    for ((subject, yenc), vol) in subjects.iter().zip(&yenc_names).zip(&vols) {
        fx.add_file_obfuscated(subject, yenc, vol, 40_000);
    }
    assert!(fx.add_par2(10, &yenc_names, 40_000), "par2 create failed");
    // Rotate by one: declared segment k carries yEnc part k+1 and the
    // offset-0 article lands at the very end of each declared ladder;
    // sequential numbers slapped on, like the live posts.
    for (name, segs) in fx.nzb_files.iter_mut() {
        if name.ends_with(".par2") {
            continue;
        }
        segs.rotate_left(1);
        for (i, seg) in segs.iter_mut().enumerate() {
            seg.2 = i as u32 + 1;
        }
    }
    // Paced arrivals, so holds really accumulate pre-classification (at
    // memcpy speed the run is over before the probe could matter).
    let chaos = Chaos { delay_ms: 5, ..Default::default() };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // --mem-limit 64M puts the per-slot spill at ~7.2 MB: a 12 MB slot
    // that cannot classify until its natural tail trips it and demotes.
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "64M"])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(log.contains("one-pass"), "shape must say one-pass:\n{log}");
    assert!(!log.contains("partly on disk"), "set demoted:\n{log}");
    let extracted = std::fs::read(fx.dir.join("out/realfilm.mkv")).expect("extracted file");
    assert_eq!(extracted, film, "extracted bytes differ");
    for n in yenc_names.iter().chain(subjects.iter()) {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} must not touch disk (one-pass)"
        );
    }
}

/// Encrypted RAR5 store set (the obfuscated-release norm): with the
/// password from the `Name{{pw}}.nzb` convention, the whole job must
/// complete on the NATIVE path - in-stream ciphertext assembly, live
/// PAR2 verify against volume bytes, one AES pass at finish - with unrar
/// forbidden by canary and no volume files ever touching disk.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_store_rar_decrypts_natively_without_unrar() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("encstore");
    let inner = payload(900_001, 23); // odd length: end-padding truncate
    let f = fixtures::encrypt_file("s3cretpw", &inner, 3);
    let n = f.cipher.len();
    // One CBC stream carved at odd (non-16-aligned) points, real-rar
    // style; every volume repeats the same crypt record.
    let (a, b) = (350_003, 700_006);
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    // Password rides the filename convention (SAB/NZBGet compatible).
    let locked = fx.dir.join("release{{s3cretpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &locked, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed (unrar canary tripped?):\n{log}");
    assert!(log.contains("password taken from"), "{log}");
    assert!(log.contains("decrypted"), "no native decrypt notice:\n{log}");
    assert!(!log.contains("unpacking archive with unrar"), "{log}");
    let extracted = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(extracted.len(), inner.len(), "padding must be truncated");
    assert_eq!(extracted, inner, "decrypted bytes differ");
    for v in &names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// The same shape in RAR4 (`rar -m0 -p`, the AES-128 + SHA-1 schedule):
/// posted split store set, password off the `Name{{pw}}.nzb` convention,
/// unrar forbidden by canary. RAR4 stores no password check, so this whole
/// job runs the UNVERIFIED route - ciphertext assembled at store offsets
/// during the download, one AES pass at finish, and the extracted file
/// published only because the archive's own plaintext CRC32 accepted it.
/// The end state must still be full one-pass extraction: exact payload,
/// not a volume on disk.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_rar4_store_set_decrypts_natively_without_unrar() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("encstore4");
    let inner = payload(900_001, 43); // odd length: end-padding truncate
    let f = fixtures::encrypt_file_v4("s3cretpw", &inner, 13);
    let n = f.cipher.len();
    // One CBC stream carved at odd (non-16-aligned) points, exactly as the
    // rars writer and WinRAR chunk a split RAR4 volume set.
    let (a, b) = (350_003, 700_006);
    let vols = [
        fixtures::rar4_volume_enc(&[("movie.mkv", &f, 0..a, false, true)]),
        fixtures::rar4_volume_enc(&[("movie.mkv", &f, a..b, true, true)]),
        fixtures::rar4_volume_enc(&[("movie.mkv", &f, b..n, true, false)]),
    ];
    let names = ["r4.part1.rar", "r4.part2.rar", "r4.part3.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let locked = fx.dir.join("release{{s3cretpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &locked, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed (unrar canary tripped?):\n{log}");
    assert!(log.contains("password taken from"), "{log}");
    assert!(log.contains("decrypted"), "no native decrypt notice:\n{log}");
    assert!(!log.contains("unpacking archive with unrar"), "{log}");
    let extracted = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(extracted.len(), inner.len(), "padding must be truncated");
    assert_eq!(extracted, inner, "decrypted bytes differ");
    for v in &names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// The RAR4 `-hp` shape (encrypted HEADERS as well as data) end to end.
/// Nothing in the volume is readable without the password - not even the
/// file name - so this proves the mapper's header decryption, not just its
/// data path.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_rar4_header_encrypted_set_decrypts_natively_without_unrar() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("enchdrs4");
    let inner = payload(500_003, 44);
    let f = fixtures::encrypt_file_v4("hp4pass", &inner, 14);
    let n = f.cipher.len();
    let a = 260_001;
    let vols = [
        fixtures::rar4_volume_enc_headers(
            &[("movie.mkv", &f, 0..a, false, true)],
            "hp4pass",
            5,
        ),
        fixtures::rar4_volume_enc_headers(&[("movie.mkv", &f, a..n, true, false)], "hp4pass", 5),
    ];
    let names = ["h4.part1.rar", "h4.part2.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let locked = fx.dir.join("release{{hp4pass}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &locked, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed (unrar canary tripped?):\n{log}");
    assert!(log.contains("decrypted"), "no native decrypt notice:\n{log}");
    assert!(!log.contains("unpacking archive with unrar"), "{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        inner
    );
    for v in &names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// Same set, WRONG password: the job must fail (not exit 0 with garbage),
/// keep the verified volumes on disk for a retry, and still never touch
/// unrar when the canary forbids it.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_store_rar_wrong_password_keeps_volumes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("encwrongpw");
    let inner = payload(400_000, 24);
    let f = fixtures::encrypt_file("rightpw", &inner, 5);
    let n = f.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n / 2, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, n / 2..n, true, false)], Some(1)),
    ];
    let names = ["w.part1.rar", "w.part2.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let locked = fx.dir.join("release{{wrongpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &locked, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(!ok, "wrong password must not exit 0:\n{log}");
    assert!(log.contains("wrong archive password"), "{log}");
    // The PAR2-verified volumes are the retry currency - byte-exact.
    for (name, vol) in names.iter().zip(&vols) {
        assert_eq!(
            &std::fs::read(fx.dir.join("out").join(name)).expect("volume on disk"),
            vol,
            "volume {name} must be byte-exact for a retry"
        );
    }
    assert!(!fx.dir.join("out/movie.mkv").exists(), "no garbage output");
}

/// Same set, NO password anywhere: the job must complete like an `-hp`
/// (encrypted-headers) set does - verified volumes kept on disk and the
/// 🔒 password prompt printed - NOT fail through an unrar attempt that
/// cannot succeed without a key. The demote reason used to be NotStore's
/// "compressed or encrypted entries", whose "compressed" substring steered
/// the finish ladder's unrar arm; MapBlocker::EncryptedNoPassword now
/// routes it to the locked-no-password arm.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_store_rar_no_password_keeps_volumes_and_prompts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("encnopw");
    let inner = payload(400_000, 25);
    let f = fixtures::encrypt_file("neverseen", &inner, 6);
    let n = f.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n / 2, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, n / 2..n, true, false)], Some(1)),
    ];
    let names = ["k.part1.rar", "k.part2.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "locked set with no password must complete, not fail:\n{log}");
    assert!(
        log.contains("password-protected and no password was found"),
        "missing the 🔒 prompt:\n{log}"
    );
    assert!(
        !log.contains("could not be unpacked"),
        "the pre-fix unrar-arm failure is back:\n{log}"
    );
    // The PAR2-verified volumes are the deliverable until a password lands.
    for (name, vol) in names.iter().zip(&vols) {
        assert_eq!(
            &std::fs::read(fx.dir.join("out").join(name)).expect("volume on disk"),
            vol,
            "volume {name} must be byte-exact for the unlock"
        );
    }
    assert!(!fx.dir.join("out/movie.mkv").exists(), "no garbage output");
}

/// A single non-volume RAR5 store archive of `files`, each its own AES
/// stream under one shared password (`rar -m0 -p` multi-file shape).
fn enc_store(pw: &str, files: &[(&str, &[u8])], seed: u8) -> Vec<u8> {
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

/// The password-chain gauntlet, end to end through the real binary: a
/// 3-level encrypted nest where each level carries the NEXT level's
/// password in a sibling text file, wrapped in an unencrypted release
/// archive that is the only thing downloaded. From zero job passwords the
/// whole stack must auto-unlock (rc=0) with no manual-🔑 park, and produce
/// the innermost payload byte-exact.
#[tokio::test(flavor = "multi_thread")]
async fn nested_password_chain_auto_unlocks_end_to_end() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("pwchain");
    let inner = payload(300_000, 19);
    let stage3 = enc_store("charlie", &[("movie.mkv", &inner)], 40);
    let stage2 = enc_store("bravo", &[("stage3.rar", &stage3), ("pw3.txt", b"charlie\n")], 20);
    let stage1 = enc_store("alpha", &[("stage2.rar", &stage2), ("pw2.txt", b"bravo\n")], 10);
    // The downloaded release: an ordinary store archive holding the first
    // encrypted level and its password note.
    let outer = fixtures::rar5_volume(&[
        ("stage1.rar", stage1.len() as u64, stage1.as_slice(), false, false),
        ("pw1.txt", 6, &b"alpha\n"[..], false, false),
    ]);
    fx.add_file("release.rar", &outer, 120_000);
    assert!(fx.add_par2(15, &["release.rar"], 120_000), "par2 create failed");

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "nested password chain must complete rc=0:\n{log}");
    let low = log.to_lowercase();
    // Key on the actual park messages (the 🔒 prompt, the daemon's unlock
    // notice), not a bare "password required" - the nested-prevalence
    // telemetry line legitimately prints the demote reason "encrypted
    // entries (password required)" on a run that then auto-unlocks.
    assert!(!log.contains("🔒"), "must not park for a manual key:\n{log}");
    assert!(!low.contains("password required to unpack"), "must not park for a manual key:\n{log}");
    assert!(!low.contains("no password was found"), "must not park for a manual key:\n{log}");
    assert!(!low.contains("set a password"), "must not park for a manual key:\n{log}");
    assert!(log.contains("auto-unlocked"), "expected auto-unlock notices:\n{log}");

    // The innermost payload lands somewhere under the out tree, byte-exact.
    let mut found: Option<PathBuf> = None;
    let mut stack = vec![fx.dir.join("out")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == "movie.mkv") {
                found = Some(p);
            }
        }
    }
    let found = found.unwrap_or_else(|| panic!("movie.mkv must be produced:\n{log}"));
    assert_eq!(std::fs::read(&found).unwrap(), inner, "decrypted payload differs");
}

/// Multi-file store set with a file boundary INSIDE a volume (E01's tail
/// and E02's head share v2) - the season-pack / movie+sample layout.
/// Regression for the 20 Jul Fable-audit whole-file-loss bug: volumes
/// grouped by their FIRST inner-file name, so E02's continuation volumes
/// formed a second group whose head piece lived in the first group; its
/// spans never base-resolved, and at finish() the fallback DELETED the
/// shared E02.mkv - in-stream PAR2 passed throughout (volume bytes were
/// all correct), so the job exited 0 with an entire file gone.
#[tokio::test(flavor = "multi_thread")]
async fn multi_file_store_set_extracts_both_files() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multifile");
    let e01 = payload(500_000, 11);
    let e02 = payload(300_000, 12);
    let vols = [
        // WinRAR-true: volume 0's piece is one byte longer than volume 1's.
        fixtures::rar5_volume_n(&[("E01.mkv", 500_000, &e01[..200_001], false, true)], 0),
        fixtures::rar5_volume_n(&[("E01.mkv", 500_000, &e01[200_001..400_001], true, true)], 1),
        fixtures::rar5_volume_n(
            &[
                ("E01.mkv", 500_000, &e01[400_001..], true, false),
                ("E02.mkv", 300_000, &e02[..100_000], false, true),
            ],
            2,
        ),
        fixtures::rar5_volume_n(&[("E02.mkv", 300_000, &e02[100_000..], true, false)], 3),
    ];
    let names = ["s.part1.rar", "s.part2.rar", "s.part3.rar", "s.part4.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 2 file(s) in-stream"), "{log}");
    assert!(
        !log.contains("fell back"),
        "direct extraction fell back:\n{log}"
    );
    let got1 = std::fs::read(fx.dir.join("out/E01.mkv")).expect("E01 extracted");
    let got2 = std::fs::read(fx.dir.join("out/E02.mkv")).expect("E02 extracted");
    assert_eq!(got1, e01, "E01 bytes differ");
    assert_eq!(got2, e02, "E02 bytes differ");
    for v in &names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// Real WinRAR fixtures vendored with the rars fork - the inner layer of
/// the RAR-in-RAR tests, guaranteed extractable by the native unpack path.
fn rars_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/rars/tests/fixtures/rar50")
}

/// RAR-in-RAR: a store-mode outer set whose PAYLOAD is itself a named
/// multi-volume RAR set (real WinRAR volumes). The outer set extracts
/// in-stream; the nested post-pass must then denest the inner set.
/// Regression: the daemon gated that pass on "no named .rar in the
/// output dir", which the inner payload itself tripped - the job exited
/// 0 with the inner volumes still packed.
///
/// The chasing decompressor is gated OFF for this run: with it on, the
/// compressed inner set decodes in-stream and the disk post-pass this
/// test exists to cover never engages (that path has its own e2e below).
#[tokio::test(flavor = "multi_thread")]
async fn store_rar_in_rar_denests_inner_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarinrar");
    let fixdir = rars_fixture_dir();
    let i1 = std::fs::read(fixdir.join("multivol.part1.rar")).unwrap();
    let i2 = std::fs::read(fixdir.join("multivol.part2.rar")).unwrap();
    let i3 = std::fs::read(fixdir.join("multivol.part3.rar")).unwrap();
    let cut = i2.len() / 2;
    // Outer store set: inner volume files as entries, one boundary INSIDE
    // an outer volume (multivol.part2.rar spans both) - the season-pack
    // shape, with the payload files being a RAR set of their own.
    let vols = [
        fixtures::rar5_volume_n(
            &[
                ("multivol.part1.rar", i1.len() as u64, &i1[..], false, false),
                ("multivol.part2.rar", i2.len() as u64, &i2[..cut], false, true),
            ],
            0,
        ),
        fixtures::rar5_volume_n(
            &[
                ("multivol.part2.rar", i2.len() as u64, &i2[cut..], true, false),
                ("multivol.part3.rar", i3.len() as u64, &i3[..], false, false),
            ],
            1,
        ),
    ];
    let names = ["o.part1.rar", "o.part2.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 1500);
    }
    assert!(fx.add_par2(20, &names, 1500), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_NESTED_CHASE", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 3 file(s) in-stream"), "{log}");
    // The nested pass must denest the inner set into its real payload.
    let payload = fx.dir.join("out/random_4k.bin");
    assert!(payload.exists(), "inner RAR set was not denested:\n{log}");
    assert_eq!(
        std::fs::metadata(&payload).unwrap().len(),
        4096,
        "denested payload has the wrong size:\n{log}"
    );
    // Outer volumes still never touch disk.
    for v in &names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "outer volume {v} must not touch disk:\n{log}"
        );
    }
}

/// The same RAR-in-RAR post with the chasing decompressor LIVE (the
/// default): the compressed inner set decodes while its bytes arrive -
/// the payload lands directly and NEITHER the outer volumes NOR the
/// inner .rar set ever touches disk. Real WinRAR volumes, an inner
/// volume boundary inside an outer volume, full daemon path.
#[tokio::test(flavor = "multi_thread")]
async fn store_rar_in_rar_chases_compressed_inner() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarinrar-chase");
    let fixdir = rars_fixture_dir();
    let i1 = std::fs::read(fixdir.join("multivol.part1.rar")).unwrap();
    let i2 = std::fs::read(fixdir.join("multivol.part2.rar")).unwrap();
    let i3 = std::fs::read(fixdir.join("multivol.part3.rar")).unwrap();
    let cut = i2.len() / 2;
    let vols = [
        fixtures::rar5_volume_n(
            &[
                ("multivol.part1.rar", i1.len() as u64, &i1[..], false, false),
                ("multivol.part2.rar", i2.len() as u64, &i2[..cut], false, true),
            ],
            0,
        ),
        fixtures::rar5_volume_n(
            &[
                ("multivol.part2.rar", i2.len() as u64, &i2[cut..], true, false),
                ("multivol.part3.rar", i3.len() as u64, &i3[..], false, false),
            ],
            1,
        ),
    ];
    let names = ["o.part1.rar", "o.part2.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 1500);
    }
    assert!(fx.add_par2(20, &names, 1500), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        !log.contains("fell back") && !log.contains("nested fallback"),
        "chase demoted:\n{log}"
    );
    let payload = fx.dir.join("out/random_4k.bin");
    assert!(payload.exists(), "chased payload missing:\n{log}");
    assert_eq!(
        std::fs::metadata(&payload).unwrap().len(),
        4096,
        "chased payload has the wrong size:\n{log}"
    );
    // One pass all the way down: no outer volume, no inner volume.
    for v in names.iter().copied().chain([
        "multivol.part1.rar",
        "multivol.part2.rar",
        "multivol.part3.rar",
    ]) {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "{v} must not touch disk:\n{log}"
        );
    }
}

/// Compressed set: direct extraction falls back and the on-disk unpack
/// runs exactly once - the nested post-pass must NOT re-process the
/// fallback volumes (that guard is what the RAR-in-RAR fix above
/// refined, not removed). Since spec Part B the successfully-unpacked
/// volumes are spent and deleted rather than left beside the payload.
/// Pinned on the top-chase kill switch: with the depth-0 chase on this
/// shape streams instead, but the disk path stays reachable (cap
/// demote, gate off) and its mechanics are what this test guards.
#[tokio::test(flavor = "multi_thread")]
async fn compressed_fallback_leftovers_not_reprocessed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("comprleft");
    // Real compressed (m3) WinRAR archive - the mapper flags it NotStore
    // and the group falls back to materialized volumes.
    let arch = std::fs::read(rars_fixture_dir().join("m3_default.rar")).unwrap();
    fx.add_file("c.rar", &arch, 1500);
    assert!(fx.add_par2(20, &["c.rar"], 1500), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_TOP_RAR_CHASE", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("compressed"), "no fallback notice:\n{log}");
    // Exactly ONE unpack over the fallback volumes - a second one means
    // the nested pass re-processed the leftover outer set.
    assert_eq!(
        log.matches("unpacking archive natively").count(),
        1,
        "outer volumes re-processed:\n{log}"
    );
    // Part B: the unpack succeeded, so the volume is spent and deleted -
    // only the payload remains.
    assert!(
        !fx.dir.join("out/c.rar").exists(),
        "spent volume must not survive the unpack:\n{log}"
    );
    assert!(
        fx.dir.join("out/bigtext_64k.bin").exists(),
        "compressed payload missing:\n{log}"
    );
}

/// Compressed OUTER wrapping a named inner RAR, on the DISK path
/// (pinned via the top-chase kill switch - with the depth-0 chase on,
/// this shape streams): the volumes fall back, the on-disk unpack
/// produces inner.rar BESIDE the leftover c.rar - and the nested
/// pass must park the leftovers, denest the inner set, and put the
/// leftovers back untouched. Regression: the leftover guard used to skip
/// the whole pass, exiting 0 with the payload still packed.
#[tokio::test(flavor = "multi_thread")]
async fn compressed_outer_wrapping_rar_denests_beside_leftovers() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Half-entropy payload: the store-mode inner rar built from it stays
    // compressible, so the outer writer really compresses (it silently
    // stores incompressible entries, which would dodge the fallback).
    let mut s = 0x243f6a8885a308d3u64;
    let doc: Vec<u8> = (0..300_000usize)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect();
    let store_opts = || {
        rars::rar50::WriterOptions::new(rars::ArchiveVersion::Rar50, rars::FeatureSet::store_only())
    };
    let inner = rars::rar50::Rar50Writer::new(store_opts())
        .stored_entries(&[rars::rar50::StoredEntry {
            name: b"movie.bin",
            data: &doc,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap();
    let outer = rars::rar50::Rar50Writer::new(store_opts())
        .compressed_entries(&[
            rars::rar50::CompressedEntry {
                name: b"inner.rar",
                data: &inner,
                mtime: None,
                attributes: 0,
                host_os: 0,
            },
            rars::rar50::CompressedEntry {
                name: b"readme.txt",
                data: b"the payload rides one level down",
                mtime: None,
                attributes: 0,
                host_os: 0,
            },
        ])
        .finish()
        .unwrap();

    let mut fx = Fixture::new("comprnest");
    fx.add_file("c.rar", &outer, 1500);
    assert!(fx.add_par2(20, &["c.rar"], 1500), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_TOP_RAR_CHASE", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("compressed"), "no fallback notice:\n{log}");
    // Two unpacks: the fallback over c.rar, the nested pass over inner.rar.
    assert_eq!(
        log.matches("unpacking archive natively").count(),
        2,
        "expected fallback unpack + nested denest:\n{log}"
    );
    let got = std::fs::read(fx.dir.join("out/movie.bin")).expect("denested payload");
    assert_eq!(got, doc, "denested payload bytes differ");
    assert_eq!(
        std::fs::read(fx.dir.join("out/readme.txt")).unwrap(),
        b"the payload rides one level down",
        "sibling payload damaged:\n{log}"
    );
    // Part B: the outer volume was spent by its successful unpack and
    // deleted; the scratch hold is gone too.
    assert!(
        !fx.dir.join("out/c.rar").exists(),
        "spent outer volume must not survive the unpack:\n{log}"
    );
    assert!(
        !fx.dir.join("out/.nzbfast-outer-hold").exists(),
        "scratch hold left behind:\n{log}"
    );
}

/// Same compressed-outer shape, but the payload archive rides in a
/// SUBFOLDER ("Sub/inner.rar") - the on-disk unpack writes real subdirs,
/// and both the leftover gate and the nested pass historically scanned
/// the top level only, so the subfoldered inner set stayed packed.
#[tokio::test(flavor = "multi_thread")]
async fn compressed_outer_with_subfolder_rar_payload_denests() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut s = 0x13198a2e03707344u64;
    let doc: Vec<u8> = (0..250_000usize)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect();
    let store_opts = || {
        rars::rar50::WriterOptions::new(rars::ArchiveVersion::Rar50, rars::FeatureSet::store_only())
    };
    let inner = rars::rar50::Rar50Writer::new(store_opts())
        .stored_entries(&[rars::rar50::StoredEntry {
            name: b"movie.bin",
            data: &doc,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap();
    let outer = rars::rar50::Rar50Writer::new(store_opts())
        .compressed_entries(&[rars::rar50::CompressedEntry {
            name: b"Sub/inner.rar",
            data: &inner,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap();

    let mut fx = Fixture::new("comprsubnest");
    fx.add_file("c.rar", &outer, 1500);
    assert!(fx.add_par2(20, &["c.rar"], 1500), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Disk path pinned via the top-chase kill switch (see the sibling
    // test above for why).
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_TOP_RAR_CHASE", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("compressed"), "no fallback notice:\n{log}");
    let got = std::fs::read(fx.dir.join("out/Sub/movie.bin"))
        .expect("subfoldered payload denested");
    assert_eq!(got, doc, "denested payload bytes differ");
    // Part B: the outer volume was spent by its successful unpack.
    assert!(
        !fx.dir.join("out/c.rar").exists(),
        "spent outer volume must not survive the unpack:\n{log}"
    );
    assert!(
        !fx.dir.join("out/.nzbfast-outer-hold").exists(),
        "scratch hold left behind:\n{log}"
    );
}

/// The top-level RAR chase (the RAR analogue of TODO 37 step 1): a
/// POSTED multi-volume COMPRESSED RAR5 set streams at depth 0 - payload
/// decoded in flight, volumes never on disk, unrar forbidden by canary.
/// Before the depth-gate lift this shape demoted to materialized
/// volumes and waited for the unrar ladder.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_compressed_rar_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Half-entropy payload: compressible enough that the writer keeps
    // the compressed method (it silently stores incompressible entries,
    // which would dodge the chase and test the store path instead).
    let mut s = 0x9e3779b97f4a7c15u64;
    let doc: Vec<u8> = (0..600_000usize)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect();
    let vols = rars::rar50::Rar50VolumeWriter::new(rars::rar50::WriterOptions::default())
        .compressed_entries(&[rars::rar50::CompressedEntry {
            name: b"movie.bin",
            data: &doc,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .max_payload_per_volume(80_000)
        .finish()
        .unwrap();
    assert!(vols.len() >= 3, "want a real multi-volume set, got {}", vols.len());
    let mut fx = Fixture::new("toprarchase");
    let names: Vec<String> =
        (1..=vols.len()).map(|i| format!("c.part{i}.rar")).collect();
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 9_000);
    }
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(20, &name_refs, 9_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed (unrar canary tripped?):\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(
        log.contains("extracted 1 file(s) in-stream"),
        "payload did not stream:\n{log}"
    );
    assert!(
        !log.contains("unpacking archive"),
        "disk unpack ran - the chase demoted:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ"
    );
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} must not touch disk"
        );
    }
}

/// Half-entropy bytes (xorshift byte, zero byte, ...): compressible
/// enough that the rars writer keeps the compressed method - it silently
/// stores incompressible entries, which would dodge the chase and test
/// the store path instead.
fn half_entropy(n: usize, mut s: u64) -> Vec<u8> {
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect()
}

/// Encrypted AND compressed at depth 0 (Increment E's second shape): a
/// posted multi-volume RAR5 whose single member is both deflated and
/// AES-encrypted, password riding the `Name{{pw}}.nzb` convention. With
/// the password in hand at start the chase gate admits the entry, and
/// the whole job must stream one-pass: payload decoded+decrypted in
/// flight, no volume ever on disk, unrar forbidden by canary.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_compressed_rar_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let doc = half_entropy(600_000, 0x9e3779b97f4a7c15);
    let mut features = rars::FeatureSet::store_only();
    features.file_encryption = true;
    let opts = rars::rar50::WriterOptions::new(rars::ArchiveVersion::Rar50, features);
    let vols = rars::rar50::Rar50VolumeWriter::new(opts)
        .encrypted_compressed_entries(&[rars::rar50::EncryptedCompressedEntry {
            name: b"movie.bin",
            data: &doc,
            mtime: None,
            attributes: 0,
            host_os: 0,
            password: b"s3cretpw",
        }])
        .max_payload_per_volume(80_000)
        .finish()
        .unwrap();
    assert!(vols.len() >= 3, "want a real multi-volume set, got {}", vols.len());
    let mut fx = Fixture::new("topencchase");
    let names: Vec<String> =
        (1..=vols.len()).map(|i| format!("c.part{i}.rar")).collect();
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 9_000);
    }
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(20, &name_refs, 9_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    // Password rides the filename convention (SAB/NZBGet compatible).
    let locked = fx.dir.join("release{{s3cretpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &locked, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed (unrar canary tripped?):\n{log}");
    assert!(log.contains("password taken from"), "{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(
        log.contains("extracted 1 file(s) in-stream"),
        "payload did not stream:\n{log}"
    );
    assert!(
        !log.contains("unpacking archive"),
        "disk unpack ran - the chase demoted:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "decrypted+decoded bytes differ"
    );
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} must not touch disk"
        );
    }
}

/// A DAMAGED posted compressed set exits the chase through the
/// materialize-for-repair door (the depth-0 twin of
/// `damaged_post_repairs_and_reextracts`): a data article goes missing
/// mid-volume, so the chased slots come down as byte-exact volume files
/// ("materializing volumes for repair"), PAR2 repairs them on disk, and
/// the re-extract pass must land the correct payload - rc=0 only for
/// that end state.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_compressed_rar_damaged_repairs_and_reextracts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let doc = half_entropy(600_000, 0xa076_1d64_78bd_642f);
    let vols = rars::rar50::Rar50VolumeWriter::new(rars::rar50::WriterOptions::default())
        .compressed_entries(&[rars::rar50::CompressedEntry {
            name: b"movie.bin",
            data: &doc,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .max_payload_per_volume(80_000)
        .finish()
        .unwrap();
    assert!(vols.len() >= 3, "want a real multi-volume set, got {}", vols.len());
    let mut fx = Fixture::new("toprardmg");
    let names: Vec<String> =
        (1..=vols.len()).map(|i| format!("c.part{i}.rar")).collect();
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 9_000);
    }
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(20, &name_refs, 9_000), "par2 create failed");
    // Lose a DATA article inside part2's packed stream: the chase engine
    // blocks at the gap, verification reads the hole back bad, and the
    // mapped-repair gate declines the chased slot - forcing the
    // materialize + repair_dir + re-extract path this test pins.
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("c_part2_rar") && k.ends_with("-3@mock>"))
        .expect("victim article")
        .clone();
    let chaos = Chaos {
        missing: [victim].into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("materializing volumes for repair"), "{log}");
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    // The re-extract pass runs in protect-sources mode, which never
    // chases - a compressed set demotes there and exits through its
    // unrar-ladder fallback. What matters is the end state: payload on
    // disk, volumes spent.
    assert!(log.contains("re-extracting"), "no re-extract pass:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ after repair"
    );
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "spent volume {n} must be cleaned up:\n{log}"
        );
    }
}

/// Build a real store-mode RAR5 (rars writer, whole-file CRC stored in
/// the header) around one payload file - the inner layer for the CRC
/// audit tests.
fn store_rar(name: &'static [u8], data: &[u8]) -> Vec<u8> {
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
}

/// Same damage with NO cure packed beside it: the job must fail loudly
/// (rc=1) with the corrupt output deleted - never exit 0 with silently
/// wrong bytes, which is exactly what this audit exists to prevent.
#[tokio::test(flavor = "multi_thread")]
async fn nested_prepacked_data_damage_fails_loudly_without_cure() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("crcloud");
    let movie = payload(300_000, 43);
    let mut damaged = store_rar(b"movie.bin", &movie);
    let n = damaged.len();
    damaged[n - 2000..n - 1900].iter_mut().for_each(|b| *b ^= 0x5a);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        damaged.len() as u64,
        &damaged[..],
        false,
        false,
    )]);
    fx.add_file("o.rar", &outer, 8000);
    assert!(fx.add_par2(20, &["o.rar"], 8000), "outer par2 create failed");

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(!ok, "pre-packed damage with no cure must not exit 0:\n{log}");
    assert!(
        log.contains("failed its stored CRC"),
        "CRC gate did not fire:\n{log}"
    );
    let corrupt_survived = std::fs::read(fx.dir.join("out/movie.bin"))
        .is_ok_and(|b| b != movie);
    assert!(!corrupt_survived, "corrupt payload left on disk as output:\n{log}");
}

/// A store volume whose headers do not describe a whole file - an honest
/// data area, an inflated `unpacked_size`, `split_after` set and no further
/// volume - must never come back as a finished job. Every byte arrives
/// exactly as posted, so PAR2 reports zero damage and the download itself
/// is clean; the archive is simply not all there. The in-stream gate
/// demotes the group and materializes the volume, and the job then has to
/// judge that on-disk set: either it unpacks (and the job succeeds) or it
/// does not (and the job fails). What it must not do is report success over
/// an output directory holding one loose .rar and no payload at all.
#[tokio::test(flavor = "multi_thread")]
async fn set_whose_headers_are_short_a_file_never_completes_empty() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("shorthdr");
    let data = payload(300_000, 11);
    // 900 KB declared, 300 KB posted, continues into a volume that does
    // not exist.
    let vol = fixtures::rar5_volume(&[("movie.mkv", 900_000, &data[..], false, true)]);
    fx.add_file("o.rar", &vol, 60_000);
    assert!(fx.add_par2(20, &["o.rar"], 60_000), "par2 create failed");

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    let payload_out = fx.dir.join("out/movie.mkv");
    if ok {
        // Success is only honest if the payload is actually there and whole.
        let got = std::fs::read(&payload_out).unwrap_or_else(|e| {
            panic!("job reported success with no payload in the output dir ({e}):\n{log}")
        });
        assert_eq!(
            got.len(),
            900_000,
            "job reported success over a short file:\n{log}"
        );
    } else {
        // Failing is the other honest answer, but a partial file must not
        // be left lying about as though it were the release.
        assert!(
            !payload_out.exists(),
            "failed job left a partial payload on disk:\n{log}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn redownload_reclaims_real_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Obfuscated plain post: the data file is posted under a hash-like
    // name; only the PAR2 FileDesc carries the real one. Regression: the
    // deobfuscation rename used to be skipped when the target already
    // existed, so a RE-download into the same folder stranded a full,
    // verified copy under its obfuscated post name (two 7 GB "hash"
    // files next to one correctly named mkv, 19 Jul field report).
    let mut fx = Fixture::new("rename2");
    let data = payload(400_000, 3);
    fx.add_file("9b7232da7042b6a8", &data, 60_000);
    std::fs::write(fx.dir.join("movie.mkv"), &data).unwrap();
    assert!(fx.add_par2(10, &["movie.mkv"], 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    for run in 1..=2 {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap();
        assert!(ok, "run {run} failed:\n{log}");
        assert!(
            fx.dir.join("out/movie.mkv").exists(),
            "run {run}: real name missing:\n{log}"
        );
        assert!(
            !fx.dir.join("out/9b7232da7042b6a8").exists(),
            "run {run}: obfuscated name survived:\n{log}"
        );
        assert_eq!(
            std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(),
            data,
            "run {run}: bytes differ"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_server_union_completes() {
    // Server A is missing half the articles, server B the other half -
    // only the union can complete the download.
    let mut fx = Fixture::new("union");
    let data = payload(500_000, 3);
    fx.add_file("data.bin", &data, 40_000);
    let all_ids: Vec<String> = fx.articles.keys().cloned().collect();
    let mut chaos_a = Chaos::default();
    let mut chaos_b = Chaos::default();
    for (i, id) in all_ids.iter().enumerate() {
        if i % 2 == 0 {
            chaos_a.missing.insert(id.clone());
        } else {
            chaos_b.missing.insert(id.clone());
        }
    }
    let srv_a = MockServer::start(fx.articles.clone(), chaos_a).await;
    let srv_b = MockServer::start(fx.articles.clone(), chaos_b).await;
    let cfg = fx.write_config(&[&srv_a, &srv_b]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/data.bin")).unwrap(), data);
}

/// The one test that forces the EXTERNAL par2cmdline fallback
/// (`NZBFAST_NO_NATIVE_REPAIR`), and therefore the regression guard for the
/// handle discipline that fallback needs on Windows.
///
/// par2cmdline opens its targets with no sharing, so until `run_external_par2`
/// parked our writers this could not pass on Windows at all - par2 reported
///
///     Could not open ".\testset.par2": The process cannot access the file
///       because it is being used by another process.
///     Could not open "...\out\payload.bin": ...
///     Target: "payload.bin" - missing.  Repair is not possible.
///
/// and asked for 1600 more recovery blocks, because a whole-file "missing"
/// verdict needs the whole file's worth of recovery. It ran everywhere else
/// (Unix does not enforce sharing), which is exactly why the assertions here
/// were never weakened while the gate was on.
#[tokio::test(flavor = "multi_thread")]
async fn corrupt_article_detected_and_repaired() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("corrupt");
    let data = payload(600_000, 5);
    fx.add_file("payload.bin", &data, 50_000);
    assert!(fx.add_par2(20, &["payload.bin"], 50_000));
    // Corrupt two payload articles (mock flips a byte → yEnc CRC fails →
    // decode error → the span never lands → its blocks read back bad):
    // the offset-0 HEAD article - regression guard: with the sniff bytes
    // lost the slot never classifies, and its held spans must still reach
    // disk before repair (else par2 sees the whole target missing) - plus
    // an ordinary mid-file article. Runs with native repair DISABLED so
    // the par2cmdline fallback path stays covered end-to-end (the native
    // path is pinned by damaged_post_repairs_and_reextracts).
    let victim = |suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains("payload_bin") && k.ends_with(suffix))
            .unwrap()
            .clone()
    };
    let chaos = Chaos {
        corrupt: [victim("-1@mock>"), victim("-6@mock>")].into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_NATIVE_REPAIR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    assert!(
        !log.contains("(native"),
        "native repair ran despite NZBFAST_NO_NATIVE_REPAIR:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/payload.bin")).unwrap(),
        data,
        "repaired bytes differ"
    );
}

/// The 2026-07 damaged-post bench scenario: a store-mode RAR set
/// direct-extracting when DATA articles turn out missing on the wire.
/// Volumes materialize for repair, par2 repairs them, and re-extraction
/// must yield the inner file - with the volumes cleaned up and rc=0 only
/// for that end state. (The original bug: re-extraction fed volumes in
/// read_dir order, hit the holds cap, and its fallback truncated the
/// repaired volumes it was reading - rc=0 with no mkv and a wrecked set.)
#[tokio::test(flavor = "multi_thread")]
async fn damaged_post_repairs_and_reextracts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, inner, vol_names) = rar_release("damagedpost", true);
    // Poison mid-volume DATA articles across two volumes, AND part3's
    // offset-0 HEADER article: the headerless volume can't map, so the
    // M2c.1 mapped-repair gate declines and this test keeps pinning the
    // materialize + repair_dir + re-extract path (the mapped path has
    // its own test below).
    let victim = |file: &str, suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains(file) && k.ends_with(suffix))
            .unwrap()
            .clone()
    };
    let chaos = Chaos {
        missing: [
            victim("r_part2_rar", "-3@mock>"),
            victim("r_part3_rar", "-1@mock>"),
        ]
        .into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("materializing volumes for repair"), "{log}");
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    // The repair must be the in-process GF(2^16) path, not par2cmdline -
    // a silent fallback here would hide a native-repair regression.
    assert!(log.contains("(native"), "repair fell back to par2cmdline:\n{log}");
    assert!(log.contains("re-extracting"), "no re-extract pass:\n{log}");
    assert!(
        !log.contains("not re-extractable"),
        "re-extraction fell back:\n{log}"
    );
    let mkv = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(mkv, inner, "extracted bytes differ after repair");
    for v in &vol_names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} should be removed after re-extraction"
        );
    }
}

/// M2c.1: when every damaged file is a mapped store-mode slot, repair
/// goes straight INTO the extracted output through the block→payload
/// mapping - volume files must never exist on disk and no re-extract
/// pass may run.
#[tokio::test(flavor = "multi_thread")]
async fn damaged_post_repairs_into_output_without_volumes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, inner, vol_names) = rar_release("mappedrepair", true);
    // Mid-volume DATA articles only - headers arrive, every volume maps.
    let victim = |file: &str, suffix: &str| {
        fx.articles
            .keys()
            .find(|k| k.contains(file) && k.ends_with(suffix))
            .unwrap()
            .clone()
    };
    let chaos = Chaos {
        missing: [
            victim("r_part2_rar", "-3@mock>"),
            victim("r_part2_rar", "-5@mock>"),
            victim("r_part3_rar", "-4@mock>"),
        ]
        .into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("(native, mapped:"),
        "repair did not take the mapped path:\n{log}"
    );
    assert!(
        !log.contains("materializing volumes for repair"),
        "volumes were materialized:\n{log}"
    );
    assert!(
        !log.contains("re-extracting"),
        "a re-extract pass ran:\n{log}"
    );
    let mkv = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(mkv, inner, "extracted bytes differ after mapped repair");
    for v in &vol_names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must never exist on disk:\n{log}"
        );
    }
}

/// M2c.5 speculative prefetch: a slow download gives the watcher time to
/// fetch recovery volumes that may cover the WHOLE deficit before
/// settle. Repair must still run - `needed == 0` is a fetch answer, not
/// a damage verdict (gating repair on it shipped bad blocks as a
/// "clean download" with exit 0).
#[tokio::test(flavor = "multi_thread")]
async fn speculative_prefetch_covers_deficit_and_repair_still_runs() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, inner, _vol_names) = rar_release("specpre", true);
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("r_part2_rar") && k.ends_with("-3@mock>"))
        .unwrap()
        .clone();
    let chaos = Chaos {
        missing: [victim].into(),
        // Slow every body so the download outlives the watcher's poll +
        // side fetch - the Missing verdict lands in the first batch.
        delay_ms: 150,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("prefetching recovery volume"),
        "speculative prefetch never fired:\n{log}"
    );
    assert!(
        log.contains("repair complete"),
        "repair must run even when the prefetch covered the deficit:\n{log}"
    );
    assert!(
        !log.contains("clean download"),
        "damaged post must never report a clean download:\n{log}"
    );
    let mkv = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(mkv, inner, "extracted bytes differ after prefetch-covered repair");
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_connection_recovers() {
    let mut fx = Fixture::new("stall");
    let data = payload(400_000, 9);
    fx.add_file("s.bin", &data, 40_000);
    let victim = fx.articles.keys().next().unwrap().clone();
    let chaos = Chaos {
        stall: [victim].into(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_READ_TIMEOUT_SECS", "2")])
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/s.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn stall_watchdog_breaks_a_wedged_pool() {
    // A pool bug can leave an article non-terminal, wedging the whole job
    // AFTER its bytes download - fetch_all_multi never returns, silently
    // (seen on a 190 GB low-memory run: 3 h frozen, no output). Model the
    // frozen state with a body delay far longer than the watchdog window:
    // no bytes decode, work stays outstanding, and the watchdog must dump
    // pool state and abort so the process RETURNS (fails loud, resumable)
    // instead of hanging. Without the watchdog this job would only return
    // when the 20 s delay elapsed - the assertions below (a stall report +
    // a pool dump, and a non-success exit) are true only if it fired.
    let mut fx = Fixture::new("stallwd");
    let data = payload(400_000, 21);
    fx.add_file("w.bin", &data, 40_000);
    let chaos = Chaos {
        delay_ms: 20_000, // no body arrives within the watchdog window
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(
            &cfg,
            &nzb,
            &out,
            &[
                // > 5 s so the fire lands past the pool dump's startup
                // rate-limit; still well under the 20 s body delay.
                ("NZBFAST_STALL_ABORT_SECS", "8"),
                ("NZBFAST_READ_TIMEOUT_SECS", "60"),
            ],
        )
    })
    .await
    .unwrap();

    assert!(!ok, "a wedged job must fail loud, not report success: {log}");
    assert!(log.contains("download stalled"), "watchdog should report the stall: {log}");
    assert!(log.contains("[pool-debug]"), "watchdog should dump pool state: {log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_segment_id_completes_without_hanging() {
    // TODO §7: a malformed NZB repeating a <segment> id charged the pool's
    // `pending` per occurrence but credited per id - the job sat at ~100%
    // forever and only abort() escaped. Deduped (main.rs build loop + the
    // pool's own guard), the job must simply complete with correct bytes.
    // The stall-watchdog backstop turns any regression into a fast loud
    // failure instead of a 3-minute hang.
    let mut fx = Fixture::new("dupseg");
    let data = payload(400_000, 13);
    fx.add_file("d.bin", &data, 40_000);
    let dup = fx.nzb_files[0].1[2].clone();
    fx.nzb_files[0].1.push(dup);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_STALL_ABORT_SECS", "10")])
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("repeats 1 segment id"), "dedupe notice missing:\n{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert!(!log.contains("download stalled"), "watchdog fired - dedupe regressed:\n{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/d.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_id_across_files_repairs_the_shorted_file() {
    // The nastier duplicate shape: one message-id listed by TWO files. The
    // first file owns the article (its bytes land there); the second file
    // genuinely lacks that segment, is reported missing - not hung - and
    // PAR2 repair fills the hole.
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("dupx");
    let a = payload(300_000, 17);
    let b = payload(300_000, 23);
    fx.add_file("a.bin", &a, 40_000);
    fx.add_file("b.bin", &b, 40_000);
    assert!(fx.add_par2(20, &["a.bin", "b.bin"], 40_000));
    // b.bin's 3rd segment now claims a.bin's 3rd article id; b's real
    // article for that span is unreferenced and never fetched.
    fx.nzb_files[1].1[2].0 = fx.nzb_files[0].1[2].0.clone();
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_STALL_ABORT_SECS", "10")])
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(!log.contains("download stalled"), "watchdog fired - dedupe regressed:\n{log}");
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/a.bin")).unwrap(), a, "a.bin bytes differ");
    assert_eq!(std::fs::read(fx.dir.join("out/b.bin")).unwrap(), b, "b.bin bytes differ");
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_connections_reconnect() {
    let mut fx = Fixture::new("drop");
    let data = payload(800_000, 11);
    fx.add_file("d.bin", &data, 30_000);
    let chaos = Chaos {
        drop_after: 3, // every connection dies after 3 bodies
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/d.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn truncated_bodies_retry() {
    let mut fx = Fixture::new("trunc");
    let data = payload(300_000, 13);
    fx.add_file("t.bin", &data, 30_000);
    // Two servers: A truncates one article mid-body (connection cut);
    // B is healthy - the requeue must land it.
    let victim = fx.articles.keys().next().unwrap().clone();
    let chaos_a = Chaos {
        truncate: [victim].into(),
        ..Default::default()
    };
    let srv_a = MockServer::start(fx.articles.clone(), chaos_a).await;
    let srv_b = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv_a, &srv_b]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/t.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn compressed_rar_falls_back_and_unrars() {
    // Opt-in: needs working rar + unrar + par2. RARLab binaries stall in
    // Gatekeeper assessment on headless Macs (observed: dyld_start hang
    // even de-quarantined + ad-hoc signed), so this never probes them -
    // set NZBFAST_TEST_RAR=1 on a machine where `rar` is known-good.
    // The unrar invocation itself is validated in situ on the bench
    // machines (6.48 GB REMUX unpacked in 3.8 s via the bundled unrar).
    let have = |c: &str| {
        std::env::var_os("PATH").is_some_and(|p| {
            std::env::split_paths(&p).any(|d| d.join(c).is_file())
        })
    };
    if std::env::var_os("NZBFAST_TEST_RAR").is_none()
        || !have("rar")
        || !have("unrar")
        || !have_par2()
    {
        eprintln!("skipping: rar/unrar/par2 not all installed");
        return;
    }
    let mut fx = Fixture::new("compressed");
    let inner = payload(500_000, 19);
    std::fs::write(fx.dir.join("data.bin"), &inner).unwrap();
    // Compressed (-m3) multi-volume RAR5 set.
    let st = Command::new("rar")
        .args(["a", "-m3", "-v200k", "-ep", "arch", "data.bin"])
        .stdin(std::process::Stdio::null())
        .current_dir(&fx.dir)
        .output()
        .unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let mut vols: Vec<String> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().to_string_lossy().to_string();
            n.ends_with(".rar").then_some(n)
        })
        .collect();
    vols.sort();
    assert!(vols.len() >= 2, "expected multi-volume, got {vols:?}");
    std::fs::remove_file(fx.dir.join("data.bin")).unwrap();
    for v in &vols {
        let bytes = std::fs::read(fx.dir.join(v)).unwrap();
        std::fs::write(fx.dir.join(v), &bytes).unwrap();
        let tag = format!("{}-{}", v.replace('.', "_"), fx.nzb_files.len());
        let segs = make_file_articles(v, &bytes, 60_000, &tag, &mut fx.articles);
        fx.nzb_files.push((v.clone(), segs));
    }
    let vol_refs: Vec<&str> = vols.iter().map(String::as_str).collect();
    assert!(fx.add_par2(15, &vol_refs, 60_000));

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("compressed"), "no fallback notice:\n{log}");
    assert!(log.contains("unrar complete"), "unrar didn't run:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/data.bin")).unwrap(),
        inner,
        "unpacked bytes differ"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_flags_impossible() {
    let mut fx = Fixture::new("impossible");
    let data = payload(500_000, 15);
    fx.add_file("gone.bin", &data, 40_000);
    // Every article missing on the only server; no recovery volumes.
    let chaos = Chaos {
        missing: fx.articles.keys().cloned().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();

    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_nzbfast"))
            .env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("check")
            .arg(&nzb)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let log = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(log.contains("IMPOSSIBLE"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn kill9_resume_completes_without_refetching_everything() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Big enough that a mid-download SIGKILL leaves real progress behind.
    let mut fx = Fixture::new("resume");
    let data = payload(3_000_000, 21);
    fx.add_file("big.bin", &data, 25_000); // 120 articles
    assert!(fx.add_par2(10, &["big.bin"], 25_000));
    let total_articles = fx.articles.len() as u64;
    // Paced for the same reason as the direct-extract sibling below: an
    // unpaced server on a busy machine can finish all 120 articles before
    // the poll loop ever sees 40%, and a kill after completion leaves
    // nothing to resume.
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos { delay_ms: 10, ..Chaos::default() },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Run 1: kill -9 once ~40% of the articles have been served AND the
    // journal has recorded real progress for run 2 to resume from.
    {
        let cfg = cfg.clone();
        let nzb = nzb.clone();
        let out = out.clone();
        let served = served.clone();
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--connections")
                .arg("2")
                .arg("--window")
                .arg("2")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let journal = out.join(".nzbfast.journal");
            while served.load(std::sync::atomic::Ordering::Relaxed) < total_articles * 2 / 5
                || !std::fs::read_to_string(&journal).is_ok_and(|s| s.lines().count() > 1)
            {
                if std::time::Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            child.kill().unwrap(); // SIGKILL
            let _ = child.wait();
        })
        .await
        .unwrap();
    }
    let served_run1 = served.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        served_run1 >= total_articles * 2 / 5,
        "run 1 made no progress ({served_run1}/{total_articles})"
    );

    // Run 2: must resume, complete, verify clean, and not refetch what
    // run 1 already journaled.
    let (log, ok) = {
        let cfg = cfg.clone();
        let nzb = nzb.clone();
        let out = out.clone();
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log}");
    assert!(log.contains("resuming:"), "no resume banner:\n{log}");
    assert!(
        log.contains("clean download") || log.contains("repair complete"),
        "{log}"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/big.bin")).unwrap(), data);
    let served_total = served.load(std::sync::atomic::Ordering::Relaxed);
    let refetched = served_total - served_run1;
    // In-flight-at-kill articles (≤ conns × window + channel slack) may
    // refetch; the bulk must not.
    assert!(
        refetched < total_articles,
        "resume refetched everything ({refetched}/{total_articles})"
    );
    // Journal removed after the verified finish.
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// The 2026-07 bench4 "honest loss": kill -9 mid-download of a store-mode
/// RAR job being DIRECT-EXTRACTED. The bytes land in the extracted inner
/// file, not in any volume file, so the v1 journal covered nothing and a
/// resume refetched the whole pre-kill payload (15.3 GB vs NZBGet's
/// 0.2 GB). The placement journal must record where each article's bytes
/// physically went, the resume must copy them back into volume files
/// instead of refetching, and PAR2 must verify every restored byte.
#[tokio::test(flavor = "multi_thread")]
async fn kill9_resume_direct_extract_refetches_little() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("resume-rar");
    let inner = payload(3_000_000, 33);
    let n_vols = 4;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    // WinRAR-true: volume 0's piece is one byte longer than the rest.
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i == 0 {
            per + 1
        } else if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    {
        let names: Vec<&str> = vol_names.iter().map(String::as_str).collect();
        assert!(fx.add_par2(20, &names, 25_000), "par2 create failed");
    }
    let total_articles = fx.articles.len() as u64;
    // Pace the network so decode and placement keep up with the request
    // counter. Unpaced, a machine busy with the rest of the suite can
    // serve 40% of the articles while the client has journaled nothing,
    // and the kill lands before the first placement record exists.
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos { delay_ms: 10, ..Chaos::default() },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Run 1: kill -9 once ~40% of the articles have been served AND the
    // direct extractor has journaled at least one placement.
    {
        let cfg = cfg.clone();
        let nzb = nzb.clone();
        let out = out.clone();
        let served = served.clone();
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--connections")
                .arg("2")
                .arg("--window")
                .arg("2")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let journal = out.join(".nzbfast.journal");
            while served.load(std::sync::atomic::Ordering::Relaxed) < total_articles * 2 / 5
                || !std::fs::read_to_string(&journal)
                    .is_ok_and(|s| s.lines().any(|line| line.starts_with("R ")))
            {
                if std::time::Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            child.kill().unwrap(); // SIGKILL
            let _ = child.wait();
        })
        .await
        .unwrap();
    }
    let served_run1 = served.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        served_run1 >= total_articles * 2 / 5,
        "run 1 made no progress ({served_run1}/{total_articles})"
    );
    // The core of the fix: direct-extracted articles ARE journal-covered
    // (placement lines). Pre-fix this count was zero.
    let journal_txt = std::fs::read_to_string(fx.dir.join("out/.nzbfast.journal")).unwrap();
    let placed_run1 = journal_txt.lines().filter(|l| l.starts_with("R ")).count() as u64;
    assert!(
        placed_run1 > 0,
        "no placement records after kill - direct-extracted articles not journaled:\n{journal_txt}"
    );

    // Run 2: restore instead of refetch, verify, re-extract.
    let (log, ok) = {
        let cfg = cfg.clone();
        let nzb = nzb.clone();
        let out = out.clone();
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log}");
    assert!(log.contains("resume: restored"), "no restore banner:\n{log}");
    assert!(log.contains("resuming:"), "no resume banner:\n{log}");
    assert!(
        log.contains("clean download") || log.contains("repair complete"),
        "{log}"
    );
    // Every journal-placed article was restored, not refetched: run 2's
    // article count stays within the un-journaled remainder (+1 slack for
    // a served-but-undecoded article at the kill boundary).
    let refetched = served.load(std::sync::atomic::Ordering::Relaxed) - served_run1;
    assert!(
        refetched <= total_articles - placed_run1 + 1,
        "resume refetched journaled articles ({refetched} of {total_articles}, {placed_run1} were placed)"
    );
    // End state: extracted output byte-identical, volumes cleaned up,
    // journal gone after the verified finish.
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    for v in &vol_names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} left behind after re-extraction:\n{log}"
        );
    }
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// Plaintext-once phase 2, end to end: an encrypted store set decrypts
/// in-stream (the default), its articles journal as D records once
/// their seams settle, and a SIGKILL mid-download resumes by
/// RE-ENCRYPTING the on-disk plaintext back into posted volume bytes -
/// refetching only what was never journaled. No PAR2 on purpose: the
/// restored bytes must be right on their own, and the final payload
/// equality is the proof.
#[tokio::test(flavor = "multi_thread")]
async fn kill9_resume_instream_encrypted_refetches_little() {
    let mut fx = Fixture::new("resume-enc-d");
    let inner = payload(6_000_000, 91);
    let enc = fixtures::encrypt_file("hunter2", &inner, 27);
    let cipher = enc.cipher.clone();
    let n_vols = 3;
    let per = cipher.len() / n_vols;
    for i in 0..n_vols {
        let end = if i == n_vols - 1 { cipher.len() } else { (i + 1) * per };
        let vol = fixtures::rar5_volume_enc(
            &[("movie.mkv", &enc, i * per..end, i > 0, i < n_vols - 1)],
            Some(i as u64),
        );
        fx.add_file(&format!("e.part{}.rar", i + 1), &vol, 25_000);
    }
    let total_articles = fx.articles.len() as u64;
    // Pace the network enough for decode/seam settlement to run before
    // the request counter reaches the kill threshold. Without this the
    // loop below can kill a fast local run after BODY writes complete but
    // before any decoder has had a chance to emit its first D record.
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos { delay_ms: 10, ..Chaos::default() },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Run 1: kill -9 once ~60% of the articles have been served.
    {
        let (cfg, nzb, out, served) = (cfg.clone(), nzb.clone(), out.clone(), served.clone());
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--password")
                .arg("hunter2")
                .arg("--connections")
                .arg("2")
                .arg("--window")
                .arg("2")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let journal = out.join(".nzbfast.journal");
            while served.load(std::sync::atomic::Ordering::Relaxed) < total_articles * 3 / 5
                || !std::fs::read_to_string(&journal)
                    .is_ok_and(|s| s.lines().any(|line| line.starts_with("D ")))
            {
                if std::time::Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            child.kill().unwrap();
            let _ = child.wait();
        })
        .await
        .unwrap();
    }
    let served_run1 = served.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        served_run1 >= total_articles * 3 / 5,
        "run 1 made no progress ({served_run1}/{total_articles})"
    );
    // The point of phase 2: in-stream decrypted articles ARE journaled
    // (D records), with their E facts alongside.
    let journal_txt = std::fs::read_to_string(fx.dir.join("out/.nzbfast.journal")).unwrap();
    let placed_run1 = journal_txt.lines().filter(|l| l.starts_with("D ")).count() as u64;
    assert!(
        placed_run1 > 0,
        "no D records after kill - plaintext-once articles not journaled:\n{journal_txt}"
    );
    assert!(
        journal_txt.lines().any(|l| l.starts_with("E ")),
        "no E record:\n{journal_txt}"
    );

    // Run 2: restore by re-encryption, refetch only the remainder.
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || {
            let o = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--password")
                .arg("hunter2")
                .arg("--connections")
                .arg("4")
                .arg("--window")
                .arg("3")
                .output()
                .unwrap();
            (
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
                o.status.success(),
            )
        })
        .await
        .unwrap()
    };
    assert!(ok, "{log}");
    assert!(log.contains("resume: restored"), "no restore banner:\n{log}");
    let refetched = served.load(std::sync::atomic::Ordering::Relaxed) - served_run1;
    assert!(
        refetched <= total_articles - placed_run1 + 2,
        "resume refetched journaled articles ({refetched} of {total_articles}, {placed_run1} placed)"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// Finding A8, end to end with the real binary and a real SIGKILL.
///
/// An encrypted RAR5 STORE set direct-extracts as ciphertext at plain
/// store offsets, and the placement journal records the articles as living
/// in that output file. The finish decrypt then replaces those bytes with
/// plaintext. When it did so IN PLACE, a kill mid-pass left the file half
/// plaintext and half ciphertext with the journal still calling it
/// authoritative - and the resume copied the poisoned bytes into the
/// volume files and marked the message ids restored, so they were never
/// refetched. There is no PAR2 here on purpose: that is the shape where
/// nothing downstream would ever notice, and the retry can loop forever on
/// local garbage while the provider still holds every original article.
///
/// The kill is aimed at the decrypt window (spin until the pass's scratch
/// file or the journal's retirement line appears), but the assertion does
/// not depend on hitting it: whatever instant the kill caught, the output
/// on disk must be wholly one thing or the other, and run 2 must produce
/// the exact payload.
#[tokio::test(flavor = "multi_thread")]
async fn kill9_mid_decrypt_never_resumes_from_poisoned_bytes() {
    let mut fx = Fixture::new("resume-enc");
    let inner = payload(6_000_000, 71);
    let enc = fixtures::encrypt_file("hunter2", &inner, 17);
    let cipher = enc.cipher.clone();
    let n_vols = 3;
    let per = cipher.len() / n_vols;
    for i in 0..n_vols {
        let end = if i == n_vols - 1 { cipher.len() } else { (i + 1) * per };
        let vol = fixtures::rar5_volume_enc(
            &[("movie.mkv", &enc, i * per..end, i > 0, i < n_vols - 1)],
            Some(i as u64),
        );
        fx.add_file(&format!("e.part{}.rar", i + 1), &vol, 25_000);
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let journal = out.join(".nzbfast.journal");
    let movie = out.join("movie.mkv");

    // Run 1: SIGKILL as close to the decrypt as the test can aim.
    let caught = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let (served, journal) = (served.clone(), journal.clone());
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                // This test guards the LEGACY finish-decrypt's kill
                // ordering (temp + barrier + rename). The default
                // plaintext-once path has no decrypt scratch to catch -
                // its articles are simply never journaled.
                .env("NZBFAST_NO_INSTREAM_DECRYPT", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--password")
                .arg("hunter2")
                .arg("--connections")
                .arg("2")
                .arg("--window")
                .arg("2")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            let mut caught = "deadline";
            loop {
                if std::time::Instant::now() > deadline {
                    break;
                }
                // Decrypt scratch on disk = the pass is running right now.
                let scratch = std::fs::read_dir(&out).into_iter().flatten().flatten().any(|e| {
                    e.file_name().to_string_lossy().starts_with(".nzbfast-dec.")
                });
                if scratch {
                    caught = "mid-decrypt";
                    break;
                }
                // Retirement line = the barrier cleared, publish imminent.
                if std::fs::read_to_string(&journal)
                    .is_ok_and(|t| t.lines().any(|l| l.starts_with("X ")))
                {
                    caught = "post-barrier";
                    break;
                }
                if child.try_wait().unwrap().is_some() {
                    caught = "already exited";
                    break;
                }
                if served.load(std::sync::atomic::Ordering::Relaxed) >= total_articles {
                    std::thread::yield_now();
                }
            }
            let _ = child.kill(); // SIGKILL
            let _ = child.wait();
            caught
        })
        .await
        .unwrap()
    };
    eprintln!("kill landed: {caught}");

    // Whatever instant the kill caught, the output is never a mix. Either
    // it is still the ciphertext the journal describes (so a resume reads
    // local bytes), or it is the published plaintext and the journal has
    // stopped claiming it (so those articles refetch).
    if movie.exists() {
        let on_disk = std::fs::read(&movie).unwrap();
        let retired = std::fs::read_to_string(&journal)
            .is_ok_and(|t| t.lines().any(|l| l.trim() == "X movie.mkv"));
        let is_cipher = on_disk.len() >= cipher.len() && on_disk[..cipher.len()] == cipher[..];
        let is_plain = on_disk == inner;
        assert!(
            is_cipher || is_plain,
            "movie.mkv is neither intact ciphertext nor the finished plaintext \
             (len {}, kill landed {caught}) - a half-decrypted file is exactly \
             what poisons the resume",
            on_disk.len()
        );
        assert!(
            !is_cipher || !retired,
            "the journal retired its claim before the bytes were published"
        );
        assert!(
            !is_plain || retired || !journal.exists(),
            "plaintext is published but the journal still claims it is the \
             recorded ciphertext - a resume would restore poisoned bytes"
        );
    }

    // Run 2: resume, and land the exact payload. A restore that trusted
    // half-decrypted bytes would produce a corrupt movie.mkv here (with no
    // PAR2 to catch it) or spin without ever converging.
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || {
            let o = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .env("NZBFAST_NO_INSTREAM_DECRYPT", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--password")
                .arg("hunter2")
                .arg("--connections")
                .arg("4")
                .arg("--window")
                .arg("3")
                .output()
                .unwrap();
            (
                String::from_utf8_lossy(&o.stdout).to_string()
                    + &String::from_utf8_lossy(&o.stderr),
                o.status.success(),
            )
        })
        .await
        .unwrap()
    };
    assert!(ok, "resume after a mid-decrypt kill failed:\n{log}");
    assert_eq!(
        std::fs::read(&movie).unwrap(),
        inner,
        "resumed output is not the exact payload:\n{log}"
    );
    assert!(!journal.exists(), "journal survived a verified finish:\n{log}");
    assert!(
        std::fs::read_dir(&out)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".nzbfast-dec.")),
        "decrypt scratch left in the output directory"
    );
}

/// M14e tiers: a level-1 fill server serves ONLY the articles the
/// level-0 primary 430s - pay-per-GB economics enforced by the gate.
#[tokio::test(flavor = "multi_thread")]
async fn fill_server_fetches_only_missing() {
    let mut fx = Fixture::new("tiers");
    let data = payload(400_000, 21);
    fx.add_file("t.bin", &data, 40_000);
    let all_ids: Vec<String> = fx.articles.keys().cloned().collect();
    let n_total = all_ids.len() as u64;
    // Primary is missing exactly 3 articles.
    let mut chaos_a = Chaos::default();
    for id in all_ids.iter().take(3) {
        chaos_a.missing.insert(id.clone());
    }
    let srv_a = MockServer::start(fx.articles.clone(), chaos_a).await;
    let srv_b = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg_path = fx.dir.join("config.json");
    std::fs::write(
        &cfg_path,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}},{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"level\":1}}]}}",
            srv_a.addr.ip(),
            srv_a.addr.port(),
            srv_b.addr.ip(),
            srv_b.addr.port()
        ),
    )
    .unwrap();
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg_path, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/t.bin")).unwrap(), data);
    let a = srv_a.served.load(std::sync::atomic::Ordering::Relaxed);
    let b = srv_b.served.load(std::sync::atomic::Ordering::Relaxed);
    // The fill server may pick up a stale-article dup at the tail, but
    // must never take bulk work (primary was missing only 3).
    assert!(b <= 5, "fill server served {b} of {n_total} (primary {a})");
    assert!(a >= n_total - 3, "primary under-served: {a} of {n_total}");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_everywhere_reported_not_hung() {
    // A missing article with NO par2: the download must terminate and
    // report, not hang (termination-race regression guard).
    let mut fx = Fixture::new("missing");
    let data = payload(300_000, 17);
    fx.add_file("m.bin", &data, 30_000);
    let victim = fx.articles.keys().next().unwrap().clone();
    let chaos = Chaos {
        missing: [victim].into(),
        ..Default::default()
    };
    let srv_a = MockServer::start(fx.articles.clone(), chaos.clone()).await;
    let srv_b = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv_a, &srv_b]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    // Terminates (doesn't hang) AND exits nonzero: an incomplete,
    // unrepairable download must read as FAILED (M14b - an *arr importing
    // a holey file would be worse than the hang this test guards against).
    assert!(!ok, "incomplete download must exit nonzero\n{log}");
    assert!(log.contains("1 missing"), "{log}");
    assert!(log.contains("download incomplete"), "{log}");
}

/// A wholly dead post must be DRIVEN to terminal-missing, not abandoned
/// by the stall watchdog.
///
/// 31 Jul, live: a 30-day-old post whose every article was gone (a STAT
/// probe found 0 of 306 alive on any of five servers) failed a manual
/// retry as "the connection pool stalled ... this is a fault on THIS
/// machine or its link, not evidence that anything is missing from the
/// post - most of the outstanding articles were never requested". Both
/// halves were wrong: the post really was missing, and the pool had not
/// wedged. The watchdog had aborted a run that was working perfectly.
///
/// The watchdog's freeze signal is DECODED BYTES, and a dead post decodes
/// zero bytes by definition - for as long as it takes to ask every server
/// for every article. `outstanding` was falling the whole time, which is
/// the pool making steady progress, but nothing reads it that way, so any
/// dead post whose 430 ladder outlasts the window is aborted mid-queue
/// and then described as a fault on the user's own machine.
///
/// Scaled down here (a short window, a 430 that costs a round trip like a
/// real one) but identical in shape: the run must ask for every article
/// and return the missing verdict, never the stall.
#[tokio::test(flavor = "multi_thread")]
async fn dead_post_is_driven_to_missing_not_abandoned_as_a_stall() {
    let mut fx = Fixture::new("deadpost-stall");
    let data = payload(2_000_000, 41);
    fx.add_file("gone.bin", &data, 10_000); // 200 articles
    // Old enough to be a takedown rather than a propagation gap.
    fx.date = unix_now() - 30 * 86_400;
    // Every article 430s everywhere, and each refusal costs a round trip.
    // 200 articles at 80 ms, 4 connections 3 deep, is many seconds of pure
    // refusals - well past the 1 s window set below, with zero bytes
    // decoded throughout. That ratio is the live one: the real post's 430
    // ladder simply outlasted the default 180 s.
    let chaos = Chaos {
        missing: fx.articles.keys().cloned().collect(),
        missing_delay_ms: 80,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let n_articles = fx.articles.len();

    // Run twice: the second resumes from the journal, which is how the
    // live case was hit (a manual retry of a job that already failed).
    for pass in 1..=2 {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let (log, ok) = tokio::task::spawn_blocking(move || {
            run_get(&cfg, &nzb, &out, &[("NZBFAST_STALL_ABORT_SECS", "1")])
        })
        .await
        .unwrap();
        assert!(!ok, "pass {pass}: a dead post must exit nonzero\n{log}");
        assert!(
            !log.contains("download stalled"),
            "pass {pass}: the watchdog aborted a run that was resolving \
             articles steadily - a dead post decodes zero bytes by \
             definition, which is not a wedge:\n{log}"
        );
        assert!(
            !log.contains("recovered from a stalled pool"),
            "pass {pass}: the tail was abandoned:\n{log}"
        );
        // The verdict has to be about the post, not about this machine.
        assert!(
            !log.contains("fault on THIS machine"),
            "pass {pass}: a genuinely dead post was blamed on the user's \
             own link:\n{log}"
        );
    }
    // Every article was actually ASKED for - the live message's "most of
    // the outstanding articles were never requested" is the tell that the
    // queue was abandoned rather than driven to terminal.
    let asked: std::collections::HashSet<String> =
        srv.body_log.lock().unwrap().iter().cloned().collect();
    assert_eq!(
        asked.len(),
        n_articles,
        "only {} of {n_articles} article(s) were ever requested - the run \
         gave up on the rest",
        asked.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_routes_old_post_around_short_server() {
    // Both servers carry every article, but server A's retention (10 days)
    // can't cover a 30-day-old post - it must serve ZERO bodies while B
    // (unlimited) serves everything (M14e per-server retention routing).
    let mut fx = Fixture::new("retention-old");
    let data = payload(2_000_000, 23);
    fx.add_file("old.bin", &data, 20_000); // 100 articles
    fx.date = unix_now() - 30 * 86_400;
    let srv_a = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let srv_b = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config_retention(&[(&srv_a, 10), (&srv_b, 0)]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert_eq!(
        srv_a.served.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "retention-excluded server must serve zero bodies:\n{log}"
    );
    assert!(srv_b.served.load(std::sync::atomic::Ordering::Relaxed) > 0);
    assert_eq!(std::fs::read(fx.dir.join("out/old.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_fresh_post_uses_short_retention_server() {
    // Same pair of servers, but the post is fresh - the 10-day server is
    // back inside its window and must take a share of the bulk again.
    let mut fx = Fixture::new("retention-fresh");
    let data = payload(2_000_000, 29);
    fx.add_file("fresh.bin", &data, 20_000); // 100 articles
    fx.date = unix_now();
    let srv_a = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let srv_b = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config_retention(&[(&srv_a, 10), (&srv_b, 0)]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("all 1 files complete"), "{log}");
    assert!(
        srv_a.served.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "short-retention server must serve fresh posts:\n{log}"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/fresh.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_unservable_everywhere_reports_missing_not_hung() {
    // Every configured server is retention-excluded for this old post:
    // articles must be reported Missing immediately (never requested,
    // no hang on a queue nobody can pop).
    let mut fx = Fixture::new("retention-none");
    let data = payload(300_000, 31);
    fx.add_file("gone.bin", &data, 30_000);
    fx.date = unix_now() - 30 * 86_400;
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config_retention(&[(&srv, 10)]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    // Terminates promptly AND fails loudly (an unservable post is an
    // incomplete download - same contract as missing_everywhere).
    assert!(!ok, "unservable download must exit nonzero\n{log}");
    assert!(log.contains("missing"), "{log}");
    assert_eq!(
        srv.served.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "no BODY may be issued for unservable articles:\n{log}"
    );
}

/// M15: a tiny --mem-limit must degrade to settle read-back, never to
/// swap or failure. A single 20 MB PAR2 block straddles every article,
/// and the 64 MB budget's ~19 MB partials slice can never buffer it -
/// live verification must spill it to settle read-back, and the job must
/// STILL complete verified and byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn tiny_mem_budget_spills_and_completes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("membudget");
    let data = payload(30_000_000, 23);
    fx.add_file("big.bin", &data, 300_000);
    // ONE 20 MB block: it can never fit the 64M budget's ~19 MB partials
    // slice, so spill is deterministic regardless of arrival order.
    assert!(
        fx.add_par2_opts(5, Some(30_000_000), &["big.bin"], 300_000),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Full-MD5 mode: boundary blocks are held as BYTES, so the 20 MB
    // block can't fit the budget slice and must spill to read-back.
    // (The default fast mode no longer buffers bytes at all - see the
    // companion test below.)
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(
            &cfg,
            &nzb,
            &out,
            &[("NZBFAST_FAST_VERIFY", "0")],
            &["--mem-limit", "64M"],
        )
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    // The budget forced spill (blocks left for read-back)…
    let spilled: u64 = log
        .split(" blocks to read-back")
        .next()
        .and_then(|pre| pre.rsplit('(').next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    assert!(spilled > 0, "expected partial-buffer spill under 64M budget:\n{log}");
    // …verification still passed without repair…
    assert!(log.contains("clean download - no repair"), "{log}");
    assert!(log.contains("mem: peak RSS"), "{log}");
    // …and the bytes are perfect.
    assert_eq!(std::fs::read(fx.dir.join("out/big.bin")).unwrap(), data);
}

/// B1: the same 20 MB-block set under the same 64 M budget, default
/// (fast) verify - boundary fragments are tracked as composable CRC32s,
/// no bytes are buffered, so NOTHING spills and every block verifies
/// in-stream. This is the low-RAM win the CRC-parts design exists for.
#[tokio::test(flavor = "multi_thread")]
async fn tiny_mem_budget_fast_verify_never_spills() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("membudget-b1");
    let data = payload(30_000_000, 23);
    fx.add_file("big.bin", &data, 300_000);
    assert!(
        fx.add_par2_opts(5, Some(30_000_000), &["big.bin"], 300_000),
        "par2 create failed"
    );
    // A server that delivers at a plausible rate rather than at memcpy
    // speed. Trimming releases what the decoder has already READ, so a
    // mock that hands over 40 MB in 0.3 s is testing the case trimming
    // cannot help (arrivals outrunning decode, which correctly demotes),
    // not the case it exists for.
    let chaos = Chaos {
        delay_ms: 60,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "64M"])
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(
        log.contains("(0 blocks to read-back)"),
        "fast verify must hold zero bytes and spill nothing:\n{log}"
    );
    assert!(log.contains("clean download - no repair"), "{log}");
    assert!(log.contains(" 0 by read-back"), "settle still re-reading:\n{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/big.bin")).unwrap(), data);
}

/// B1 × M15b: the same oversized-block set, but activation is forced to
/// land LAST, so the backfill (not the decoders) feeds most of the block.
/// Backfilled spans are re-reads of bytes this run decoded under a passing
/// yEnc pcrc32, so they compose CRC parts exactly like fresh ones. Feeding
/// them as generic disk spans instead demanded a 30 MB byte buffer for the
/// block, blew the 19 MB partials slice of a 64 M budget, and dumped the
/// block back on settle read-back - the flake B1 showed whenever any
/// article happened to beat activation (4 of 6 runs, and on v1.0.6 too).
#[tokio::test(flavor = "multi_thread")]
async fn backfilled_spans_compose_crcs_under_a_tiny_budget() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("membudget-b1-backfill");
    let data = payload(30_000_000, 23);
    fx.add_file("big.bin", &data, 300_000);
    assert!(
        fx.add_par2_opts(5, Some(30_000_000), &["big.bin"], 300_000),
        "par2 create failed"
    );
    // Stall every par2-main article's first request: activation waits on
    // the 2 s read-timeout + retry, by which time the payload has landed.
    let par2_ids: Vec<String> = fx
        .nzb_files
        .iter()
        .filter(|(name, _)| name.ends_with(".par2"))
        .flat_map(|(_, segs)| segs.iter().map(|(id, _, _)| format!("<{id}>")))
        .collect();
    assert!(!par2_ids.is_empty());
    let chaos = Chaos {
        stall: par2_ids.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // --window 1 for the same reason as the M15b test below: pipelining
    // would trap big.bin's offset-0 segment behind the stalled par2
    // article on one connection.
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_win(
            &cfg,
            &nzb,
            &out,
            &[("NZBFAST_READ_TIMEOUT_SECS", "2")],
            &["--mem-limit", "64M"],
            1,
        )
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("backfilled"), "backfill never ran:\n{log}");
    assert!(
        log.contains("(0 blocks to read-back)"),
        "backfilled spans must compose CRCs, not buffer bytes:\n{log}"
    );
    assert!(log.contains(" 0 by read-back"), "settle still re-reading:\n{log}");
    assert!(log.contains("clean download - no repair"), "{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/big.bin")).unwrap(), data);
}

/// M15b: spans decoded BEFORE the PAR2 set activates are hashed by the
/// in-download backfill pass, not re-read at settle. Stalling the par2
/// main article's first request delays activation until every data
/// article has already landed - the worst case that used to re-read the
/// whole payload at settle must now settle with ZERO read-back.
#[tokio::test(flavor = "multi_thread")]
async fn pre_activation_spans_backfill_not_settle_readback() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("backfill");
    let data = payload(4_000_000, 27);
    fx.add_file("b.bin", &data, 60_000);
    assert!(fx.add_par2(10, &["b.bin"], 60_000), "par2 create failed");
    // Stall the FIRST request of every par2-main article: activation
    // can't happen until the 2 s read-timeout fires and the retry lands -
    // by which time the whole 4 MB payload has arrived pre-activation.
    let par2_ids: Vec<String> = fx
        .nzb_files
        .iter()
        .filter(|(name, _)| name.ends_with(".par2"))
        .flat_map(|(_, segs)| segs.iter().map(|(id, _, _)| format!("<{id}>")))
        .collect();
    assert!(!par2_ids.is_empty());
    let chaos = Chaos {
        stall: par2_ids.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // --window 1: with pipelining, b.bin's offset-0 segment (queued right
    // after the par2 main) can ride the SAME connection as the stalled
    // par2 article and sit trapped behind it for the whole 2 s. The slot
    // then can't classify, every decoded span is held in memory instead
    // of written, and if the par2 retry decodes before the offset-0 retry
    // the backfill's coverage gate skips everything (fed == 0, flaky).
    // One request per connection guarantees the offset-0 article lands on
    // a free connection immediately, so all pre-activation spans are on
    // disk by the time the set activates.
    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_win(&cfg, &nzb, &out, &[("NZBFAST_READ_TIMEOUT_SECS", "2")], &[], 1)
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("backfilled"), "backfill never ran:\n{log}");
    assert!(log.contains(" 0 by read-back"), "settle still re-reading:\n{log}");
    assert!(log.contains("clean download - no repair"), "{log}");
    assert_eq!(std::fs::read(fx.dir.join("out/b.bin")).unwrap(), data);
}

/// M7b.1: a `conntune.json` next to the config (written by the daemon's
/// idle ladder probes) caps a server's connections at the probed knee.
#[tokio::test(flavor = "multi_thread")]
async fn conntune_caps_connections() {
    let mut fx = Fixture::new("conntune");
    let data = payload(300_000, 21);
    fx.add_file("t.bin", &data, 40_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    std::fs::write(
        cfg.with_file_name("conntune.json"),
        format!(
            "{{\"{}\":{{\"connections\":1,\"granted\":1,\"gbps\":0.5,\"checked\":1,\"source\":\"auto\"}}}}",
            srv.addr.ip()
        ),
    )
    .unwrap();
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(
        log.contains("connection auto-tune: 127.0.0.1 1"),
        "tuned cap not applied:\n{log}"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/t.bin")).unwrap(), data);
}

/// M32 lean verify: article CRCs are skipped once PAR2 covers a slot,
/// so a corrupted article DECODES and lands - and the PAR2 block CRC32
/// (the single remaining in-stream layer) must catch it and repair to
/// byte-identical output. The accuracy trade is bounded, never absent.
#[tokio::test(flavor = "multi_thread")]
async fn lean_verify_catches_corruption_at_the_block_layer() {
    let mut fx = Fixture::new("lean");
    let data = payload(600_000, 9);
    fx.add_file("payload.bin", &data, 50_000);
    assert!(fx.add_par2(20, &["payload.bin"], 50_000));
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("payload_bin") && k.ends_with("-6@mock>"))
        .unwrap()
        .clone();
    let chaos = Chaos { corrupt: [victim].into(), ..Default::default() };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_OPEN", "1");
        cmd.arg("--config")
            .arg(&cfg)
            .arg("get")
            .arg(&nzb)
            .arg("--out")
            .arg(&out)
            .arg("--verify")
            .arg("lean")
            .arg("--connections")
            .arg("4");
        let o = cmd.output().expect("run nzbfast");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        (text, o.status.success())
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert!(log.contains("verify: lean"), "lean banner missing:\n{log}");
    assert!(log.contains("repair complete"), "block layer missed the corruption:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/payload.bin")).unwrap(),
        data,
        "repaired bytes differ"
    );
}

// ---------------------------------------------------------------------------
// Nested one-pass "worst case" gauntlet (spec: research/nested-one-pass-spec.md)
// ---------------------------------------------------------------------------

/// First byte offset of `needle` in `hay`, skipping `skip` earlier matches.
fn find_nth(hay: &[u8], needle: &[u8], skip: usize) -> Option<usize> {
    let mut seen = 0usize;
    let mut from = 0usize;
    while from + needle.len() <= hay.len() {
        let pos = hay[from..]
            .windows(needle.len())
            .position(|w| w == needle)?;
        let at = from + pos;
        if seen == skip {
            return Some(at);
        }
        seen += 1;
        from = at + 1;
    }
    None
}

impl Fixture {
    /// Bracketed message-id of the article that carries byte `off` of
    /// `file` (articles are fixed-size slices of the decoded bytes).
    fn seg_id_at(&self, file: &str, off: usize, art: usize) -> String {
        let (_, segs) = self
            .nzb_files
            .iter()
            .find(|(n, _)| n == file)
            .unwrap_or_else(|| panic!("no nzb file {file}"));
        let idx = off / art;
        format!("<{}>", segs[idx].0)
    }
}

/// Run `par2 create` over `files` inside `dir` and return the resulting
/// packet files as (name, bytes), removing them from `dir`. None = no
/// usable par2 binary (caller skips).
fn par2_create_collect(
    dir: &Path,
    base: &str,
    redundancy: u32,
    files: &[&str],
) -> Option<Vec<(String, Vec<u8>)>> {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg("-q")
        .arg(base)
        .args(files)
        .current_dir(dir)
        .status()
        .ok()?;
    if !st.success() {
        return None;
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    let mut out = Vec::new();
    for p in par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let bytes = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        out.push((name, bytes));
    }
    Some(out)
}

/// Gauntlet (a): a THREE-level store post - outer volumes wrapping a mid
/// RAR set wrapping one more archive wrapping the payload - with
/// articles lost at every level of the address space SIMULTANEOUSLY:
/// (i) innermost payload data, (ii) a level-1 volume's own RAR header
/// (the same article also takes out the outer entry header in front of
/// it), and (iii) an outer volume's mid-file entry header. All of it
/// heals through the outer PAR2 set's mapped in-stream repair - rebuilt
/// blocks re-enter via patch_volume_span and re-feed every parser down
/// the chain. Payload byte-exact, no archive from any level on disk, no
/// volume materialization, rc=0.
#[tokio::test(flavor = "multi_thread")]
async fn nested_three_level_triple_damage_repairs_in_stream() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("nest3dmg");
    // Full-entropy payload: the byte-search below locates the damage
    // targets, and the structured `payload()` pattern repeats - a 48-byte
    // marker from it can false-match near offset 0 and poison the sniff
    // article by accident.
    let mut prng = 0xdeadbeefcafef00du64;
    let final_payload: Vec<u8> = (0..200_000usize)
        .map(|_| {
            prng ^= prng << 13;
            prng ^= prng >> 7;
            prng ^= prng << 17;
            (prng >> 32) as u8
        })
        .collect();
    // Level 2: one archive holding the payload.
    let inner2 = fixtures::rar5_volume(&[("final.bin", 200_000, &final_payload, false, false)]);
    // Level 1: three volumes splitting that archive.
    let (t1, t2) = (inner2.len() / 3, 2 * inner2.len() / 3);
    let m = [
        fixtures::rar5_volume_n(
            &[("inner2.rar", inner2.len() as u64, &inner2[..t1], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("inner2.rar", inner2.len() as u64, &inner2[t1..t2], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("inner2.rar", inner2.len() as u64, &inner2[t2..], true, false)],
            2,
        ),
    ];
    // Level 0: two outer volumes; m.part2.rar spans the outer boundary.
    let cut = m[1].len() / 2;
    let o1 = fixtures::rar5_volume_n(
        &[
            ("m.part1.rar", m[0].len() as u64, &m[0][..], false, false),
            ("m.part2.rar", m[1].len() as u64, &m[1][..cut], false, true),
        ],
        0,
    );
    let o2 = fixtures::rar5_volume_n(
        &[
            ("m.part2.rar", m[1].len() as u64, &m[1][cut..], true, false),
            ("m.part3.rar", m[2].len() as u64, &m[2][..], false, false),
        ],
        1,
    );
    let art = 1500usize;
    fx.add_file("o.part1.rar", &o1, art);
    fx.add_file("o.part2.rar", &o2, art);
    assert!(
        fx.add_par2(30, &["o.part1.rar", "o.part2.rar"], art),
        "par2 create failed"
    );

    // (ii) inner header: m.part2.rar's own RAR header lives at the start
    // of o1's second entry DATA - the second "inner2.rar" occurrence in
    // o1 (the first is m1's header copy). The same article also carries
    // the outer entry header directly in front of it. Never article 0.
    let ih = find_nth(&o1, b"inner2.rar", 1).expect("m2 header in o1");
    assert!(ih / art > 0, "inner-header victim must not be the sniff article");
    // (iii) outer header: o2's second entry header (the only place the
    // string m.part3.rar appears in o2).
    let oh = find_nth(&o2, b"m.part3.rar", 0).expect("entry header in o2");
    assert!(oh / art > 0, "outer-header victim must not be the sniff article");
    // (i) innermost data: a payload slice that lands in o2's data area.
    let marker = &final_payload[120_000..120_048];
    let dm = find_nth(&o2, marker, 0).expect("payload marker in o2");
    assert!(find_nth(&o2, marker, 1).is_none(), "marker must be unique in o2");
    assert!(find_nth(&o1, marker, 0).is_none(), "marker must not appear in o1");
    assert!(dm / art > 0, "data victim must not be the sniff article");
    let victims = [
        fx.seg_id_at("o.part1.rar", ih, art),
        fx.seg_id_at("o.part2.rar", oh, art),
        fx.seg_id_at("o.part2.rar", dm, art),
    ];
    let uniq: std::collections::HashSet<&String> = victims.iter().collect();
    assert_eq!(uniq.len(), 3, "victims must be three distinct articles");

    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    // The repair must be the mapped in-stream path - no volume files.
    assert!(
        log.contains("(native, mapped:"),
        "repair did not take the mapped path:\n{log}"
    );
    assert!(
        !log.contains("materializing volumes for repair"),
        "volumes were materialized:\n{log}"
    );
    let got = std::fs::read(fx.dir.join("out/final.bin")).expect("payload extracted");
    assert_eq!(got, final_payload, "payload bytes differ after 3-level repair");
    for f in [
        "o.part1.rar",
        "o.part2.rar",
        "m.part1.rar",
        "m.part2.rar",
        "m.part3.rar",
        "inner2.rar",
    ] {
        assert!(
            !fx.dir.join("out").join(f).exists(),
            "{f} must never touch disk:\n{log}"
        );
    }
}

/// Gauntlet (b): a store outer wrapping [inner volumes damaged BEFORE
/// packing + the inner par2 set that can fix them] - the poster packed a
/// broken set together with its cure. The outer set verifies clean (the
/// damage IS the posted bytes); the level-1 volume with its signature
/// destroyed can't map, so the nested level demotes and materializes;
/// the disk post-pass must then run the INNER par2 set (skipping the
/// outer index whose volumes never touched disk), heal the volume, and
/// extract the payload. rc=0.
#[tokio::test(flavor = "multi_thread")]
async fn nested_inner_par2_repairs_poster_damaged_layer() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("nestinnerpar");
    let show = payload(300_000, 55);
    let iv = [
        fixtures::rar5_volume_n(
            &[("show.mkv", 300_000, &show[..100_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("show.mkv", 300_000, &show[100_000..200_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("show.mkv", 300_000, &show[200_000..], true, false)], 2),
    ];
    // The inner par2 set is created over the INTACT volumes...
    let scratch = fx.dir.join("innerset");
    std::fs::create_dir_all(&scratch).unwrap();
    for (i, v) in iv.iter().enumerate() {
        std::fs::write(scratch.join(format!("i.part{}.rar", i + 1)), v).unwrap();
    }
    let Some(inner_pars) = par2_create_collect(
        &scratch,
        "innerset",
        30,
        &["i.part1.rar", "i.part2.rar", "i.part3.rar"],
    ) else {
        eprintln!("skipping: par2 create unavailable");
        return;
    };
    assert!(
        inner_pars.iter().any(|(_, b)| b.len() > 20_000),
        "inner par2 set carries no recovery volumes"
    );
    // ...then the poster destroys the middle volume's signature bytes
    // (the archive is unrecognizable, not merely corrupt) and packs the
    // damaged set + its par2 files into the outer archive.
    let mut iv2 = iv[1].clone();
    iv2[..8].fill(0);
    let mut entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![
        ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
        ("i.part2.rar", iv2.len() as u64, &iv2, false, false),
        ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
    ];
    for (name, bytes) in &inner_pars {
        entries.push((name.as_str(), bytes.len() as u64, bytes, false, false));
    }
    let outer = fixtures::rar5_volume(&entries);
    fx.add_file("o.rar", &outer, 1500);
    assert!(fx.add_par2(20, &["o.rar"], 1500), "par2 create failed");

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    // The damaged level demoted (materialized), it did not fail the job.
    assert!(log.contains("nested fallback"), "no nested demotion:\n{log}");
    // The nested pass ran the INNER recovery set on disk.
    assert!(
        log.contains("nested PAR2: repaired"),
        "inner par2 did not repair:\n{log}"
    );
    let got = std::fs::read(fx.dir.join("out/show.mkv")).expect("payload extracted");
    assert_eq!(got, show, "payload bytes differ after inner par2 repair");
}

/// Gauntlet (b2), closing (b)'s residual gap: the poster-damaged store
/// inner set again - but this time only the DATA was damaged before
/// packing, every header intact. The nested level maps and one-pass
/// extracts cleanly as far as structure goes, so before the in-stream
/// CRC gate this shipped a silently corrupt payload with rc=0 (the
/// outer par2 verifies the damage as posted, and the packed inner par2
/// never got a look because its covered volumes never materialized).
/// Now the child checks its routed output against the RAR5 header CRCs
/// at finish, the mismatch demotes the level to materialized volumes,
/// and the disk post-pass runs the packed inner par2 set to heal them.
/// Payload byte-exact, rc=0.
#[tokio::test(flavor = "multi_thread")]
async fn nested_inner_par2_repairs_data_damaged_store_layer() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("nestdatapar");
    let show = payload(300_000, 56);
    let whole = crc32fast::hash(&show);
    // Header CRCs the way real archivers write them: earlier split
    // pieces carry their own bytes' CRC32, the last carries the whole
    // unpacked file's (the one the verifier checks).
    // WinRAR-true geometry, and it is load-bearing for what this test
    // asserts: volume 0's main header has no volume-number field, so it is
    // one byte shorter and must carry one byte MORE data for the volume
    // FILES to come out the same size. Three equal 100_000-byte pieces
    // (what this used to do) make volume 0's file a byte short, i.e. a
    // NON-uniform set - and then the arithmetic gate's uniform premise gets
    // contradicted and the group demotes with "non-uniform store set"
    // instead of reaching the stored-CRC gate this test is about. Both
    // demotions are correct and both end in the same repaired payload, so
    // which one fires was decided by how far parsing had progressed when
    // `reresolve` ran - i.e. by timing, which made the assertion below
    // host- and load-dependent (it flipped when the daemon moved onto a
    // sized main thread, and it passed under full-suite load while failing
    // in isolation on Windows). A genuinely uniform set cannot take the
    // arithmetic path's failure branch, so the CRC gate is the only
    // demotion left and the assertion is deterministic everywhere. The last
    // volume is allowed to be short, as in any real set.
    const DL: usize = 100_000;
    let (a, b) = (DL + 1, DL + 1 + DL);
    let mut iv = vec![
        fixtures::rar5_volume_n_crc(
            &[("show.mkv", 300_000, &show[..a], false, true,
               Some(crc32fast::hash(&show[..a])))],
            0,
        ),
        fixtures::rar5_volume_n_crc(
            &[("show.mkv", 300_000, &show[a..b], true, true,
               Some(crc32fast::hash(&show[a..b])))],
            1,
        ),
        fixtures::rar5_volume_n_crc(
            &[("show.mkv", 300_000, &show[b..], true, false, Some(whole))],
            2,
        ),
    ];
    // The premise above, checked rather than assumed: if the fixture helper
    // ever changes its header layout this must fail loudly here, not turn
    // back into a timing-dependent assertion further down.
    assert_eq!(
        iv[0].len(),
        iv[1].len(),
        "fixture is not a uniform store set - volume 0 and 1 files must be the same size, \
         or the arithmetic gate demotes before the CRC gate this test is about"
    );
    // The inner par2 set is created over the INTACT volumes...
    let scratch = fx.dir.join("innerset");
    std::fs::create_dir_all(&scratch).unwrap();
    for (i, v) in iv.iter().enumerate() {
        std::fs::write(scratch.join(format!("i.part{}.rar", i + 1)), v).unwrap();
    }
    let Some(inner_pars) = par2_create_collect(
        &scratch,
        "innerset",
        30,
        &["i.part1.rar", "i.part2.rar", "i.part3.rar"],
    ) else {
        eprintln!("skipping: par2 create unavailable");
        return;
    };
    assert!(
        inner_pars.iter().any(|(_, b)| b.len() > 20_000),
        "inner par2 set carries no recovery volumes"
    );
    // ...then the poster flips bytes deep inside the middle volume's
    // DATA area - its RAR headers (and the header CRC of the original
    // payload) stay intact - and packs the damaged set + its par2 files
    // into the outer archive.
    let mid = iv[1].len() / 2;
    for b in &mut iv[1][mid..mid + 64] {
        *b ^= 0xA5;
    }
    let mut entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![
        ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
        ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
        ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
    ];
    for (name, bytes) in &inner_pars {
        entries.push((name.as_str(), bytes.len() as u64, bytes, false, false));
    }
    let outer = fixtures::rar5_volume(&entries);
    fx.add_file("o.rar", &outer, 1500);
    assert!(fx.add_par2(20, &["o.rar"], 1500), "par2 create failed");

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    // The CRC gate demoted the damaged level (it did not fail the job,
    // and it did not ship the corrupt payload silently).
    assert!(log.contains("nested fallback"), "no nested demotion:\n{log}");
    assert!(
        log.contains("stored CRC"),
        "demotion did not come from the CRC gate:\n{log}"
    );
    // The nested pass ran the INNER recovery set on disk.
    assert!(
        log.contains("nested PAR2: repaired"),
        "inner par2 did not repair:\n{log}"
    );
    let got = std::fs::read(fx.dir.join("out/show.mkv")).expect("payload extracted");
    assert_eq!(got, show, "payload bytes differ after inner par2 repair");
}

/// Gauntlet (c): a store outer wrapping a COMPRESSED inner archive that
/// was damaged before packing but carries a RAR5 recovery record (and no
/// par2). The chase hits the corrupt packed stream, demotes, and
/// materializes the archive byte-exact; the disk post-pass exhausts
/// unrar, then the embedded recovery record rewrites the volume and
/// extraction succeeds. rc=0.
#[tokio::test(flavor = "multi_thread")]
async fn nested_recovery_record_heals_poster_damaged_inner() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Half-entropy payload: compresses ~2x, so the packed stream is real
    // LZ data and the corruption below lands inside it.
    let mut s = 0x9e3779b97f4a7c15u64;
    let doc: Vec<u8> = (0..300_000usize)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect();
    let mut features = rars::FeatureSet::store_only();
    features.recovery_record = true;
    let intact = rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::new(
        rars::ArchiveVersion::Rar50,
        features,
    ))
    .compressed_entries(&[rars::rar50::CompressedEntry {
        name: b"doc.bin",
        data: &doc,
        mtime: None,
        attributes: 0,
        host_os: 0,
    }])
    .recovery_percent(Some(20))
    .finish()
    .unwrap();
    // Damage the packed stream (headers end well before offset 300; the
    // packed member of a 300 KB half-entropy input runs >100 KB).
    let mut damaged = intact.clone();
    damaged[300..380].fill(0xa5);

    let mut fx = Fixture::new("nestrr");
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        damaged.len() as u64,
        &damaged[..],
        false,
        false,
    )]);
    fx.add_file("o.rar", &outer, 1500);
    assert!(fx.add_par2(20, &["o.rar"], 1500), "par2 create failed");

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("rewritten from recovery record"),
        "recovery-record repair did not run:\n{log}"
    );
    let got = std::fs::read(fx.dir.join("out/doc.bin")).expect("payload extracted");
    assert_eq!(got, doc, "payload bytes differ after RR self-repair");
}

/// Gauntlet (e): a PAR-ONLY post - the poster created a rar, generated a
/// 100%-redundancy par2 set, deleted the rar, and posted only the pars.
/// The NZB carries no data slots at all; the whole rar must be
/// reconstructed from recovery blocks alone, then re-extracted like any
/// repaired set. rc=0, payload byte-exact, no volume left behind.
#[tokio::test(flavor = "multi_thread")]
async fn par_only_post_reconstructs_rar_and_extracts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("paronly");
    let movie = payload(250_000, 71);
    let rar = fixtures::rar5_volume(&[("movie.mkv", 250_000, &movie, false, false)]);
    // On disk for par2 create only - never added as articles.
    std::fs::write(fx.dir.join("r.rar"), &rar).unwrap();
    // 4 KB blocks: 100% redundancy over default-sized (tiny) blocks
    // costs minutes of RS time for no extra coverage.
    assert!(
        fx.add_par2_opts(100, Some(4096), &["r.rar"], 30_000),
        "par2 create failed"
    );
    assert!(
        fx.nzb_files.iter().all(|(n, _)| n.ends_with(".par2")),
        "NZB must carry only par2 files"
    );

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("file missing entirely"),
        "whole-file loss not detected:\n{log}"
    );
    assert!(log.contains("repair complete"), "no repair ran:\n{log}");
    assert!(
        log.contains("re-extracting"),
        "reconstructed set was not re-extracted:\n{log}"
    );
    let got = std::fs::read(fx.dir.join("out/movie.mkv")).expect("payload extracted");
    assert_eq!(got, movie, "payload bytes differ after reconstruction");
    assert!(
        !fx.dir.join("out/r.rar").exists(),
        "reconstructed volume left behind:\n{log}"
    );
}

/// Par-only variant: the recovery set covers a bare payload file (no
/// archive). Reconstruction recreates the file itself; nothing to
/// extract afterwards. rc=0.
#[tokio::test(flavor = "multi_thread")]
async fn par_only_post_reconstructs_bare_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("paronlybare");
    let data = payload(180_000, 72);
    std::fs::write(fx.dir.join("p.bin"), &data).unwrap();
    assert!(
        fx.add_par2_opts(100, Some(4096), &["p.bin"], 30_000),
        "par2 create failed"
    );
    assert!(
        fx.nzb_files.iter().all(|(n, _)| n.ends_with(".par2")),
        "NZB must carry only par2 files"
    );

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("repair complete"), "no repair ran:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/p.bin")).expect("payload recreated"),
        data,
        "recreated payload differs"
    );
}

/// The CLI flow of the same par-only case: `nzbfast extract <dir>` on a
/// directory holding ONLY the par2 set (the data file deleted). The
/// offline pipeline must recreate the rar from recovery blocks and then
/// extract it. rc=0.
#[test]
fn extract_local_par_only_dir_recreates_and_extracts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-e2e-paronly-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let movie = payload(220_000, 73);
    let rar = fixtures::rar5_volume(&[("movie.mkv", 220_000, &movie, false, false)]);
    std::fs::write(dir.join("r.rar"), &rar).unwrap();
    let st = Command::new("par2")
        .arg("create")
        .arg("-s4096")
        .arg("-r100")
        .arg("-q")
        .arg("cliset")
        .arg("r.rar")
        .current_dir(&dir)
        .status()
        .expect("run par2");
    assert!(st.success(), "par2 create failed");
    std::fs::remove_file(dir.join("r.rar")).unwrap();

    let o = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_OPEN", "1")
        .arg("extract")
        .arg(&dir)
        .output()
        .expect("run nzbfast extract");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success(), "extract failed:\n{log}");
    assert_eq!(
        std::fs::read(dir.join("movie.mkv")).expect("payload extracted"),
        movie,
        "payload bytes differ after CLI reconstruction"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 37 step 1: a POSTED single-file `.7z` - no RAR around it, the
/// shape 3.3% of releases actually use. The chase now takes it at depth
/// 0, so its payload streams out while the archive downloads and the
/// `.7z` itself never touches disk. Before this, the badge said
/// `7z · unpacked after download` and the archive sat on disk waiting
/// for the post-pass.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7z");
    // Incompressible, like real payload: LZMA2 leaves it ~1:1, so the
    // posted archive is genuinely article-sized rather than a stub.
    let movie = incompressible(900_000, 41);
    let arch = sevenz_container(&[("movie.mkv", &movie)]);
    fx.add_file("release.7z", &arch, 60_000);
    assert!(fx.add_par2(10, &["release.7z"], 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    // The chase's byte count, which read "(0.0 MB)" here too until the
    // zip work surfaced it on a live post (31 Jul).
    assert!(
        !log.contains("in-stream (0.0 MB)"),
        "the in-stream summary lost its byte count:\n{log}"
    );
    assert!(log.contains("7z · one-pass"), "badge still says on-disk:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(
        !fx.dir.join("out/release.7z").exists(),
        "the archive must not touch disk"
    );
}

/// The same shape, damaged. A chased slot cannot take a mapped repair
/// (its bytes are in RAM, not a file par2 can patch), so the ladder must
/// materialize it first - which is the pre-TODO-37 end state - repair it
/// on disk, and let the 7z post-pass unpack it. The failure this pins is
/// silent and total: without the chased slot in the materialize sweep,
/// par2 finds no `release.7z` at all and calls the whole file missing.
#[tokio::test(flavor = "multi_thread")]
async fn damaged_top_level_7z_materializes_repairs_and_unpacks() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7zdmg");
    let movie = incompressible(900_000, 42);
    let arch = sevenz_container(&[("movie.mkv", &movie)]);
    fx.add_file("release.7z", &arch, 60_000);
    assert!(fx.add_par2(30, &["release.7z"], 60_000));
    // Two mid-archive articles vanish: enough damage to need repair,
    // well inside the 30% redundancy.
    let victims: Vec<String> = ["-3@mock>", "-5@mock>"]
        .iter()
        .map(|suffix| {
            fx.articles
                .keys()
                .find(|k| k.contains("release_7z") && k.ends_with(suffix))
                .unwrap_or_else(|| panic!("no {suffix} article: {:?}", fx.articles.len()))
                .clone()
        })
        .collect();
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        !log.contains("file missing entirely"),
        "par2 could not see the chased archive:\n{log}"
    );
    assert!(log.contains("materializing volumes for repair"), "{log}");
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("payload after repair"),
        movie,
        "payload differs after repair + post-pass"
    );
}

/// Payload LZMA2 cannot shrink (xorshift), so a 7z fixture's posted size
/// tracks its content size.
fn incompressible(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// An in-memory single-file `.7z`, LZMA2 default.
fn sevenz_container(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
    for &(n, d) in entries {
        w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(n), Some(d))
            .unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// TODO 37 step 2: an archive several times the retention cap streams
/// anyway. The chase drops the prefix the decoder has already read past
/// out of RAM and into the archive's own path as it goes, so what bounds
/// it is the live window rather than the whole file; on success that
/// partial spill is removed and the payload is the only thing left.
///
/// `--mem-limit 64M` floors the budget, which puts the extractor's
/// held-span ceiling at ~29 MB against a ~36 MB archive. Before
/// trimming, a job like this could only demote.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_over_the_cap_trims_and_still_streams() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7ztrim");
    // Store-codec 7z over incompressible payload - the shape the census
    // says dominates (already-compressed video), and the one where
    // decode keeps up with arrival so the trim watermark advances.
    let movie = incompressible(36 << 20, 43);
    let arch = sevenz_store_container(&[("movie.mkv", &movie)]);
    assert!(arch.len() > 36 << 20, "fixture too small: {}", arch.len());
    fx.add_file("release.7z", &arch, 700_000);
    // PAR2 stays on for this one: verifying a slot whose prefix has been
    // trimmed out from under it is the interaction most likely to break.
    assert!(fx.add_par2(5, &["release.7z"], 700_000));
    // A server that delivers at a plausible rate rather than at memcpy
    // speed. Trimming releases what the decoder has already READ, so a
    // mock that hands over 40 MB in 0.3 s is testing the case trimming
    // cannot help (arrivals outrunning decode, which correctly demotes),
    // not the case it exists for.
    //
    // 150ms rather than 60: this margin is what keeps the trim path the
    // branch that actually runs below. At 60 the suite's own parallel
    // load was enough to let arrivals outrun decode.
    let chaos = Chaos {
        delay_ms: 150,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "64M"])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    // True on either path: the payload is exact, and the archive - spilled
    // partially or materialized whole - does not outlive the job.
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(
        !fx.dir.join("out/release.7z").exists(),
        "the archive survived the job"
    );
    // Which path it took is a race, and the sibling test below says why
    // asserting on the winner is a mistake - it pins its own direction
    // with the kill switch for exactly this reason. Trimming only wins
    // while decode keeps up with arrivals; on a machine running the rest
    // of this suite in parallel it sometimes does not, and demoting then
    // is the DOCUMENTED right answer rather than a regression. Asserting
    // `!log.contains("held-bytes cap")` failed about one full-suite run
    // in six for that reason, while passing 10/10 on its own.
    //
    // So: assert the trim contract when trimming happened, the demotion
    // contract when it did not. The `delay_ms` margin above is what
    // keeps the first branch the usual one; the second exists so a busy
    // box reports the truth instead of a failure.
    if log.contains("held-bytes cap") {
        eprintln!(
            "note: arrivals outran decode, so this run covered the demotion \
             fallback rather than the trim path"
        );
        assert!(
            log.contains("7z unpack complete"),
            "demoted, but the disk post-pass never ran:\n{log}"
        );
    } else {
        assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
        assert!(log.contains("7z · one-pass"), "{log}");
    }
}

/// An in-memory single-file `.7z` with the payload STORED (Copy codec).
fn sevenz_store_container(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
    w.set_content_methods(vec![sevenz_rust2::EncoderConfiguration::new(
        sevenz_rust2::EncoderMethod::COPY,
    )]);
    for &(n, d) in entries {
        w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(n), Some(d))
            .unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// The other half of the same story: whenever a trim cannot happen, the
/// job must land exactly where it did before trimming existed - archive
/// materialized, disk post-pass unpacks it, payload still right.
///
/// Driven through the kill switch rather than by outrunning the decoder.
/// Arrival-beats-decode reaches the same code, but asserting on it means
/// asserting on who won a race: under a loaded machine the chase wins,
/// streams, and the "it demoted" assertion fails for the best possible
/// reason. The gate pins the behaviour; the race is a field question.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_over_the_cap_demotes_cleanly_when_it_cannot_trim() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7znotrim");
    let movie = incompressible(36 << 20, 44);
    let arch = sevenz_store_container(&[("movie.mkv", &movie)]);
    // No PAR2: this test is about where the archive ENDS UP, and the
    // set costs more to build than the rest of the case put together.
    // The chase-plus-PAR2 interactions have their own tests, small ones.
    fx.add_file("release.7z", &arch, 700_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(
            &cfg,
            &nzb,
            &out,
            &[("NZBFAST_NO_7Z_TRIM", "1")],
            &["--mem-limit", "64M"],
        )
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("held-bytes cap: chase memory"), "{log}");
    assert!(log.contains("7z unpack complete"), "the post-pass never ran:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("payload after the disk pass"),
        movie,
        "the demoted archive did not reconstruct"
    );
}

/// TODO 37 step 3: a `.7z.001` SPLIT SET posted as three files streams
/// as one container. 7z multipart is a raw byte split, so the set is a
/// single archive with seams in it: part 1's start header sizes the
/// whole thing, and the continuation parts - which carry no signature
/// whatsoever - join by name. Nothing lands on disk.
///
/// Before this, the parts materialized and the post-pass concatenated
/// them into a scratch container before unpacking, which is a full extra
/// copy of the archive on top of the download.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_split_set_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7zsplit");
    let movie = incompressible(6 << 20, 45);
    let arch = sevenz_store_container(&[("movie.mkv", &movie)]);
    // Exactly how `7z -v` splits: every part the split size, last one
    // the remainder.
    let split = arch.len().div_ceil(3);
    let parts: Vec<&[u8]> = arch.chunks(split).collect();
    assert_eq!(parts.len(), 3, "fixture must really split");
    let names: Vec<String> = (1..=3).map(|i| format!("release.7z.{i:03}")).collect();
    for (i, name) in names.iter().enumerate() {
        fx.add_file(name, parts[i], 200_000);
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(5, &refs, 200_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(log.contains("7z · one-pass"), "the set did not stream:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    for name in &names {
        assert!(
            !fx.dir.join("out").join(name).exists(),
            "{name} must not touch disk"
        );
    }
}

/// One-pass zip (phase 2): a POSTED store zip - the shape phase 1 sent
/// to disk. The chase takes it at depth 0 now (the tail prefetch
/// front-loads the central directory, which is the last thing in a
/// zip), so its payload streams out while the archive downloads and the
/// `.zip` itself never touches disk.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_zip_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topzip");
    // Incompressible, like real payload, STORED in the container - the
    // dominant zip shape and the one the store fast path exists for.
    let movie = incompressible(900_000, 46);
    let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored(
        "movie.mkv",
        &movie,
    )]);
    fx.add_file("release.zip", &arch, 60_000);
    assert!(fx.add_par2(10, &["release.zip"], 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    // The SIZE in that summary, not just the count. Every chase (7z and
    // zip) reported "(0.0 MB)" under a correct per-file list, because
    // the extractor's byte counter only advances on the RAR mapping
    // path - invisible until a live 160 MB zip printed it (31 Jul).
    assert!(
        !log.contains("in-stream (0.0 MB)"),
        "the in-stream summary lost its byte count:\n{log}"
    );
    assert!(log.contains("zip · one-pass"), "badge still says on-disk:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(
        !fx.dir.join("out/release.zip").exists(),
        "the archive must not touch disk"
    );
}

/// A `.zip.001` byte-split set posted as three files streams as one
/// container. Unlike 7z, no zip part carries a header that sizes the
/// set - the cut is arbitrary and only part 1 even has a signature -
/// so the NZB's own file list declares the part count and the geometry
/// resolves once every part's decoded size has arrived. Nothing lands
/// on disk.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_zip_split_set_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topzipsplit");
    let movie = incompressible(2 << 20, 49);
    let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored(
        "movie.mkv",
        &movie,
    )]);
    // A uniform byte split: every part the split size, last the
    // remainder - what hjsplit and `split -b` produce.
    let split = arch.len().div_ceil(3);
    let parts: Vec<&[u8]> = arch.chunks(split).collect();
    assert_eq!(parts.len(), 3, "fixture must really split");
    let names: Vec<String> = (1..=3).map(|i| format!("release.zip.{i:03}")).collect();
    for (i, name) in names.iter().enumerate() {
        fx.add_file(name, parts[i], 60_000);
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(5, &refs, 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(log.contains("zip · one-pass"), "the set did not stream:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    for name in &names {
        assert!(
            !fx.dir.join("out").join(name).exists(),
            "{name} must not touch disk"
        );
    }
}

/// The same shape, damaged - the riskiest inherited seam. A chased slot
/// cannot take a mapped repair (its bytes are in RAM, not a file par2
/// can patch), so the ladder must materialize the zip first, repair it
/// on disk, and let the zip step of the disk post-pass unpack it. The
/// silent failure this pins: a chased zip missing from the materialize
/// sweep reads back as "file missing entirely" and the repair rebuilds
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn damaged_top_level_zip_materializes_repairs_and_unpacks() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topzipdmg");
    let movie = incompressible(900_000, 48);
    let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored(
        "movie.mkv",
        &movie,
    )]);
    fx.add_file("release.zip", &arch, 60_000);
    assert!(fx.add_par2(30, &["release.zip"], 60_000));
    // Two mid-archive articles vanish: enough damage to need repair,
    // well inside the 30% redundancy.
    let victims: Vec<String> = ["-3@mock>", "-5@mock>"]
        .iter()
        .map(|suffix| {
            fx.articles
                .keys()
                .find(|k| k.contains("release_zip") && k.ends_with(suffix))
                .unwrap_or_else(|| panic!("no {suffix} article: {:?}", fx.articles.len()))
                .clone()
        })
        .collect();
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        !log.contains("file missing entirely"),
        "par2 could not see the chased archive:\n{log}"
    );
    assert!(log.contains("materializing volumes for repair"), "{log}");
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("payload after repair"),
        movie,
        "payload differs after repair + post-pass"
    );
}

/// Phase 3 end to end: an ENCRYPTED zip (WinZip AE-256) posted with its
/// password riding the `Name{{pw}}.nzb` convention. The chase now
/// decrypts IN STREAM, so the container never touches disk - it used to
/// decline encrypted, materialize, and let the disk post-pass unpack it
/// (and before that, fail the job outright with "the payload is a zip
/// that could not be unpacked").
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_zip_completes_with_a_braces_password() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topzipenc");
    let movie = incompressible(400_000, 50);
    let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec {
        encrypt: Some(nzbkit::zip::fixtures::Encrypt::Ae {
            password: "s3cretpw",
            strength: 3,
            vendor_version: 2,
        }),
        ..nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)
    }]);
    fx.add_file("release.zip", &arch, 60_000);
    assert!(fx.add_par2(10, &["release.zip"], 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let locked = fx.dir.join("release{{s3cretpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &locked, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("decrypted payload"),
        movie,
        "decrypted bytes differ"
    );
    // The whole point: no container on disk at any moment, and the disk
    // post-pass never needed. Its absence from the log is what says the
    // chase did the work rather than declining to it.
    assert!(
        !fx.dir.join("out/release.zip").exists(),
        "the container must never touch disk"
    );
    assert!(
        !log.contains("zip unpack complete"),
        "the disk pass ran - the chase declined instead of decrypting:\n{log}"
    );
}

/// Demote parity: a zip the one-pass path DECLINES (here: an lzma
/// entry, a method the tree does not carry) must land exactly where it
/// lands today - container materialized byte-exact in the output
/// directory, disk post-pass attempted and failing with the same
/// method-naming message, job failed because the zip IS the payload.
/// Run twice, gate on and gate off (`NZBFAST_NO_TOP_ZIP=1` = the
/// phase-1 path verbatim), asserting the SAME end state; the demote
/// marker in the log is what proves the gate-on run actually attached
/// and declined rather than never chasing at all.
#[tokio::test(flavor = "multi_thread")]
async fn declined_zip_lands_exactly_like_the_gate_off_path() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for (t, env) in [
        ("on", &[][..]),
        ("off", &[("NZBFAST_NO_TOP_ZIP", "1")][..]),
    ] {
        let mut fx = Fixture::new(&format!("topzipdecline-{t}"));
        let movie = incompressible(300_000, 47);
        let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec {
            method: 14, // lzma: declined BY NAME, in-stream and on disk
            ..nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)
        }]);
        fx.add_file("release.zip", &arch, 60_000);
        assert!(fx.add_par2(10, &["release.zip"], 60_000));
        let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
        let cfg = fx.write_config(&[&srv]);
        let nzb = fx.write_nzb();
        let out = fx.dir.join("out");
        let env: Vec<(&str, &str)> = env.to_vec();

        let (log, ok) =
            tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &env))
                .await
                .unwrap();
        assert!(!ok, "gate {t}: a packed payload must fail the job:\n{log}");
        assert!(
            log.contains("uses lzma compression"),
            "gate {t}: the declined method must be named:\n{log}"
        );
        assert_eq!(
            std::fs::read(fx.dir.join("out/release.zip")).expect("materialized container"),
            arch,
            "gate {t}: the container must land byte-exact"
        );
        assert!(
            !fx.dir.join("out/movie.mkv").exists(),
            "gate {t}: no payload may appear from a declined method"
        );
        // The runs differ in exactly one observable: with the gate on,
        // the chase attached and DEMOTED under the zip marker; with it
        // off, nothing ever chased.
        let marked = log.contains("zip materialized for the disk pass");
        assert_eq!(
            marked,
            t == "on",
            "gate {t}: demote marker presence is the gate's own signature:\n{log}"
        );
    }
}

/// Increment A (one-pass encrypted plan, 2026-07-31): an encrypted RAR5
/// store set whose password rides a TEXT SIDECAR in the same NZB - the
/// wild shape for passworded posts - must complete on the native
/// one-pass path with NO password supplied anywhere: the blocked set
/// parks, the in-stream probe harvests the sidecar, and the verified
/// candidate re-keys the mapper with every byte still in RAM. Unrar
/// forbidden by canary; volumes must never touch disk.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_store_sidecar_password_probes_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("encprobe");
    let inner = payload(900_001, 29);
    let f = fixtures::encrypt_file("pr0be-pw!", &inner, 7);
    let n = f.cipher.len();
    let (a, b) = (350_003, 700_006);
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let names = ["p.part1.rar", "p.part2.rar", "p.part3.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    // The password note, poster-style: prose noise around a labeled line.
    fx.add_file(
        "readme.txt",
        b"greetz to all\npassword: pr0be-pw!\nenjoy the show\n",
        60_000,
    );
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed (unrar canary tripped?):\n{log}");
    assert!(log.contains("in-stream probe"), "probe never hit:\n{log}");
    assert!(log.contains("decrypted"), "no native decrypt notice:\n{log}");
    assert!(!log.contains("unpacking archive"), "set demoted to disk:\n{log}");
    let extracted = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert_eq!(extracted.len(), inner.len(), "padding must be truncated");
    assert!(extracted == inner, "decrypted bytes differ");
    for v in &names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// Same probe, `-hp` shape: headers encrypted too, so NOTHING parses
/// until the probe finds the password - the type-4 crypt block's check
/// is captured password-less and the sidecar candidate re-keys from the
/// retained bytes. One pass, no volumes on disk.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_headers_sidecar_password_probes_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("enchpprobe");
    let inner = payload(600_001, 31);
    let f = fixtures::encrypt_file("hp-pr0be", &inner, 9);
    let n = f.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc_headers(
            &[("movie.mkv", &f, 0..n / 2, false, true)],
            Some(0),
            "hp-pr0be",
            11,
        ),
        fixtures::rar5_volume_enc_headers(
            &[("movie.mkv", &f, n / 2..n, true, false)],
            Some(1),
            "hp-pr0be",
            12,
        ),
    ];
    let names = ["h.part1.rar", "h.part2.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    fx.add_file("release.nfo", b"pass = hp-pr0be\n", 60_000);
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed (unrar canary tripped?):\n{log}");
    assert!(log.contains("in-stream probe"), "probe never hit:\n{log}");
    let extracted = std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file");
    assert!(extracted == inner, "decrypted bytes differ");
    for v in &names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} must not touch disk"
        );
    }
}

/// Probe MISS: an encrypted set whose sidecar holds only junk lands
/// like any locked set without a password - the job completes with
/// verified volumes on disk and the password prompt, no garbage
/// output, no unrar (canary).
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_store_probe_miss_demotes_like_before() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("encprobemiss");
    let inner = payload(400_000, 33);
    let f = fixtures::encrypt_file("never-posted", &inner, 13);
    let n = f.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n / 2, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, n / 2..n, true, false)], Some(1)),
    ];
    let names = ["m.part1.rar", "m.part2.rar"];
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 60_000);
    }
    fx.add_file("notes.txt", b"just a greeting\nno secrets here\n", 60_000);
    assert!(fx.add_par2(20, &names, 60_000), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();
    // A probe miss lands where every locked set lands: verified volumes
    // kept, 🔒 prompt, job complete. (This used to pin the OLD behavior -
    // NotStore's "compressed or encrypted entries" reason steered the
    // finish ladder into the unpack-or-fail arm and the job FAILED; the
    // MapBlocker::EncryptedNoPassword demote reason now routes a `-p`
    // no-password set to the same prompt arm `-hp` sets always reached.)
    assert!(ok, "a locked set with no password must complete, not fail:\n{log}");
    assert!(
        log.contains("password-protected and no password was found"),
        "missing the 🔒 prompt:\n{log}"
    );
    assert!(
        !log.contains("could not be unpacked"),
        "the pre-fix unrar-arm failure is back:\n{log}"
    );
    assert!(!fx.dir.join("out/movie.mkv").exists(), "garbage output:\n{log}");
    for (name, vol) in names.iter().zip(&vols) {
        assert_eq!(
            &std::fs::read(fx.dir.join("out").join(name)).expect("volume on disk"),
            vol,
            "verified volume {name} must stay byte-exact for the unlock"
        );
    }
}

/// Public issue #9: a fully obfuscated post whose recovery set we could
/// not see, so a repairable download failed while SABnzbd repaired it.
///
/// Nothing here carries a `.par2`: not an NZB subject, not a yEnc name,
/// not a filename on disk. That makes every file arrive classified as
/// payload, `bootstrap_vol` (which only considers files already
/// recognised as recovery volumes) never fires, and the whole in-stream
/// repair ladder is unreachable - the run lands in the no-set arm with
/// zero-filled holes where the missing articles were.
///
/// The bytes are all on disk by then, recovery volumes included, so that
/// arm now asks the DIRECTORY rather than the NZB. This pins the
/// end-to-end outcome: real damage, real recovery, repaired output.
#[tokio::test(flavor = "multi_thread")]
async fn an_obfuscated_post_repairs_from_its_own_unnamed_par2() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("obfpar2");
    let data = payload(1_200_000, 33);
    // Payload obfuscated too - hash subject AND hash yEnc name - so the
    // repair has to adopt it by content hash, not by its name.
    fx.add_file_obfuscated("Lp3vWq8xNc2", "Lp3vWq8xNc2", &data, 40_000);
    assert!(fx.add_par2_obfuscated(30, &["Lp3vWq8xNc2"], 40_000));
    assert!(
        !fx.nzb_files.iter().any(|(n, _)| n.contains(".par2")),
        "the test is void if any subject says par2"
    );

    // Drop three payload articles: real holes, well inside 30% recovery.
    let mut victims: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("Lp3vWq8xNc2"))
        .cloned()
        .collect();
    victims.sort();
    victims.truncate(3);
    assert_eq!(victims.len(), 3, "expected payload articles to drop");
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };

    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(ok, "get failed on a repairable obfuscated post:\n{log}");
    assert!(
        log.contains("the downloaded files include one"),
        "the disk-side fallback never ran:\n{log}"
    );
    // The payload is back, byte-exact, under the name PAR2 knows it by.
    let repaired = std::fs::read(out.join("Lp3vWq8xNc2"))
        .unwrap_or_else(|e| panic!("payload missing from {}: {e}\n{log}", out.display()));
    assert_eq!(repaired.len(), data.len(), "wrong length after repair\n{log}");
    assert!(repaired == data, "payload not byte-exact after repair\n{log}");
}

//! The settings lists agree.
//!
//! A setting is spread across three places that are kept in step BY HAND:
//!
//!  1. the `apply_setting` match in serve.rs - the allowlist, since its
//!     `_` arm is what rejects an unknown name;
//!  2. the settings table in serve.rs, which `get_config` is built by
//!     walking - what the dashboard reads back;
//!  3. the restore path in `serve()`/`apply_saved_settings` - what a
//!     restart puts back from settings.json.
//!
//! Miss one and it fails SILENTLY. Missing from (2), the control saves
//! and then reads back blank, so the UI shows the old value. Missing
//! from (3), it works until the daemon restarts and then quietly
//! reverts. Neither logs anything: there is no error path to hit,
//! because nothing went wrong - a key simply was not there.
//!
//! (2) has since been collapsed into the settings table, which
//! `get_config` is generated from and which `log_value` takes its rules
//! from - so that list can no longer be missed, and serve.rs's own
//! `apply_arms_match_the_table` holds (1) to the same table. (3) is the
//! one that genuinely resists collapsing: `apply_saved_settings` maps
//! saved JSON onto launch options before the daemon exists, so its work
//! is bespoke per setting and shares no shape with the others.
//!
//! These tests remain the check that the three AGREE at runtime, which
//! is worth keeping even where the source is now generated:
//!
//!  * `allowlist_and_get_config_agree` pins (1) against (2), by name,
//!    with the asymmetries listed and justified below;
//!  * `settings_survive_a_restart` pins (1) against (3) behaviourally,
//!    over every boolean setting the daemon reports - it discovers them
//!    from the live response, so a new flag is covered the day it is
//!    added, with no edit here.
//!
//! Adding a setting therefore needs no change to this file. Forgetting
//! one of the three lists fails it.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Settable, but deliberately never echoed by `get_config`.
///
/// The three keys are credentials: `get_config` is a read anyone holding
/// the API key can make from a browser, so they surface as `has_*` flags
/// instead and the value never leaves the daemon. `index_interests_applied`
/// is a one-shot marker recording that the interest presets were expanded
/// into scan groups - it has no control on the settings page.
const SETTABLE_NOT_ECHOED: &[&str] =
    &["apikey", "nzbkey", "omdb_key", "index_interests_applied"];

/// Echoed by `get_config`, but not settable through `mode=config`.
///
/// Everything here is either derived, reported for display only, or
/// written through its own dedicated endpoint rather than the settings
/// allowlist.
const ECHOED_READ_ONLY: &[&str] = &[
    // Where the daemon's own files live - reported so a user can find
    // them, moved only by launching differently.
    "config_path",
    "settings_path",
    // Resolved from mem_limit plus the machine's RAM.
    "mem_budget_total",
    // Owned by conntune.json and the tuner that writes it.
    "conntune",
    // The server list has its own editor endpoints (credentials must not
    // ride the settings allowlist), and this is its first-run signal.
    "servers",
    "servers_configured",
    // Saved-but-not-yet-applied values, computed by diffing settings.json
    // against the running daemon.
    "pending",
    // Credential presence flags - see SETTABLE_NOT_ECHOED.
    "has_apikey",
    "has_nzbkey",
    "has_omdb",
];

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Response body of a GET against the daemon (headers stripped).
///
/// A connection refused before it produced a single byte is retried:
/// under a full parallel `cargo test` tiny_http can fail to spawn a
/// thread and drop the socket unread, which reaches us as ECONNRESET.
/// Once any byte has come back it is an answer and is returned as-is - a
/// truncated body must never be retried away.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(s, "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")?;
    let mut out = String::new();
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed without answering")
        }));
    }
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

/// The `config.nzbfast` block, as the daemon serves it.
fn settings_block(port: u16) -> serde_json::Map<String, serde_json::Value> {
    let j = api(port, "mode=get_config");
    j["config"]["nzbfast"]
        .as_object()
        .unwrap_or_else(|| panic!("get_config has no config.nzbfast object: {j}"))
        .clone()
}

/// Every name `apply_setting` accepts, read out of the source.
///
/// The allowlist is the match itself - there is no const to compare
/// against - so this reads the arms. Deliberately strict about the shape
/// it recognises: a `"name" =>` arm at the function's own indent. If the
/// match is ever reformatted this stops finding arms and the count
/// assertion below fails loudly, which is the right direction to fail.
fn allowlist() -> Vec<String> {
    let src = include_str!("../src/serve.rs");
    let mut names = Vec::new();
    let mut inside = false;
    for line in src.lines() {
        if line.starts_with("fn apply_setting") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        // The function's own closing brace, at column 0. Deliberately
        // not the text of the fallthrough arm: that arm is prose, it has
        // been reworded once already, and when it changed this loop ran
        // on into the rest of the file and collected every JSON-RPC mode
        // and locale code in it as a "setting".
        if line == "}" {
            break;
        }
        // `        "a" | "b" => {` at exactly two levels of indent.
        let Some(rest) = line.strip_prefix("        \"") else { continue };
        let Some(head) = rest.split("=>").next().filter(|_| rest.contains("=>")) else { continue };
        let head = format!("\"{head}");
        // Only an arm made purely of string literals and `|` separators.
        if head.split('|').all(|p| {
            let p = p.trim();
            p.len() > 2 && p.starts_with('"') && p.ends_with('"') && !p[1..p.len() - 1].contains('"')
        }) {
            for p in head.split('|') {
                names.push(p.trim().trim_matches('"').to_string());
            }
        }
    }
    assert!(
        names.len() > 60,
        "only found {} settings in apply_setting - the arm shape this test \
         parses must have changed, so it is no longer checking anything",
        names.len()
    );
    names
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        // ...and reap it, or the pid is held for the rest of the run.
        let _ = self.0.wait();
    }
}

struct Running {
    _child: KillOnDrop,
    port: u16,
}

/// A scratch install. `settings.json` exists from the start so this
/// reads as an EXISTING install and no first-run API key is minted -
/// auth is not what these tests are about.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-setcat-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{}").unwrap();
    dir
}

/// Launch `nzbfast serve` against `dir` and wait until it is serving.
/// Called twice per restart test, against the same directory.
fn serve(dir: &Path) -> Running {
    serve_env(dir, &[])
}

/// `serve` as a launcher that owns the port (container / Synology package).
fn serve_locked(dir: &Path) -> Running {
    serve_env(dir, &[("NZBFAST_PORT_LOCKED", "1")])
}

fn serve_env(dir: &Path, env: &[(&str, &str)]) -> Running {
    for attempt in 0..3 {
        let port = free_port();
        // Per-port, so the restart cannot read the FIRST daemon's banner
        // out of a shared log and call the second one ready.
        let logfile = dir.join(format!("daemon-{port}.log"));
        let out = std::fs::File::create(&logfile).unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd
            .env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            // Loopback only: these suites never need LAN reach, and
            // binding 0.0.0.0 raises a macOS firewall prompt for every
            // freshly built test binary.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"))
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();
        let mut running = Running { _child: KillOnDrop(child), port };
        if wait_ready(&mut running._child, port, &logfile) {
            return running;
        }
        // The daemon exited instead of binding: `free_port()` handed
        // :port to a parallel test between our bind(:0) and the daemon's
        // bind. Try a fresh port.
        assert!(attempt < 2, "daemon exited without binding :{port}\n{}", log(&logfile));
    }
    unreachable!()
}

/// Wait for OUR daemon's own listener banner, not for "something answers
/// on :port" - under a parallel run those differ, and a bare connect
/// would happily run the test against a stranger's daemon.
fn wait_ready(child: &mut KillOnDrop, port: u16, logfile: &Path) -> bool {
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if log(logfile).contains(&banner) && TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        if child.0.try_wait().ok().flatten().is_some() {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("daemon never came up on :{port}\n{}", log(logfile));
}

fn log(logfile: &Path) -> String {
    std::fs::read_to_string(logfile).unwrap_or_default()
}

/// Every settable name is read back by `get_config`, and every key
/// `get_config` reports is settable - except the asymmetries listed at
/// the top of this file, which are there on purpose.
#[test]
fn allowlist_and_get_config_agree() {
    let dir = scratch("agree");
    let d = serve(&dir);
    let echoed = settings_block(d.port);
    let allow = allowlist();

    let missing: Vec<&String> = allow
        .iter()
        .filter(|n| !echoed.contains_key(n.as_str()) && !SETTABLE_NOT_ECHOED.contains(&n.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "settable but never read back by get_config: {missing:?}\n\
         The control saves and then reads back blank. Add it to the right \
         settings table in serve.rs, or to SETTABLE_NOT_ECHOED here if it \
         is a credential."
    );

    let orphan: Vec<&String> = echoed
        .keys()
        .filter(|k| !allow.contains(k) && !ECHOED_READ_ONLY.contains(&k.as_str()))
        .collect();
    assert!(
        orphan.is_empty(),
        "reported by get_config but not settable: {orphan:?}\n\
         The UI can show it but saving it fails. Add an arm to \
         apply_setting in serve.rs, or to ECHOED_READ_ONLY here if it is \
         display-only."
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A saved setting is still in force after a restart.
///
/// Covers the third list: a setting can validate, apply live and read
/// back correctly, and still be missing from the restore path in
/// `serve()` - at which point it silently reverts on the next launch,
/// which is exactly when nobody is watching.
///
/// Every boolean the daemon reports is flipped, so this needs no table
/// of names or values to maintain: a new flag joins the test as soon as
/// `get_config` reports it.
#[test]
fn settings_survive_a_restart() {
    let dir = scratch("restart");
    let allow = allowlist();

    // Flip every settable boolean away from whatever it is now.
    let flipped: Vec<(String, bool)> = {
        let d = serve(&dir);
        let before = settings_block(d.port);
        let targets: Vec<(String, bool)> = before
            .iter()
            .filter(|(k, _)| allow.contains(k))
            .filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), !b)))
            .collect();
        assert!(
            targets.len() > 15,
            "only {} boolean settings found - this test has stopped covering \
             the settings surface",
            targets.len()
        );

        for (name, want) in &targets {
            let r = api(
                d.port,
                &format!("mode=config&name={name}&value={}", u8::from(*want)),
            );
            assert_eq!(
                r["status"].as_bool(),
                Some(true),
                "setting {name} was rejected: {r}"
            );
        }

        // Live first: a setting that never reaches the daemon would
        // otherwise look like a restart failure below.
        let after = settings_block(d.port);
        let stale: Vec<&str> = targets
            .iter()
            .filter(|(k, want)| after.get(k).and_then(|v| v.as_bool()) != Some(*want))
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(
            stale.is_empty(),
            "saved, but get_config still reports the old value: {stale:?}\n\
             The apply_setting arm validated it without applying it to the \
             running daemon."
        );
        targets
    }; // daemon killed here

    // Same directory, new process: settings.json is the only carrier.
    let d = serve(&dir);
    let restored = settings_block(d.port);
    let lost: Vec<&str> = flipped
        .iter()
        .filter(|(k, want)| restored.get(k).and_then(|v| v.as_bool()) != Some(*want))
        .map(|(k, _)| k.as_str())
        .collect();
    assert!(
        lost.is_empty(),
        "reverted across a restart: {lost:?}\n\
         Saved to settings.json but never read back at launch - add it to \
         the restore path in serve() (the boolean table) or to \
         apply_saved_settings."
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Turning fast verify off means full verify, and it stays off.
///
/// `fast_verify` and `verify_mode` are two controls over the same pair of
/// flags, so a write through one has to leave the other's saved value
/// consistent. It does not fall out of `settings_survive_a_restart`: that
/// starts from a settings.json with no verify_mode in it at all, and the
/// revert needs an install that has used the verify_mode control at some
/// point - after which the restore path applies the stale mode LAST and
/// the fast_verify write is undone on every launch.
#[test]
fn turning_fast_verify_off_survives_a_restart_after_lean_was_chosen() {
    let dir = scratch("verify");

    // An install that once chose lean, then asked for full verify.
    {
        let d = serve(&dir);
        let r = api(d.port, "mode=config&name=verify_mode&value=lean");
        assert_eq!(r["status"].as_bool(), Some(true), "verify_mode rejected: {r}");
        assert_eq!(settings_block(d.port)["verify_mode"], "lean");

        let r = api(d.port, "mode=config&name=fast_verify&value=0");
        assert_eq!(r["status"].as_bool(), Some(true), "fast_verify rejected: {r}");
        assert_eq!(settings_block(d.port)["verify_mode"], "full", "not applied live");
    } // daemon killed here

    {
        let d = serve(&dir);
        let s = settings_block(d.port);
        assert_eq!(
            s["verify_mode"], "full",
            "the daemon came back on the old verify mode - the fast_verify \
             write left a stale verify_mode in settings.json, and the \
             restore path applies that one last"
        );
        assert_eq!(s["fast_verify"], false, "fast verify came back on: {s:?}");
    }

    // The other direction: turning it back ON must survive too, and must
    // not silently promote itself to lean.
    {
        let d = serve(&dir);
        let r = api(d.port, "mode=config&name=fast_verify&value=1");
        assert_eq!(r["status"].as_bool(), Some(true), "fast_verify rejected: {r}");
        assert_eq!(settings_block(d.port)["verify_mode"], "fast", "not applied live");
    }

    {
        let d = serve(&dir);
        let s = settings_block(d.port);
        assert_eq!(s["verify_mode"], "fast", "fast verify did not survive the restart");
        assert_eq!(s["fast_verify"], true, "fast verify came back off: {s:?}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A launcher that owns the port keeps it: the API refuses to save one,
/// and a `port` already in settings.json does not move the listener.
///
/// This is the container/SPK contract. Their port is named in a published
/// mapping, a healthcheck and DSM's own Open button - none of which
/// nzbfast can rewrite - so a port saved in the dashboard used to leave
/// the service unreachable through its mapping and unhealthy on restart,
/// with the UI reporting the change took.
#[test]
fn a_locked_port_cannot_be_moved_from_the_dashboard() {
    let dir = scratch("portlock");

    // `port` is a restart-only setting, so `get_config` reports the LIVE
    // port either way - settings.json is where the saved value shows up.
    let saved_port = || -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default(),
        )
        .map(|v| v["port"].clone())
        .unwrap_or(serde_json::Value::Null)
    };

    // Unlocked (a desktop or plain CLI install): the setting is accepted
    // and saved, which is the behaviour this must not break.
    {
        let d = serve(&dir);
        let r = api(d.port, "mode=config&name=port&value=6999");
        assert_eq!(r["status"].as_bool(), Some(true), "port rejected while unlocked: {r}");
        assert_eq!(saved_port(), 6999, "an accepted port was not saved");
    }

    // Locked: refused with an explanation, and settings.json still holds
    // the 6999 written above - which the daemon must now ignore.
    {
        let d = serve_locked(&dir);
        let r = api(d.port, "mode=config&name=port&value=7001");
        assert_eq!(r["status"].as_bool(), Some(false), "a locked port was accepted: {r}");
        let err = r["error"].as_str().unwrap_or_default();
        assert!(
            err.contains("how it was started"),
            "the refusal has to say WHERE the port lives, got: {err:?}"
        );
        // The refusal must not rewrite what is already saved either.
        assert_eq!(saved_port(), 6999, "a refused write still touched settings.json");
        // `get_config` reports the LIVE port, so this is the assertion that
        // the saved 6999 was ignored at startup rather than applied.
        assert_eq!(
            settings_block(d.port)["port"].as_u64(),
            Some(d.port as u64),
            "the saved port won over the one this install was started with"
        );
        let q = api(d.port, "mode=queue");
        assert_eq!(
            q["queue"]["port_locked"].as_bool(),
            Some(true),
            "the dashboard is never told to disable the field: {q}"
        );
        // The listener answering us IS d.port - the saved 6999 did not win.
        assert_ne!(d.port, 6999);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The launcher handshake: `runtime.json` plus a challenge is what lets a
/// desktop wrapper tell this daemon from anything else that grabbed the
/// port, BEFORE it hands over the stored API key.
///
/// Not a settings test, but it needs exactly this file's daemon harness:
/// a real listener, started from a known data dir.
#[test]
fn the_daemon_proves_its_identity_to_a_launcher() {
    use sha2::{Digest, Sha256};

    let dir = scratch("handshake");
    let d = serve(&dir);

    // Written only once the listener exists, and only readable by us.
    let rt: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("runtime.json")).expect("no runtime.json"),
    )
    .unwrap();
    assert_eq!(rt["port"].as_u64(), Some(d.port as u64), "runtime.json names another port");
    let token = rt["token"].as_str().unwrap_or_default().to_string();
    assert!(token.len() >= 32, "the token is not a credential: {token:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("runtime.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "runtime.json is readable by other accounts: {mode:o}");
    }

    let proof_of = |token: &str, nonce: &str| {
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        h.update(b":");
        h.update(nonce.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // The challenge rides the keyless probe - which is the ONLY reply a
    // wrapper gets, since sending the key to an unidentified listener is
    // the thing being prevented.
    let r = api(d.port, "mode=version&hs=0123456789abcdef");
    assert_eq!(
        r["hs_proof"].as_str(),
        Some(proof_of(&token, "0123456789abcdef").as_str()),
        "the daemon did not prove it holds its own token: {r}"
    );
    // A different nonce is a different answer - no replay.
    let again = api(d.port, "mode=version&hs=fedcba9876543210");
    assert_ne!(again["hs_proof"], r["hs_proof"]);
    // No challenge, no proof field - nothing leaks into ordinary replies.
    let plain = api(d.port, "mode=version");
    assert!(plain.get("hs_proof").is_none(), "a proof appeared unasked: {plain}");
    // And a nonce that could not have come from a launcher is ignored
    // rather than hashed into the response.
    let junk = api(d.port, "mode=version&hs=short");
    assert!(junk.get("hs_proof").is_none(), "an out-of-shape nonce was answered: {junk}");

    let _ = std::fs::remove_dir_all(&dir);
}

//! First-run API key + `--bind`, against the real binary.
//!
//! Until 1.0.9 every launcher except the container started the daemon
//! keyless on 0.0.0.0, where the auth computation treats every request as
//! fully authorized. The daemon now mints a key on a genuinely new
//! install - and, just as importantly, NEVER on an existing one, because
//! a key appearing under a running install would silently break the
//! user's Sonarr/Radarr and phone remotes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Mirrors serve::KEYLESS_MARKER, which the Windows tray also matches on
/// to explain the stop. Kept as a literal because the integration test
/// binary cannot see the crate's private consts.
fn nzbfast_keyless_marker() -> &'static str {
    "nzbfast cannot start: API key file"
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Response body of a GET against the daemon (headers stripped).
///
/// A connection REFUSED before it produced a single byte is retried. That
/// is not the same as tolerating a bad answer: tiny_http's honest reply
/// when it cannot start a thread for a new connection is to drop the
/// socket unread, and with our request still in its receive buffer the
/// kernel turns that into an RST - which arrives here as ECONNRESET. Under
/// a fully parallel `cargo test` this whole crate's suites run ~100
/// daemons at once, so `thread::Builder::spawn` really does hit EAGAIN,
/// and this test then failed on a refusal to serve rather than on
/// anything it asserts. Once a byte has come back it is an answer, and it
/// is returned (or fails) exactly as it arrived.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
            Ok(body) => return body,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

/// One attempt. Returns Err ONLY when the daemon produced nothing at all;
/// a partial or malformed response is data, and is handed back for the
/// caller's assertions to judge.
fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(s, "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")?;
    let mut raw = Vec::new();
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
    let read = s.read_to_end(&mut raw);
    if raw.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let out = String::from_utf8_lossy(&raw);
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run the daemon expecting it to REFUSE to start, bounded by a timeout.
///
/// `Command::output()` is wrong for this: it waits for exit, so against
/// code that (incorrectly) starts and serves, the test hangs forever and
/// wedges the whole suite instead of reporting a failure. A refusal is
/// supposed to be prompt, so anything still alive after the deadline IS
/// the bug.
fn expect_refusal(dir: &Path, port: u16, extra: &[&str]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    cmd.env("NZBFAST_NO_ENRICH", "1")
        .env_remove("NZBFAST_OPEN")
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("serve")
        .arg("--port")
        .arg(port.to_string())
        .arg("--out")
        .arg(dir.join("complete"))
        .args(extra)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        match child.try_wait().unwrap() {
            Some(status) => {
                let out = child.wait_with_output().unwrap();
                let log = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(!status.success(), "daemon started when it should have refused: {log}");
                return log;
            }
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("daemon was still running after 20s - it did not refuse to start");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-firstrun-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A config with no servers is enough: nothing here downloads.
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    dir
}

struct Running {
    _child: KillOnDrop,
    port: u16,
    log: PathBuf,
}

impl Running {
    /// Everything the daemon has written to stdout/stderr so far.
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// Launch `nzbfast serve` against `dir`, with stdout+stderr captured to a
/// file so the first-run banner can be asserted on.
fn serve(dir: &Path, extra: &[&str]) -> Running {
    serve_env(dir, extra, None)
}

/// As `serve`, with `NZBFAST_OPEN` optionally set (the deliberate keyless
/// opt-out). It is REMOVED otherwise, so an inherited value can never
/// quietly turn the first-run assertions into no-ops.
fn serve_env(dir: &Path, extra: &[&str], open_env: Option<&str>) -> Running {
    // The port is claimed by bind(:0) and released a moment before the
    // daemon binds it; when a parallel suite wins that race the daemon
    // exits and this retries on a fresh port rather than flaking.
    for attempt in 0..3 {
        let port = free_port();
        let log = dir.join("daemon.log");
        let out = std::fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1");
        match open_env {
            Some(v) => cmd.env("NZBFAST_OPEN", v),
            None => cmd.env_remove("NZBFAST_OPEN"),
        };
        // Loopback unless the caller asked for something else. These
        // assertions are about which KEY the daemon starts with, not which
        // interface it listens on, and a wide bind makes the macOS firewall
        // prompt for every freshly built test binary - a new path on every
        // run. `bind_parses_and_defaults_to_all_interfaces` is the one test
        // that genuinely needs LAN reach and names its own bind.
        let narrow: &[&str] =
            if extra.contains(&"--bind") { &[] } else { &["--bind", "127.0.0.1"] };
        let child = cmd
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .args(narrow)
            .args(extra)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();
        let mut running = Running { _child: KillOnDrop(child), port, log };
        // Readiness is OUR daemon's own listener banner, not "something
        // answers on :port". A bare connect cannot tell the two apart, and
        // under a full parallel run they diverge: `free_port()` can hand
        // :port to a second test between our bind(:0) and our daemon's
        // bind, that test's daemon wins the port, ours exits, and a plain
        // connect then succeeds against the OTHER daemon. The test would
        // run against a stranger and, when that stranger's owner finished
        // and killed it, fail with ConnectionReset mid-request. The banner
        // is read from this dir's own log, so it can only be ours, and it
        // is printed immediately after the bind returns.
        let banner = format!("open the dashboard at  http://localhost:{port}/");
        let mut dead = false;
        for _ in 0..300 {
            if running.log().contains(&banner) && TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return running;
            }
            if running._child.0.try_wait().ok().flatten().is_some() {
                dead = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = running.log();
        assert!(dead && attempt < 2, "daemon never bound on :{port}\n--- log ---\n{log}");
    }
    unreachable!()
}

/// The banner is printed after the listener is up, so give the write a
/// moment to reach the redirected file before reading it.
fn log_containing(r: &Running, needle: &str) -> String {
    for _ in 0..50 {
        let l = r.log();
        if l.contains(needle) {
            return l;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let l = r.log();
    panic!("log never contained {needle:?}\n--- log ---\n{l}");
}

/// The daemon answers a missing key with "API Key Required" and a wrong
/// one with "API Key Incorrect"; both are refusals.
fn rejected(body: &str) -> bool {
    body.contains("API Key Required") || body.contains("API Key Incorrect")
}

fn is_hex_key(k: &str) -> bool {
    k.len() == 48 && k.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// (a) A brand-new install gets a strong key, stored and printed once,
///     and the API is closed without it.
#[test]
fn fresh_install_generates_prints_and_enforces_a_key() {
    let dir = scratch("fresh");
    let r = serve(&dir, &[]);

    let keyfile = dir.join("apikey");
    let key = std::fs::read_to_string(&keyfile).expect("apikey file must be written");
    assert!(is_hex_key(&key), "weak/odd generated key {key:?}");

    // Printed for the user, exactly once, with the key itself.
    let log = log_containing(&r, &key);
    assert!(log.contains("API key:"), "no first-run banner\n{log}");
    assert_eq!(log.matches(&key as &str).count(), 1, "key printed more than once\n{log}");

    // The API is now closed to anything without the key.
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(rejected(&anon), "unauthenticated request allowed: {anon}");
    let anon = http(r.port, "/api?mode=queue&output=json");
    assert!(rejected(&anon), "unauthenticated queue read allowed: {anon}");
    // ...and open with it.
    let ok = http(r.port, &format!("/api?mode=version&apikey={key}&output=json"));
    assert!(ok.contains("version"), "generated key rejected: {ok}");

    // Restarting reuses the SAME key - the *arrs hold it.
    drop(r);
    let r2 = serve(&dir, &[]);
    let ok = http(r2.port, &format!("/api?mode=version&apikey={key}&output=json"));
    assert!(ok.contains("version"), "key not stable across restarts: {ok}");
    assert_eq!(std::fs::read_to_string(&keyfile).unwrap(), key);
    // ...and does not re-print it (it was printed once, on generation).
    assert!(!r2.log().contains("API key:"), "banner repeated on restart\n{}", r2.log());
}

/// A key typed into Settings is written to settings.json and NOWHERE
/// else - the config handler only touches the `apikey` file to delete it
/// on clear. So an unreadable settings.json silently drops that key,
/// load_settings degrades to an empty map, and the daemon used to come
/// up wide open on the default 0.0.0.0 listener. Same cause the keyfile
/// branch already guarded (uid change, torn write), same answer.
#[test]
#[cfg(unix)]
fn an_unreadable_settings_store_refuses_to_start_when_the_key_lived_there() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("settings-unreadable-fails-closed");
    // An established install whose ONLY credential is in settings.json.
    std::fs::create_dir_all(dir.join(".spool")).unwrap();
    let settings = dir.join("settings.json");
    std::fs::write(&settings, "{\"apikey\":\"dashboard-set-key\"}").unwrap();
    let mut perms = std::fs::metadata(&settings).unwrap().permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&settings, perms).unwrap();

    let log = expect_refusal(&dir, free_port(), &[]);
    let mut perms = std::fs::metadata(&settings).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&settings, perms).unwrap();
    assert!(log.contains("refusing to start the control API"), "{log}");
}

/// `--apikey ""` was a quieter fail-open than the ones this module
/// guards. `Some("")` short-circuited first_run_apikey entirely, so no
/// key was minted; the open-API banner stayed silent because `d.apikey`
/// was not None; and `ct_eq("", "")` then authorised any request
/// carrying `?apikey=`.
///
/// The first draft of this test passed NZBFAST_OPEN=1, which makes the
/// daemon keyless either way and so proved nothing. It has to be a
/// genuinely fresh install with the flag as the ONLY input.
#[test]
fn an_empty_apikey_flag_is_not_a_credential() {
    let dir = scratch("empty-apikey-flag");
    let r = serve_env(&dir, &["--apikey", ""], None);

    // Trimmed to None, the fresh-install path runs and mints a real key.
    let key = std::fs::read_to_string(dir.join("apikey"))
        .expect("an empty --apikey must not suppress first-run key minting");
    assert!(is_hex_key(&key), "weak/odd generated key {key:?}");

    // And the empty credential must not open anything.
    let empty = http(r.port, "/api?mode=queue&output=json&apikey=");
    assert!(rejected(&empty), "an empty --apikey authorised the control API: {empty}");
    let anon = http(r.port, "/api?mode=queue&output=json");
    assert!(rejected(&anon), "unauthenticated request allowed: {anon}");
    let ok = http(r.port, &format!("/api?mode=version&apikey={key}&output=json"));
    assert!(ok.contains("version"), "minted key rejected: {ok}");
}

#[test]
fn an_empty_existing_keyfile_refuses_to_start_instead_of_opening_the_api() {
    let dir = scratch("empty-key-fails-closed");
    std::fs::write(dir.join("settings.json"), "{\"auto_speed\":false}").unwrap();
    std::fs::write(dir.join("apikey"), "").unwrap();
    let port = free_port();
    let out = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_NO_ENRICH", "1")
        .env_remove("NZBFAST_OPEN")
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("serve")
        .arg("--port")
        .arg(port.to_string())
        .arg("--out")
        .arg(dir.join("complete"))
        .output()
        .unwrap();
    assert!(!out.status.success(), "daemon accepted an empty credential file");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Two different refusal messages exist: the empty/unreadable KEYFILE
    // path uses KEYLESS_MARKER (which the tray also matches on, so it can
    // explain the stop), and the entropy and settings-store paths say
    // "refusing to start the control API". Assert the BEHAVIOUR and accept
    // either wording - pinning one exact string is what made this test
    // fail when the message was reworded, without anything being broken.
    assert!(
        log.contains(nzbfast_keyless_marker()) || log.contains("refusing to start"),
        "no refusal message in the log:\n{log}"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "a failed-closed startup still opened the listener"
    );
}

/// (b) THE regression that protects current users: an install that is
///     already running keyless must come back up keyless. A key appearing
///     underneath it would break every configured Sonarr/Radarr and phone
///     remote on a restart the user never connected to a config change.
///     Marked by dashboard settings.
#[test]
fn existing_install_with_settings_stays_keyless() {
    let dir = scratch("existing-settings");
    std::fs::write(dir.join("settings.json"), "{\"auto_speed\":false}").unwrap();

    let r = serve(&dir, &[]);
    assert!(!dir.join("apikey").exists(), "a key was minted under an existing install");
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(anon.contains("version"), "existing keyless install started keyed: {anon}");
}

/// The `nzbfast setup` wizard runs as its OWN process, so the indexing
/// answer it collects lands in settings.json before the daemon has ever
/// started. That file must not read as "an existing install" - a user who
/// answered the wizard would otherwise get an unkeyed daemon, which is
/// the hole this whole test file exists to close.
#[test]
fn a_wizard_answer_alone_is_still_a_first_run() {
    let dir = scratch("wizard-answer");
    std::fs::write(dir.join("settings.json"), "{\"index_interests\":\"linux,sports\"}").unwrap();

    let r = serve(&dir, &[]);
    assert!(dir.join("apikey").exists(), "no key minted after the setup wizard ran");
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(rejected(&anon), "keyless request accepted on a fresh install: {anon}");

    // ...and one real setting beside it makes it an established install
    // again, so the rule cannot be widened by accident.
    let dir2 = scratch("wizard-answer-plus");
    std::fs::write(
        dir2.join("settings.json"),
        "{\"index_interests\":\"linux\",\"auto_speed\":false}",
    )
    .unwrap();
    let r2 = serve(&dir2, &[]);
    assert!(!dir2.join("apikey").exists(), "a key was minted under an existing install");
    assert!(http(r2.port, "/api?mode=version&output=json").contains("version"));
}

/// (b, second marker) Same rule when the user never changed a dashboard
/// setting but the install has run before: the spool is the evidence.
#[test]
fn existing_install_with_a_spool_stays_keyless() {
    let dir = scratch("existing-spool");
    std::fs::create_dir_all(dir.join(".spool")).unwrap();

    let r = serve(&dir, &[]);
    assert!(!dir.join("apikey").exists(), "a key was minted under an existing install");
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(anon.contains("version"), "existing keyless install started keyed: {anon}");
}

/// (b, third marker) A genuinely legacy install - one that ran before the
/// spool moved out of the download directory - is still an existing
/// install. What marks it is the DATA-DIR evidence (here settings.json);
/// the leftover download-root spool alongside it must not change that
/// answer either way.
#[test]
fn existing_install_with_a_legacy_spool_stays_keyless() {
    let dir = scratch("existing-legacy-spool");
    std::fs::create_dir_all(dir.join("complete/.spool")).unwrap();
    std::fs::write(dir.join("settings.json"), "{\"auto_speed\":false}").unwrap();

    let r = serve(&dir, &[]);
    assert!(!dir.join("apikey").exists(), "a key was minted under an existing install");
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(anon.contains("version"), "existing keyless install started keyed: {anon}");
}

/// THE REGRESSION this file exists for on Windows: a REINSTALL.
///
/// The uninstaller asks about downloads separately and defaults to keeping
/// them, so `<downloads>/nzbfast/.spool` routinely outlives the install
/// that made it. Treating that as "an existing install" meant a wiped data
/// dir - no settings.json, no spool, no key file, nothing a credential
/// could possibly live in - started keyless on 0.0.0.0 with no key minted.
/// On Windows there is no console and the dashboard log panel is unix-only,
/// so the SECURITY banner had nowhere to appear: the API was simply open.
#[test]
fn reinstall_over_a_leftover_download_spool_mints_a_key() {
    let dir = scratch("reinstall");
    // Exactly the Windows repro: a pristine data dir (config.json only,
    // written by scratch()) beside a download root left behind by an
    // install from days earlier.
    std::fs::create_dir_all(dir.join("complete/.spool")).unwrap();
    assert!(!dir.join("settings.json").exists());
    assert!(!dir.join(".spool").exists());

    let r = serve(&dir, &[]);
    let key = std::fs::read_to_string(dir.join("apikey"))
        .expect("a reinstall onto a leftover download spool must still mint a key");
    assert!(is_hex_key(&key), "weak/odd generated key {key:?}");

    // And it is enforced, which is the whole point.
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(rejected(&anon), "reinstall left the API open: {anon}");
    let ok = http(r.port, &format!("/api?mode=version&apikey={key}&output=json"));
    assert!(ok.contains("version"), "generated key rejected: {ok}");
    let log = log_containing(&r, &key);
    assert!(log.contains("API key:"), "no first-run banner\n{log}");
}

/// NZBFAST_OPEN=1 is the deliberate keyless opt-in, on a fresh install too.
#[test]
fn nzbfast_open_env_stays_keyless() {
    let dir = scratch("open-env");
    let r = serve_env(&dir, &[], Some("1"));
    assert!(!dir.join("apikey").exists(), "NZBFAST_OPEN=1 still minted a key");
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(anon.contains("version"), "NZBFAST_OPEN=1 did not stay keyless: {anon}");
}

/// (c) An explicit --apikey is the operator's choice and wins: nothing is
///     generated and nothing is stored behind their back.
#[test]
fn explicit_apikey_wins_on_a_fresh_install() {
    let dir = scratch("explicit");
    let r = serve(&dir, &["--apikey", "sekrit"]);

    assert!(!dir.join("apikey").exists(), "--apikey should not mint or store a key");
    assert!(!r.log().contains("API key:"), "first-run banner shown despite --apikey");

    let ok = http(r.port, "/api?mode=version&apikey=sekrit&output=json");
    assert!(ok.contains("version"), "--apikey rejected: {ok}");
    let bad = http(r.port, "/api?mode=version&apikey=wrong&output=json");
    assert!(bad.contains("API Key Incorrect"), "wrong key accepted: {bad}");
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(rejected(&anon), "unauthenticated request allowed: {anon}");
}

/// BUG: clearing the key in the dashboard removed it from settings.json
/// but left the minted key file on disk, and that file is the FIRST thing
/// the next start reads. So a user who deliberately went keyless was
/// keyed again on the next restart, with nothing on screen to say why.
///
/// The clear must also take the key file - and leave the install in a
/// state that stays quietly keyless, rather than tripping the
/// "exists but is empty" warning on every boot.
#[test]
fn clearing_the_key_in_the_dashboard_stays_cleared() {
    let dir = scratch("cleared");
    let keyfile = dir.join("apikey");

    // A fresh install mints one...
    let r = serve(&dir, &[]);
    let key = std::fs::read_to_string(&keyfile).expect("apikey file must be written");
    let ok = http(r.port, &format!("/api?mode=version&apikey={key}&output=json"));
    assert!(ok.contains("version"), "generated key rejected: {ok}");

    // ...the user clears it in Settings.
    let cleared =
        http(r.port, &format!("/api?mode=config&name=apikey&value=&apikey={key}&output=json"));
    assert!(cleared.contains("\"status\""), "clear rejected: {cleared}");
    // Immediately keyless, as it always was.
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(anon.contains("version"), "clearing the key did not open the API: {anon}");
    // ...and the file that would resurrect it is gone. Gone, not blanked:
    // an empty file makes first_run_apikey warn on every single boot.
    assert!(!keyfile.exists(), "the minted key file survived the clear - it will be read back");

    // THE REGRESSION: the restart must come back up keyless.
    drop(r);
    let r2 = serve(&dir, &[]);
    let anon = http(r2.port, "/api?mode=version&output=json");
    assert!(anon.contains("version"), "a cleared key came back on restart: {anon}");
    assert!(!keyfile.exists(), "a key was re-minted under an existing install");
    let log = r2.log();
    assert!(!log.contains("API key:"), "a new key was generated and printed\n{log}");
    assert!(
        !log.contains("refusing to replace"),
        "the deliberate clear left empty-keyfile noise on the next boot\n{log}"
    );

    // And it stays gone: a third start is just as quiet.
    drop(r2);
    let r3 = serve(&dir, &[]);
    let anon = http(r3.port, "/api?mode=version&output=json");
    assert!(anon.contains("version"), "keyless install did not stay keyless: {anon}");
    assert!(!keyfile.exists());
}

/// The counterpart: SETTING a key from the dashboard still works, and is
/// what wins on the next start (settings.json is read before the key
/// file). Nothing here should be tempted to delete the file for a
/// non-empty value.
#[test]
fn setting_a_key_in_the_dashboard_survives_a_restart() {
    let dir = scratch("dashboard-set");
    std::fs::write(dir.join("settings.json"), "{}").unwrap(); // existing install: keyless

    let r = serve(&dir, &[]);
    let set = http(r.port, "/api?mode=config&name=apikey&value=chosen-key&output=json");
    assert!(set.contains("\"status\""), "set rejected: {set}");
    let anon = http(r.port, "/api?mode=version&output=json");
    assert!(rejected(&anon), "setting a key did not close the API: {anon}");

    drop(r);
    let r2 = serve(&dir, &[]);
    let ok = http(r2.port, "/api?mode=version&apikey=chosen-key&output=json");
    assert!(ok.contains("version"), "dashboard-set key lost across a restart: {ok}");
    let anon = http(r2.port, "/api?mode=version&output=json");
    assert!(rejected(&anon), "dashboard-set key not enforced after a restart: {anon}");
}

/// (d) --bind exists, still defaults to 0.0.0.0, and narrows the listener
///     when asked.
#[test]
fn bind_parses_and_defaults_to_all_interfaces() {
    let help = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .args(["serve", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&help.stdout).to_string();
    let line = help
        .lines()
        .skip_while(|l| !l.contains("--bind"))
        .take(4)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!line.is_empty(), "serve has no --bind option\n{help}");
    assert!(
        line.contains("0.0.0.0"),
        "--bind must still default to 0.0.0.0 (NAS + remote *arr deployments)\n{line}"
    );

    // An explicit narrow bind is honoured and still serves loopback.
    let dir = scratch("bind");
    let r = serve(&dir, &["--bind", "127.0.0.1", "--apikey", "sekrit"]);
    let ok = http(r.port, "/api?mode=version&apikey=sekrit&output=json");
    assert!(ok.contains("version"), "--bind 127.0.0.1 did not serve loopback: {ok}");

    // The rest needs this machine's LAN address, and proving the wide
    // bind reaches it means opening an all-interfaces listener. On macOS
    // that is a firewall prompt on EVERY run: the test binary is freshly
    // built at a new hashed path with a new ad-hoc signature each time,
    // which is exactly the shape the firewall re-asks about. The prompt
    // is not the port and not a missed `--bind` - it is the wide listener
    // itself, so the only way to stop it is not to open one.
    //
    // Off by default, therefore, and on in CI (and any run that wants
    // it) via NZBFAST_LAN_TESTS=1. What is lost while it is off is the
    // reachability half; the DEFAULT is still asserted from `--help`
    // above on every run, which is the part that would silently regress
    // a NAS install. `lan_ip()` is inside the gate too - it binds a UDP
    // socket to 0.0.0.0 and can prompt on its own.
    if std::env::var_os("NZBFAST_LAN_TESTS").is_none() {
        println!(
            "skipping the LAN reachability half: set NZBFAST_LAN_TESTS=1 to run it \
             (it opens an all-interfaces listener, which prompts the macOS firewall \
             on every rebuild)"
        );
        return;
    }

    // Where this machine has a routable LAN address, the difference is
    // observable: a loopback bind refuses it, the default accepts it.
    // Skipped on hosts with no such address (sandboxed CI).
    let Some(lan) = lan_ip() else { return };
    assert!(
        TcpStream::connect((lan, r.port)).is_err(),
        "--bind 127.0.0.1 still accepted a connection on {lan}"
    );
    drop(r);
    let dir = scratch("bind-default");
    // Named explicitly because `serve` narrows to loopback otherwise. That
    // the DEFAULT is this value is asserted from `--help` above; what is
    // proved here is that the wide bind actually reaches the LAN.
    let r = serve(&dir, &["--bind", "0.0.0.0", "--apikey", "sekrit"]);
    assert!(
        TcpStream::connect((lan, r.port)).is_ok(),
        "the wide bind must still serve {lan} - NAS boxes and remote *arrs depend on it"
    );
}

/// This host's routable IPv4, if it has one (no packets are sent).
fn lan_ip() -> Option<std::net::Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("203.0.113.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(a) if !a.is_loopback() && !a.is_unspecified() => Some(a),
        _ => None,
    }
}

//! nzbtray - the Windows wrapper around the nzbfast daemon.
//!
//! A no-console tray app: it
//! owns `nzbfast.exe serve` as a hidden child, the web dashboard stays
//! the only real UI. Hand-rolled win32 via windows-sys - a message
//! loop, one hidden window, Shell_NotifyIconW - because the tray-crate
//! ecosystem drags in GUI stacks the mingw static recipe doesn't need.
//!
//! Lifecycle rules (shared with the Mac wrapper):
//! - attach-or-spawn: if the persisted port answers a keyless
//!   mode=version as nzbfast - either the version body or our own
//!   "API Key Required/Incorrect" refusal, see `probe_body` - reuse it
//!   and NEVER kill it (we didn't spawn it); otherwise spawn on the
//!   first free port scanning up from 6789.
//! - spawn with NZBFAST_BUNDLED=1 (update self-swap gate), data in
//!   %LOCALAPPDATA%\nzbfast, downloads in %USERPROFILE%\Downloads\nzbfast.
//! - Quit = POST mode=shutdown, wait ≤5 s, then hard-kill; in-flight
//!   downloads resume from the journal next start.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("nzbtray is the Windows tray wrapper - nothing to do on this OS.");
}

#[cfg(windows)]
fn main() {
    app::run();
}

/// The tray's decisions that do not need win32: recognising an nzbfast
/// daemon from the body of an *unauthenticated* `mode=version` probe, and
/// working out which API key to speak to it with. Lives outside the win32
/// `app` module, and off `cfg(windows)`, so all of it is unit-testable on
/// any host (`cargo test -p nzbtray`) - `mod app` never compiles on the
/// machines these tests run on, so anything left in there is unguarded by
/// construction.
#[cfg(any(windows, test))]
mod probe_body {
    use serde_json::Value;
    use std::path::Path;

    /// A stored credential is usable only after trimming. Older nzbfast
    /// releases persisted `{"apikey":""}` when the user cleared the field;
    /// the daemon now treats that as absent and falls through to its minted
    /// key file, so the tray must do the same instead of shadowing the real
    /// key with an empty query value.
    pub fn stored_key(s: &str) -> Option<String> {
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_string())
    }

    /// Percent-encode a query value. Generated keys are hex, but user-chosen
    /// keys may contain `&`, `+`, `%` or `#`; sending those raw changes the
    /// parsed query and makes every tray action fail authentication.
    pub fn query_value(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
    }

    /// Read the daemon's API key from the data dir. Two sources, in the
    /// daemon's own precedence order: a key the user set in the dashboard
    /// (settings.json), else the one the daemon minted for itself on a
    /// first run (the `apikey` file - see serve::first_run_apikey). Before
    /// that minting existed a fresh install had no key at all and this
    /// returned None, which is still the answer for an install that is
    /// deliberately keyless.
    pub fn apikey(data_dir: &Path) -> Option<String> {
        let from_settings = || -> Option<String> {
            let s = std::fs::read_to_string(data_dir.join("settings.json")).ok()?;
            let v: Value = serde_json::from_str(&s).ok()?;
            stored_key(v.get("apikey")?.as_str()?)
        };
        let from_keyfile = || -> Option<String> {
            let k = std::fs::read_to_string(data_dir.join("apikey")).ok()?;
            stored_key(&k)
        };
        from_settings().or_else(from_keyfile)
    }

    /// An API URL that already has a query string, plus our credential.
    pub fn keyed_url(mut url: String, data_dir: &Path) -> String {
        if let Some(k) = apikey(data_dir) {
            url.push_str("&apikey=");
            url.push_str(&query_value(&k));
        }
        url
    }

    /// Dashboard URL, carrying the API key when we know one. The page
    /// adopts it into localStorage and strips it from the address bar, so
    /// the tray's own "Open dashboard" does not land the user on a prompt
    /// for a key that was generated for them and never shown.
    pub fn dash_url(port: u16, data_dir: &Path) -> String {
        match apikey(data_dir) {
            Some(k) => format!("http://127.0.0.1:{port}/?apikey={}", query_value(&k)),
            None => format!("http://127.0.0.1:{port}/"),
        }
    }

    /// Is this the answer of an nzbfast daemon?
    ///
    /// Two bodies count as ours:
    /// - the plain `mode=version` answer, which carries an `nzbfast` field;
    /// - the daemon's own refusal to answer without a key. Since 1.0.9 a
    ///   first run mints an API key for itself, so a fresh install answers
    ///   the anonymous probe with `{"status":false,"error":"API Key
    ///   Required"}` and never with the version body. Without this arm the
    ///   tray classified its own brand-new daemon as a stranger, waited out
    ///   the 15 s startup poll, and exited with an error box - on every
    ///   launch, since the installer, the Start Menu entry and autostart all
    ///   run the same exe.
    ///
    /// The probe stays keyless on purpose: nothing has authenticated the far
    /// side yet, and 6789 is well known, so sending the key would hand it to
    /// whatever process bound the port first - and it unlocks
    /// `mode=server_secret`, i.e. the Usenet password in cleartext. The
    /// refusal shape is what makes the key unnecessary (same reasoning as
    /// the Mac wrapper's `isNzbfast`).
    ///
    /// Deliberately narrow: a match means attach-and-never-kill, so only the
    /// two exact refusal phrases inside a `status:false` JSON object qualify
    /// - never "anything that answered HTTP".
    pub fn is_nzbfast(body: &str) -> bool {
        let Ok(v) = serde_json::from_str::<Value>(body) else {
            return false;
        };
        // `Value::get(&str)` is Some only for JSON objects, so both arms
        // below are object-only by construction.
        if v.get("nzbfast").is_some() {
            return true;
        }
        v.get("status").and_then(Value::as_bool) == Some(false)
            && matches!(
                v.get("error").and_then(Value::as_str),
                Some("API Key Required") | Some("API Key Incorrect")
            )
    }

    /// The port to look for first: what the DAEMON will bind, then what we
    /// last spawned it on.
    ///
    /// `settings.json` wins because the daemon's own precedence puts it
    /// above the `--port` flag we pass. Reading only `tray.json` meant that
    /// after a port change in the dashboard the tray probed the old port,
    /// found it free, spawned a daemon that bound the NEW one, then polled
    /// the old port for 15 s and gave up - leaving the daemon it had just
    /// started running with nothing attached to it. The Mac wrapper has
    /// always resolved the saved port this way.
    ///
    /// Out here rather than in `mod app` so the precedence is tested on
    /// every host, not only when someone builds for Windows.
    pub fn load_port(data_dir: &Path) -> Option<u16> {
        let from_settings = || -> Option<u16> {
            let s = std::fs::read_to_string(data_dir.join("settings.json")).ok()?;
            let v: Value = serde_json::from_str(&s).ok()?;
            // Settings values arrive as numbers or strings depending on which
            // path wrote them; accept both, reject anything out of range.
            let port = v.get("port")?;
            port.as_u64()
                .or_else(|| port.as_str()?.trim().parse().ok())
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p != 0)
        };
        let from_tray = || -> Option<u16> {
            let v: Value =
                serde_json::from_str(&std::fs::read_to_string(data_dir.join("tray.json")).ok()?)
                    .ok()?;
            u16::try_from(v.get("port")?.as_u64()?).ok().filter(|p| *p != 0)
        };
        from_settings().or_else(from_tray)
    }

    /// What `runtime.json` tells us about the daemon we expect to find:
    /// the port it bound and the per-start secret it will prove it holds.
    /// Absent for an older daemon, or a data dir it never started from.
    pub struct Runtime {
        pub port: u16,
        pub token: String,
    }

    pub fn runtime(data_dir: &Path) -> Option<Runtime> {
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(data_dir.join("runtime.json")).ok()?)
                .ok()?;
        let port = u16::try_from(v.get("port")?.as_u64()?).ok().filter(|p| *p != 0)?;
        let token = stored_key(v.get("token")?.as_str()?)?;
        Some(Runtime { port, token })
    }

    /// A nonce for one probe. Not a secret and not a key - it only has to
    /// differ between probes so a recorded answer cannot be replayed - so
    /// process id, address entropy and a counter are enough, and this stays
    /// free of a random-number dependency.
    pub fn probe_nonce() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let counter = N.fetch_add(1, Ordering::Relaxed);
        let stack = &counter as *const _ as usize as u64;
        let clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        format!("{:016x}{:016x}", clock ^ stack, counter ^ std::process::id() as u64)
    }

    /// Does this reply prove the listener is the daemon `runtime.json`
    /// describes?
    ///
    /// The daemon answers `mode=version&hs=<nonce>` with
    /// `sha256(token:nonce)`. The token itself never travels, so a probe
    /// sent to an impostor teaches it nothing, and only a process that can
    /// read our user-only `runtime.json` can produce the answer.
    ///
    /// `false` for a reply with no proof at all, which is what an OLDER
    /// daemon returns - the caller decides what to do about that (see
    /// `probe`), because refusing outright would break attaching to a
    /// daemon from the release before this one.
    pub fn proof_matches(body: &str, token: &str, nonce: &str) -> bool {
        use sha2::{Digest, Sha256};
        let Ok(v) = serde_json::from_str::<Value>(body) else {
            return false;
        };
        let Some(got) = v.get("hs_proof").and_then(Value::as_str) else {
            return false;
        };
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        h.update(b":");
        h.update(nonce.as_bytes());
        let want = h.finalize();
        // Constant-time-ish: the token is not guessable from a comparison
        // here anyway (an attacker who can see this process's memory has
        // already won), but there is no reason to leak the prefix length.
        let want_hex = want.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        want_hex.len() == got.len()
            && want_hex
                .bytes()
                .zip(got.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    /// Whether a reply carried a launcher proof at all - i.e. whether the
    /// far side is new enough to be held to it.
    pub fn has_proof(body: &str) -> bool {
        serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("hs_proof").and_then(Value::as_str).map(str::to_string))
            .is_some()
    }

    #[cfg(test)]
    mod tests {
        use super::{apikey, dash_url, is_nzbfast, keyed_url, query_value, stored_key};
        use std::path::PathBuf;

        #[test]
        fn version_body_is_ours() {
            assert!(is_nzbfast(r#"{"version":"4.5.0","nzbfast":"1.0.9"}"#));
        }

        /// The 1.0.9 regression: a keyed daemon refuses the keyless probe.
        /// Both refusals are still unmistakably a daemon we may attach to.
        #[test]
        fn auth_refusals_are_ours() {
            assert!(is_nzbfast(r#"{"status":false,"error":"API Key Required"}"#));
            assert!(is_nzbfast(r#"{"status":false,"error":"API Key Incorrect"}"#));
            // Field order and whitespace are the serialiser's business.
            assert!(is_nzbfast("{ \"error\" : \"API Key Required\" , \"status\" : false }"));
        }

        #[test]
        fn strangers_are_not_ours() {
            // Some other JSON service on the port.
            assert!(!is_nzbfast(r#"{"status":"ok","service":"grafana"}"#));
            // SABnzbd's own anonymous mode=version answer.
            assert!(!is_nzbfast(r#"{"version":"4.5.0"}"#));
            // Not JSON at all.
            assert!(!is_nzbfast("<html><body>hello</body></html>"));
            assert!(!is_nzbfast(""));
            // JSON, but not an object.
            assert!(!is_nzbfast(r#"["API Key Required"]"#));
            assert!(!is_nzbfast(r#""API Key Required""#));
        }

        /// The refusal arm must not become "any error body": attaching means
        /// never killing what we found, so a stranger's error page stays a
        /// stranger.
        #[test]
        fn other_error_bodies_are_not_ours() {
            assert!(!is_nzbfast(r#"{"status":false,"error":"Unauthorized"}"#));
            assert!(!is_nzbfast(r#"{"status":false,"error":"api key required"}"#));
            assert!(!is_nzbfast(r#"{"status":false}"#));
            // The phrases only count as a refusal, not as success.
            assert!(!is_nzbfast(r#"{"status":true,"error":"API Key Required"}"#));
            assert!(!is_nzbfast(r#"{"error":"API Key Required"}"#));
        }

        #[test]
        fn legacy_blank_key_falls_through_and_query_keys_are_escaped() {
            assert_eq!(stored_key(" \r\n"), None);
            assert_eq!(stored_key("  chosen key  ").as_deref(), Some("chosen key"));
            assert_eq!(query_value("a+b&c%# d"), "a%2Bb%26c%25%23%20d");
            assert_eq!(query_value("hex-._~09"), "hex-._~09");
        }

        /// A scratch data dir holding whichever of the two key sources
        /// the case needs.
        fn data_dir(name: &str, settings: Option<&str>, keyfile: Option<&str>) -> PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("nzbtray-key-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(s) = settings {
                std::fs::write(dir.join("settings.json"), s).unwrap();
            }
            if let Some(k) = keyfile {
                std::fs::write(dir.join("apikey"), k).unwrap();
            }
            dir
        }

        /// The two sources in the daemon's own precedence order, and the
        /// case that broke every tray action on an upgraded install: an
        /// older release persisted `{"apikey":""}` when the user cleared
        /// the field, and an empty value that is treated as SET shadows
        /// the key the daemon minted for itself - so the tray sent
        /// `&apikey=` and was refused by its own daemon.
        #[test]
        fn a_blank_stored_key_does_not_shadow_the_minted_one() {
            let minted = "0123456789abcdef";
            let d = data_dir("blank", Some(r#"{"apikey":"  "}"#), Some(minted));
            assert_eq!(apikey(&d).as_deref(), Some(minted));

            // A key the user really did set wins over the minted one.
            let d = data_dir("chosen", Some(r#"{"apikey":"mine"}"#), Some(minted));
            assert_eq!(apikey(&d).as_deref(), Some("mine"));

            // No settings file at all: the minted key still applies.
            let d = data_dir("keyonly", None, Some(minted));
            assert_eq!(apikey(&d).as_deref(), Some(minted));

            // A deliberately keyless install stays keyless - the tray must
            // not invent a credential or refuse to talk.
            let d = data_dir("none", Some("{}"), None);
            assert_eq!(apikey(&d), None);
        }

        /// Whatever the key turns out to be, it has to survive the query
        /// string. A user-chosen key containing `&` or `%` sent raw is a
        /// different key by the time the daemon parses it.
        #[test]
        fn urls_carry_the_key_escaped() {
            let d = data_dir("url", Some(r#"{"apikey":"a b&c"}"#), None);
            assert_eq!(
                keyed_url("http://127.0.0.1:6789/api?mode=queue".into(), &d),
                "http://127.0.0.1:6789/api?mode=queue&apikey=a%20b%26c"
            );
            assert_eq!(dash_url(6789, &d), "http://127.0.0.1:6789/?apikey=a%20b%26c");

            // Keyless: no empty parameter left dangling on either URL.
            let d = data_dir("urlnone", None, None);
            assert_eq!(
                keyed_url("http://127.0.0.1:6789/api?mode=queue".into(), &d),
                "http://127.0.0.1:6789/api?mode=queue"
            );
            assert_eq!(dash_url(6789, &d), "http://127.0.0.1:6789/");
        }

        /// The launcher handshake, which is what stands between "something
        /// answers on 6789 in our shape" and handing that something the API
        /// key (and with it `mode=server_secret`).
        #[test]
        fn only_the_daemon_holding_our_token_can_prove_it() {
            use super::{has_proof, proof_matches, runtime};
            use sha2::{Digest, Sha256};

            let token = "3c2f0f9a5e1d4b8f7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e";
            let nonce = "0123456789abcdef";
            let proof = |t: &str| {
                let mut h = Sha256::new();
                h.update(t.as_bytes());
                h.update(b":");
                h.update(nonce.as_bytes());
                h.finalize().iter().fold(String::new(), |mut s, b| {
                    use std::fmt::Write;
                    let _ = write!(s, "{b:02x}");
                    s
                })
            };

            let real = format!(
                r#"{{"status":false,"error":"API Key Required","nzbfast":"1.0.12","hs_proof":"{}"}}"#,
                proof(token)
            );
            assert!(has_proof(&real));
            assert!(proof_matches(&real, token, nonce));

            // An impostor can print our JSON - it cannot read the token file,
            // so it cannot answer the challenge.
            let impostor = r#"{"status":false,"error":"API Key Required","nzbfast":"1.0.12"}"#;
            assert!(!has_proof(impostor), "a reply with no proof must not pass as proven");
            assert!(!proof_matches(impostor, token, nonce));

            // Nor can it guess one, or replay another nonce's answer.
            let forged = format!(
                r#"{{"status":false,"error":"API Key Required","hs_proof":"{}"}}"#,
                proof("some other token")
            );
            assert!(has_proof(&forged));
            assert!(!proof_matches(&forged, token, nonce));
            assert!(!proof_matches(&real, token, "a-different-nonce"));

            // The daemon's own runtime.json is what supplies the pair.
            let d = data_dir("runtime", None, None);
            assert!(runtime(&d).is_none(), "no file means no expectation to hold it to");
            std::fs::write(
                d.join("runtime.json"),
                format!(r#"{{"pid":42,"port":6790,"token":"{token}","version":"1.0.12"}}"#),
            )
            .unwrap();
            let rt = runtime(&d).expect("a written runtime.json is read back");
            assert_eq!(rt.port, 6790);
            assert!(proof_matches(&real, &rt.token, nonce));

            // Truncated or tokenless files are treated as absent rather than
            // as an empty token that everything matches.
            std::fs::write(d.join("runtime.json"), r#"{"pid":42,"port":6790}"#).unwrap();
            assert!(runtime(&d).is_none());
            std::fs::write(d.join("runtime.json"), r#"{"port":6790,"token":"  "}"#).unwrap();
            assert!(runtime(&d).is_none());
        }

        /// Which port the tray looks for first. Reading only `tray.json`
        /// is what made it probe the OLD port after a dashboard port
        /// change, spawn a daemon that bound the new one, and then exit on
        /// timeout leaving that daemon orphaned.
        #[test]
        fn the_daemon_port_beats_the_one_we_last_spawned_on() {
            use super::load_port;

            let write = |dir: &std::path::Path, name: &str, body: &str| {
                std::fs::write(dir.join(name), body).unwrap();
            };

            // Nothing saved anywhere: the caller's scan range decides.
            let d = data_dir("port-none", None, None);
            assert_eq!(load_port(&d), None);

            // Only the tray's own note - the pre-dashboard case.
            let d = data_dir("port-tray", None, None);
            write(&d, "tray.json", r#"{"port": 6789}"#);
            assert_eq!(load_port(&d), Some(6789));

            // Both: settings.json wins, because that is what the daemon
            // itself applies over the --port we pass it.
            write(&d, "settings.json", r#"{"port": 6790}"#);
            assert_eq!(load_port(&d), Some(6790));

            // A port saved as a string still counts (different writers,
            // different JSON types), and 0 or out of range does not.
            write(&d, "settings.json", r#"{"port": "6791"}"#);
            assert_eq!(load_port(&d), Some(6791));
            for bad in [r#"{"port": 0}"#, r#"{"port": 70000}"#, r#"{"port": true}"#, "{}", "not json"] {
                write(&d, "settings.json", bad);
                assert_eq!(load_port(&d), Some(6789), "fell through to tray.json for {bad}");
            }
        }

        /// Two probes must not share a nonce, or a recorded answer replays.
        #[test]
        fn probe_nonces_differ() {
            use super::probe_nonce;
            let a = probe_nonce();
            let b = probe_nonce();
            assert_ne!(a, b);
            assert!(a.len() >= 16 && a.bytes().all(|c| c.is_ascii_alphanumeric()), "{a}");
        }
    }
}

#[cfg(windows)]
mod app {
    use serde_json::Value;
    use std::cell::RefCell;
    use std::io::Write as _;
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Registry::*;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::Shell::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const WM_TRAY: u32 = WM_APP + 1;
    /// Posted by a second `nzbtray.exe --quit` process to ask the running
    /// tray to shut down the way the menu item does. The installer uses it
    /// instead of terminating us, so the queue is persisted before an
    /// upgrade overwrites the exe.
    const WM_QUITAPP: u32 = WM_APP + 2;
    /// Must match nzbfast's serve::KEYLESS_MARKER. The tray cannot link
    /// against the daemon, so this is the one place the string is
    /// duplicated; a test in the daemon pins the pair together.
    const KEYLESS_MARKER: &str = "nzbfast cannot start: API key file";
    const TIMER_CHILD: usize = 1;

    /// Window class + title of the hidden message window, shared by the
    /// running tray and the `--quit` helper that has to find it.
    const MSG_CLASS: &str = "nzbtray_msg";
    const MSG_TITLE: &str = "nzbfast";

    // Menu command ids (TrackPopupMenu with TPM_RETURNCMD).
    const ID_DASH: u16 = 1;
    const ID_DOWNLOADS: u16 = 2;
    const ID_PAUSE: u16 = 3;
    const ID_AUTOSTART: u16 = 4;
    const ID_MANUAL: u16 = 5;
    const ID_RESTART: u16 = 6;
    const ID_QUIT: u16 = 7;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE: &str = "nzbfast";
    /// Ports to try above the base before giving up (50 is far beyond
    /// any realistic collision pile-up on a desktop).
    const BASE_PORT: u16 = 6789;
    const SCAN_SPAN: u16 = 50;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct App {
        port: u16,
        /// True when WE spawned the daemon (and may therefore stop it).
        owner: bool,
        child: Option<Child>,
        child_dead: bool,
        /// Last state seen when the menu opened - picks the Pause/Resume label.
        paused: bool,
        data_dir: PathBuf,
        out_dir: PathBuf,
        exe_dir: PathBuf,
    }

    thread_local! {
        static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    }

    // ---- small helpers ------------------------------------------------

    fn agent(timeout_ms: u64) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
    }

    use crate::probe_body::{dash_url, keyed_url, query_value};

    /// GET an API mode; None on any transport/JSON failure.
    fn api_get(port: u16, data_dir: &Path, mode: &str, timeout_ms: u64) -> Option<Value> {
        let url = keyed_url(
            format!("http://127.0.0.1:{port}/api?mode={mode}&output=json"),
            data_dir,
        );
        let body = agent(timeout_ms).get(&url).call().ok()?.into_string().ok()?;
        serde_json::from_str(&body).ok()
    }

    enum Probe {
        Nzbfast,
        Other,
        Free,
    }

    /// What lives on 127.0.0.1:port? Connection refused = free; a body
    /// `probe_body::is_nzbfast` recognises (the version answer OR the
    /// daemon's own auth refusal) is one of ours; anything else is a
    /// stranger. Sent WITHOUT the API key - see `probe_body::is_nzbfast`.
    ///
    /// A reply shape is not identity, though, and `Probe::Nzbfast` means
    /// attach-and-then-hand-over-the-API-key. So when `runtime.json` names
    /// THIS port, the listener must also prove it holds that file's
    /// per-start token (`probe_body::proof_matches`): any local account can
    /// print our JSON, but only our own user can read that file. A daemon
    /// too old to answer the challenge is accepted as before - refusing
    /// would break attaching across the upgrade - and everything else that
    /// fails the proof is a stranger.
    fn probe(port: u16, data_dir: &Path) -> Probe {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_err() {
            return Probe::Free;
        }
        let rt = crate::probe_body::runtime(data_dir).filter(|r| r.port == port);
        let nonce = crate::probe_body::probe_nonce();
        let url =
            format!("http://127.0.0.1:{port}/api?mode=version&output=json&hs={nonce}");
        let Some(body) = agent(900).get(&url).call().ok().and_then(|r| r.into_string().ok())
        else {
            return Probe::Other;
        };
        if !crate::probe_body::is_nzbfast(&body) {
            return Probe::Other;
        }
        match rt {
            // We know what should be here. Hold it to the proof, unless it
            // gave none at all (pre-handshake daemon).
            Some(rt) if crate::probe_body::has_proof(&body) => {
                if crate::probe_body::proof_matches(&body, &rt.token, &nonce) {
                    Probe::Nzbfast
                } else {
                    Probe::Other
                }
            }
            // No runtime.json for this port: an older daemon, or one started
            // from a different data dir. Unchanged behaviour.
            _ => Probe::Nzbfast,
        }
    }

    /// The user's real Downloads folder via the known-folder API - a
    /// OneDrive-redirected or relocated profile puts it far from
    /// %USERPROFILE%\Downloads, which stays as the fallback.
    fn downloads_dir() -> PathBuf {
        use windows_sys::Win32::System::Com::CoTaskMemFree;
        use windows_sys::core::GUID;
        const FOLDERID_DOWNLOADS: GUID = GUID {
            data1: 0x374DE290,
            data2: 0x123F,
            data3: 0x4565,
            data4: [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B],
        };
        unsafe {
            let mut p: *mut u16 = std::ptr::null_mut();
            if SHGetKnownFolderPath(&FOLDERID_DOWNLOADS, 0, std::ptr::null_mut(), &mut p) == 0
                && !p.is_null()
            {
                let mut len = 0usize;
                while *p.add(len) != 0 {
                    len += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                CoTaskMemFree(p as *const _);
                if !s.is_empty() {
                    return PathBuf::from(s);
                }
            }
        }
        let profile = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
        PathBuf::from(profile).join("Downloads")
    }

    fn prefs_path(data_dir: &Path) -> PathBuf {
        data_dir.join("tray.json")
    }

    fn save_port(data_dir: &Path, port: u16) {
        let tmp = prefs_path(data_dir).with_extension("json.tmp");
        if std::fs::write(&tmp, format!("{{\"port\": {port}}}\n")).is_ok() {
            let _ = std::fs::rename(&tmp, prefs_path(data_dir));
        }
    }

    fn open_url(url: &str) {
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                w("open").as_ptr(),
                w(url).as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }

    fn message_box(text: &str, flags: u32) -> i32 {
        unsafe {
            MessageBoxW(std::ptr::null_mut(), w(text).as_ptr(), w("nzbfast").as_ptr(), flags)
        }
    }

    fn log_tail(data_dir: &Path, lines: usize) -> String {
        std::fs::read_to_string(data_dir.join("daemon.log"))
            .map(|s| {
                let v: Vec<&str> = s.lines().rev().take(lines).collect();
                v.into_iter().rev().collect::<Vec<_>>().join("\n")
            })
            .unwrap_or_default()
    }

    // ---- daemon lifecycle ---------------------------------------------

    /// Rotate daemon.log at ~5 MB (keep one generation), then spawn the
    /// daemon on `port` with the wrapper contract: bundled flag, hidden
    /// window, explicit data-dir paths, cwd = data dir.
    fn spawn_daemon(exe_dir: &Path, data_dir: &Path, out_dir: &Path, port: u16) -> Option<Child> {
        let log_path = data_dir.join("daemon.log");
        if std::fs::metadata(&log_path).map(|m| m.len() > 5_000_000).unwrap_or(false) {
            let _ = std::fs::remove_file(data_dir.join("daemon.log.1"));
            let _ = std::fs::rename(&log_path, data_dir.join("daemon.log.1"));
        }
        let log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).ok()?;
        let log2 = log.try_clone().ok()?;
        Command::new(exe_dir.join("nzbfast.exe"))
            .args(["serve", "--port", &port.to_string()])
            .args(["--config", &data_dir.join("config.local.json").to_string_lossy()])
            .args(["--out", &out_dir.to_string_lossy()])
            // Watch the user's actual Downloads folder: save an .nzb the
            // way you save anything and it's queued automatically. Only
            // .nzb files are touched (consumed on ingest); the out dir
            // below it isn't scanned (non-recursive). A folder set in the
            // dashboard persists in settings.json and wins over this flag.
            .args(["--watch", &downloads_dir().to_string_lossy()])
            .args(["--index-db", &data_dir.join("index.db").to_string_lossy()])
            .env("NZBFAST_BUNDLED", "1")
            .current_dir(data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .ok()
    }

    /// Attach to a running nzbfast or spawn our own. Returns
    /// (port, spawned child). Shows an error box and exits on failure.
    fn ensure_daemon(exe_dir: &Path, data_dir: &Path, out_dir: &Path) -> (u16, Option<Child>) {
        // Persisted port first (the attach contract), then the scan range.
        let saved = crate::probe_body::load_port(data_dir);
        let candidates =
            saved.into_iter().chain((BASE_PORT..BASE_PORT + SCAN_SPAN).filter(|p| Some(*p) != saved));
        let mut spawn_at = None;
        for p in candidates {
            match probe(p, data_dir) {
                Probe::Nzbfast => return (p, None), // attach - not ours to manage
                Probe::Free => {
                    spawn_at = Some(p);
                    break;
                }
                Probe::Other => continue,
            }
        }
        let Some(port) = spawn_at else {
            message_box(
                &format!("No free port found (tried {BASE_PORT}–{}).", BASE_PORT + SCAN_SPAN),
                MB_ICONERROR,
            );
            std::process::exit(1);
        };
        let Some(child) = spawn_daemon(exe_dir, data_dir, out_dir, port) else {
            message_box(
                &format!(
                    "Couldn't start nzbfast.exe from:\n{}\n\nReinstalling nzbfast should fix this.",
                    exe_dir.display()
                ),
                MB_ICONERROR,
            );
            std::process::exit(1);
        };
        // The daemon opens its index db and binds before answering; give
        // it 15 s of 250 ms polls like the Mac wrapper.
        let t0 = Instant::now();
        let mut child = child;
        while t0.elapsed() < Duration::from_secs(15) {
            if matches!(probe(port, data_dir), Probe::Nzbfast) {
                return (port, Some(child));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // Timed out: the daemon we started is still ours, and exiting without
        // it leaves an orphan holding the spool, the queue and a listening
        // socket - with no tray to stop it and nothing to attach to it.
        // Whatever the timeout was caused by, it is not a reason to walk away
        // from a child process.
        let _ = child.kill();
        let _ = child.wait();
        message_box(
            &format!(
                "nzbfast didn't come up on port {port} within 15 s.\n\nLast log lines:\n{}",
                log_tail(data_dir, 20)
            ),
            MB_ICONERROR,
        );
        std::process::exit(1);
    }

    /// Multipart POST of one .nzb to addfile. Returns the queued name.
    fn post_nzb(port: u16, data_dir: &Path, path: &Path) -> Result<String, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "job.nzb".into());
        let boundary = "nzbtray9f4c2b7e";
        let mut body = Vec::with_capacity(bytes.len() + 512);
        let _ = write!(
            body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"nzbfile\"; \
             filename=\"{name}\"\r\nContent-Type: application/x-nzb\r\n\r\n"
        );
        body.extend_from_slice(&bytes);
        let _ = write!(body, "\r\n--{boundary}--\r\n");
        let url = keyed_url(
            format!("http://127.0.0.1:{port}/api?mode=addfile&output=json"),
            data_dir,
        );
        let resp = agent(10_000)
            .post(&url)
            .set("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
            .send_bytes(&body)
            .map_err(|e| format!("addfile: {e}"))?;
        let v: Value = serde_json::from_str(&resp.into_string().unwrap_or_default())
            .map_err(|e| format!("addfile parse: {e}"))?;
        if v.get("status").and_then(Value::as_bool) == Some(true) {
            Ok(name)
        } else {
            Err(v.get("error").and_then(Value::as_str).unwrap_or("rejected").to_string())
        }
    }

    /// Hand a clicked `nzblnk:` link to mode=addnzblnk. Returns the
    /// queued name.
    ///
    /// The link crosses VERBATIM as one query value: `nzbkit::nzblnk` in
    /// the daemon is the only parser, and the only one that is fuzzed.
    ///
    /// A longer timeout than post_nzb's: resolving a header can mean a
    /// round of searches against the user's indexers, where posting an
    /// .nzb is a local write.
    fn post_nzblnk(port: u16, data_dir: &Path, link: &str) -> Result<String, String> {
        let url = keyed_url(
            format!(
                "http://127.0.0.1:{port}/api?mode=addnzblnk&output=json&link={}",
                query_value(link)
            ),
            data_dir,
        );
        let resp = agent(45_000).get(&url).call().map_err(|e| format!("addnzblnk: {e}"))?;
        let v: Value = serde_json::from_str(&resp.into_string().unwrap_or_default())
            .map_err(|e| format!("addnzblnk parse: {e}"))?;
        if v.get("status").and_then(Value::as_bool) == Some(true) {
            Ok(v.get("name").and_then(Value::as_str).unwrap_or("download").to_string())
        } else {
            Err(v.get("error").and_then(Value::as_str).unwrap_or("rejected").to_string())
        }
    }

    // ---- graceful stop, for the installer -----------------------------

    /// Find the running tray's hidden window. It is a message-only window
    /// (HWND_MESSAGE parent), which the plain top-level FindWindowW search
    /// does not enumerate - the message-only pseudo-parent has to be named
    /// explicitly.
    fn find_tray_window() -> HWND {
        unsafe {
            FindWindowExW(
                HWND_MESSAGE,
                std::ptr::null_mut(),
                w(MSG_CLASS).as_ptr(),
                w(MSG_TITLE).as_ptr(),
            )
        }
    }

    /// `nzbtray.exe --quit`: stop the stack cleanly and wait for it to be
    /// gone. Exists so the installer can replace the exes without killing
    /// processes - an unsigned installer running `taskkill /F` is exactly
    /// the pattern Defender's ML heuristics score as malware, and it also
    /// discarded the queue instead of persisting it.
    ///
    /// Preferred path is asking the running tray, because the tray owns
    /// the daemon child and already has the drain-then-kill logic. Falling
    /// back to a direct shutdown POST covers a daemon started some other
    /// way (a console `nzbfast serve`, or a tray that already died).
    fn quit_running_instance(data_dir: &Path) {
        let hwnd = find_tray_window();
        if !hwnd.is_null() {
            unsafe { PostMessageW(hwnd, WM_QUITAPP, 0, 0) };
            // The tray gives its daemon 5 s to drain before hard-killing,
            // so allow a little more than that before giving up.
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(12) {
                if unsafe { IsWindow(find_tray_window()) } == 0 {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            // Still there: this is a tray from 1.0.8 or earlier. Those
            // register the same window class but have no WM_QUITAPP
            // handler, and their only route to a clean stop is the
            // tray-menu item, which nothing outside the process can
            // reach. So do by hand exactly what that menu item does -
            // drain the daemon over its own API, then close the window -
            // and fall through to the shared shutdown below.
            //
            // This is what makes an upgrade FROM a pre-1.0.9 install
            // possible at all: the Restart Manager cannot help, because
            // the tray's window is message-only (invisible to RM's
            // enumeration) and the daemon has no window whatsoever.
        }
        legacy_shutdown(data_dir);
    }

    /// Stop a running stack that cannot be asked nicely: shut the daemon
    /// down through the HTTP API it already exposes, then close the
    /// tray's window so its process exits and its image file unlocks.
    /// Both halves are cooperative - nothing here terminates a process.
    fn legacy_shutdown(data_dir: &Path) {
        if let Some(port) = crate::probe_body::load_port(data_dir) {
            if matches!(probe(port, data_dir), Probe::Nzbfast) {
                let url = keyed_url(
                    format!("http://127.0.0.1:{port}/api?mode=shutdown&output=json"),
                    data_dir,
                );
                let _ = agent(2000).post(&url).send_string("");
                let t0 = Instant::now();
                while t0.elapsed() < Duration::from_secs(8) {
                    if matches!(probe(port, data_dir), Probe::Free) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        // The daemon is down (or was never up). Now the tray itself: an
        // old tray answers WM_CLOSE through DefWindowProc, which destroys
        // the window and ends its message loop.
        let hwnd = find_tray_window();
        if hwnd.is_null() {
            return;
        }
        unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(8) {
            if unsafe { IsWindow(find_tray_window()) } == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // ---- autostart (HKCU Run) -----------------------------------------

    fn autostart_enabled() -> bool {
        unsafe {
            let mut ty = 0u32;
            let mut len = 0u32;
            RegGetValueW(
                HKEY_CURRENT_USER,
                w(RUN_KEY).as_ptr(),
                w(RUN_VALUE).as_ptr(),
                RRF_RT_REG_SZ,
                &mut ty,
                std::ptr::null_mut(),
                &mut len,
            ) == ERROR_SUCCESS
        }
    }

    fn set_autostart(on: bool) {
        unsafe {
            if on {
                let exe = std::env::current_exe().unwrap_or_default();
                let val = w(&format!("\"{}\"", exe.display()));
                let mut hkey = std::ptr::null_mut();
                if RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    w(RUN_KEY).as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    KEY_SET_VALUE,
                    std::ptr::null(),
                    &mut hkey,
                    std::ptr::null_mut(),
                ) == ERROR_SUCCESS
                {
                    RegSetValueExW(
                        hkey,
                        w(RUN_VALUE).as_ptr(),
                        0,
                        REG_SZ,
                        val.as_ptr().cast(),
                        (val.len() * 2) as u32,
                    );
                    RegCloseKey(hkey);
                }
            } else {
                let mut hkey = std::ptr::null_mut();
                if RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    w(RUN_KEY).as_ptr(),
                    0,
                    KEY_SET_VALUE,
                    &mut hkey,
                ) == ERROR_SUCCESS
                {
                    RegDeleteValueW(hkey, w(RUN_VALUE).as_ptr());
                    RegCloseKey(hkey);
                }
            }
        }
    }

    // ---- tray icon ----------------------------------------------------

    fn nid(hwnd: HWND) -> NOTIFYICONDATAW {
        let mut n: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        n.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        n.hWnd = hwnd;
        n.uID = 1;
        n
    }

    fn tray_add(hwnd: HWND) {
        let mut n = nid(hwnd);
        n.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        n.uCallbackMessage = WM_TRAY;
        // Resource id 1 (see build.rs); stock glyph if the resource is absent.
        n.hIcon = unsafe {
            let h = LoadImageW(
                GetModuleHandleW(std::ptr::null()),
                1 as _,
                IMAGE_ICON,
                0,
                0,
                LR_DEFAULTSIZE,
            );
            if h.is_null() {
                LoadIconW(std::ptr::null_mut(), IDI_APPLICATION)
            } else {
                h as HICON
            }
        };
        let tip = w("nzbfast");
        n.szTip[..tip.len()].copy_from_slice(&tip);
        unsafe { Shell_NotifyIconW(NIM_ADD, &n) };
    }

    fn tray_remove(hwnd: HWND) {
        unsafe { Shell_NotifyIconW(NIM_DELETE, &nid(hwnd)) };
    }

    fn balloon(hwnd: HWND, title: &str, text: &str) {
        let mut n = nid(hwnd);
        n.uFlags = NIF_INFO;
        n.dwInfoFlags = NIIF_INFO;
        let t = w(title);
        let x = w(text);
        n.szInfoTitle[..t.len().min(64)].copy_from_slice(&t[..t.len().min(64)]);
        n.szInfo[..x.len().min(256)].copy_from_slice(&x[..x.len().min(256)]);
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &n) };
    }

    // ---- menu ---------------------------------------------------------

    fn show_menu(hwnd: HWND) {
        let (port, data_dir, owner, child_dead, paused) = APP.with(|a| {
            let mut a = a.borrow_mut();
            let app = a.as_mut().unwrap();
            // Refresh the pause state while the user is mid-click; a slow
            // daemon just leaves the previous label.
            if let Some(q) = api_get(app.port, &app.data_dir, "queue", 900) {
                if let Some(p) = q.pointer("/queue/paused").and_then(Value::as_bool) {
                    app.paused = p;
                }
            }
            (app.port, app.data_dir.clone(), app.owner, app.child_dead, app.paused)
        });
        unsafe {
            let m = CreatePopupMenu();
            let add = |m, id: u16, label: &str, flags: u32| {
                AppendMenuW(m, flags, id as usize, w(label).as_ptr());
            };
            add(m, ID_DASH, "Open Dashboard", MF_STRING);
            add(m, ID_DOWNLOADS, "Open Downloads Folder", MF_STRING);
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            add(m, ID_PAUSE, if paused { "Resume" } else { "Pause" }, MF_STRING);
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            add(
                m,
                ID_AUTOSTART,
                "Start with Windows",
                MF_STRING | if autostart_enabled() { MF_CHECKED } else { 0 },
            );
            add(m, ID_MANUAL, "User Manual", MF_STRING);
            if owner && child_dead {
                AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
                add(m, ID_RESTART, "Restart nzbfast", MF_STRING);
            }
            AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
            add(m, ID_QUIT, "Quit nzbfast", MF_STRING);
            SetMenuDefaultItem(m, ID_DASH as u32, 0);

            let mut pt = POINT { x: 0, y: 0 };
            GetCursorPos(&mut pt);
            // Foreground first or the menu won't dismiss on outside-click
            // (the classic Shell_NotifyIcon menu gotcha).
            SetForegroundWindow(hwnd);
            let cmd = TrackPopupMenu(
                m,
                TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                pt.x,
                pt.y,
                0,
                hwnd,
                std::ptr::null(),
            );
            DestroyMenu(m);
            handle_command(hwnd, cmd as u16, port, &data_dir);
        }
    }

    fn handle_command(hwnd: HWND, cmd: u16, port: u16, data_dir: &Path) {
        match cmd {
            ID_DASH => open_url(&dash_url(port, data_dir)),
            ID_DOWNLOADS => {
                // Prefer the daemon's live out_dir (an attached daemon may
                // download somewhere other than our default).
                let dir = api_get(port, data_dir, "get_config", 1500)
                    .and_then(|v| {
                        v.pointer("/config/nzbfast/out_dir")
                            .and_then(Value::as_str)
                            .map(PathBuf::from)
                    })
                    .unwrap_or_else(|| APP.with(|a| a.borrow().as_ref().unwrap().out_dir.clone()));
                let _ = std::fs::create_dir_all(&dir);
                open_url(&dir.to_string_lossy());
            }
            ID_PAUSE => {
                let paused = APP.with(|a| a.borrow().as_ref().unwrap().paused);
                let mode = if paused { "resume" } else { "pause" };
                if api_get(port, data_dir, mode, 2000).is_some() {
                    APP.with(|a| a.borrow_mut().as_mut().unwrap().paused = !paused);
                }
            }
            ID_AUTOSTART => set_autostart(!autostart_enabled()),
            ID_MANUAL => open_url(&format!("http://127.0.0.1:{port}/manual")),
            ID_RESTART => restart_daemon(hwnd),
            ID_QUIT => quit(hwnd),
            _ => {}
        }
    }

    fn restart_daemon(hwnd: HWND) {
        APP.with(|a| {
            let mut a = a.borrow_mut();
            let app = a.as_mut().unwrap();
            if let Some(c) = spawn_daemon(&app.exe_dir, &app.data_dir, &app.out_dir, app.port) {
                app.child = Some(c);
                app.child_dead = false;
                balloon(hwnd, "nzbfast", "Restarting the download engine…");
            } else {
                balloon(hwnd, "nzbfast", "Restart failed - see daemon.log in the data folder.");
            }
        });
    }

    /// Graceful stop per the shared spec: POST mode=shutdown, give the
    /// daemon 5 s to persist and exit, then hard-kill. Attached daemons
    /// (not ours) are left running.
    fn quit(hwnd: HWND) {
        tray_remove(hwnd);
        APP.with(|a| {
            let mut a = a.borrow_mut();
            let app = a.as_mut().unwrap();
            if let Some(child) = app.child.as_mut() {
                if child.try_wait().ok().flatten().is_none() {
                    let url = keyed_url(
                        format!(
                            "http://127.0.0.1:{}/api?mode=shutdown&output=json",
                            app.port
                        ),
                        &app.data_dir,
                    );
                    let _ = agent(2000).post(&url).send_string("");
                    let t0 = Instant::now();
                    while t0.elapsed() < Duration::from_secs(5) {
                        if child.try_wait().ok().flatten().is_some() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    if child.try_wait().ok().flatten().is_none() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            }
        });
        unsafe { PostQuitMessage(0) };
    }

    // ---- window proc / message loop -----------------------------------

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        unsafe {
        match msg {
            WM_TRAY => {
                match lp as u32 {
                    WM_LBUTTONDBLCLK => {
                        let (port, data_dir) = APP.with(|a| {
                            let b = a.borrow();
                            let app = b.as_ref().unwrap();
                            (app.port, app.data_dir.clone())
                        });
                        open_url(&dash_url(port, &data_dir));
                    }
                    WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                    _ => {}
                }
                0
            }
            // An `nzbtray.exe --quit` helper (the installer) asking for the
            // same clean stop the tray menu performs.
            WM_QUITAPP => {
                quit(hwnd);
                0
            }
            WM_TIMER if wp == TIMER_CHILD => {
                // Child-death watchdog: single-threaded try_wait poll (no
                // handle juggling across threads).
                let died = APP.with(|a| {
                    let mut a = a.borrow_mut();
                    let app = a.as_mut().unwrap();
                    if app.child_dead {
                        return false;
                    }
                    match app.child.as_mut().map(|c| c.try_wait()) {
                        Some(Ok(Some(status))) => {
                            app.child_dead = true;
                            Some(status)
                        }
                        _ => None,
                    }
                    .is_some()
                });
                if died {
                    // Some deaths are not "try again" deaths. A missing
                    // or unusable API key stops startup deliberately and
                    // will do so every time, so telling this user to hit
                    // Restart sends them round a loop with no way out and
                    // no idea why. The daemon writes the whole
                    // explanation to daemon.log before it exits; if that
                    // is what happened, show it and say nothing about
                    // restarting.
                    let dir = APP.with(|a| a.borrow().as_ref().unwrap().data_dir.clone());
                    let tail = log_tail(&dir, 40);
                    if let Some(at) = tail.find(KEYLESS_MARKER) {
                        message_box(&tail[at..], MB_ICONERROR);
                    } else {
                        balloon(
                            hwnd,
                            "nzbfast stopped unexpectedly",
                            "The download engine exited. Right-click the tray icon → Restart nzbfast.",
                        );
                    }
                }
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
        }
    }

    pub fn run() {
        // An unrecognised flag must NEVER fall through to a normal
        // startup. Every tray up to 1.0.8 did, and it cost us the 1.0.9
        // upgrade: the 1.0.9 installer calls `{app}\nzbtray.exe --quit`
        // on the tray it is replacing and waits for it to exit, so an
        // older tray answered the request to shut down by starting a
        // resident tray plus a fresh daemon that re-locked the install
        // directory, and Setup hung on "Preparing to Install" until it
        // was force-closed. That installer now version-gates the call,
        // but the gate only protects trays that ship AFTER it - this
        // check is what makes the next flag we invent survivable.
        //
        // Bare paths are not flags: non-.nzb ones are filtered below and
        // a plain launch is the normal double-click case.
        let unknown: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| a.starts_with('-') || a.starts_with('/'))
            .filter(|a| {
                !["--open", "--quit"].iter().any(|k| a.eq_ignore_ascii_case(k))
            })
            .collect();
        if !unknown.is_empty() {
            // Exit silently, including for --version/--help. This is a
            // GUI-subsystem binary with no console to print to, and the
            // obvious alternative - a message box - would block forever
            // whenever there is no desktop to show it on: a silent
            // installer, a scheduled task, a remote shell. Hanging an
            // unattended caller is the failure this whole check exists
            // to prevent, so it must not be reintroduced here.
            return;
        }

        // --open: always end by opening the dashboard, first run or not.
        // The installer passes it so setup finishes with the user looking
        // at the web UI (a reinstall/upgrade box isn't a "first run", so
        // the prefs-file heuristic alone would stay silent there).
        let open_ui = std::env::args_os()
            .skip(1)
            .any(|a| a.eq_ignore_ascii_case("--open"));
        let args: Vec<PathBuf> = std::env::args_os()
            .skip(1)
            .map(PathBuf::from)
            .filter(|p| {
                p.extension().is_some_and(|e| e.eq_ignore_ascii_case("nzb")) && p.exists()
            })
            .collect();
        // nzblnk: links, from the URL-scheme association the installer
        // writes. They cannot ride `args`: that filter demands a .nzb
        // extension AND that the path exists on disk, and a link is
        // neither a file nor a path. They survive the unknown-flag guard
        // above only because a link starts with neither `-` nor `/`.
        //
        // A scheme TEST, not a parse. The daemon owns the only NZBLNK
        // parser (nzbkit::nzblnk) and the tray deliberately does not
        // depend on nzbkit - pulling the engine crate in for a prefix
        // check would drag rusqlite and tokio into a tray that ships
        // with plain-HTTP ureq and nothing else. This is strictly
        // narrower than the daemon's own `looks_like`, which also peels
        // wrapping quotes and brackets; argv from the registry's "%1"
        // never has them. Narrower is the safe direction.
        let links: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| a.len() >= 7 && a.as_bytes()[..7].eq_ignore_ascii_case(b"nzblnk:"))
            .collect();

        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
        let data_dir = PathBuf::from(local).join("nzbfast");

        // --quit: stop a running stack and exit. Handled before the
        // single-instance mutex, or we would take the "already running"
        // branch and open the dashboard instead of closing it. Creates
        // nothing on disk: an uninstall must not resurrect the data dir.
        if std::env::args_os().skip(1).any(|a| a.eq_ignore_ascii_case("--quit")) {
            quit_running_instance(&data_dir);
            return;
        }
        // Finished downloads land inside the user's Downloads folder.
        // Pre-1.0.2 installs used Downloads\nzbfast - keep that when it
        // already exists so an upgrade doesn't split the library.
        let dl = downloads_dir();
        let legacy = dl.join("nzbfast");
        let out_dir =
            if legacy.is_dir() { legacy } else { dl.join("nzbfast downloads") };
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        let first_run = !prefs_path(&data_dir).exists();
        for d in [&data_dir, &out_dir] {
            let _ = std::fs::create_dir_all(d);
        }

        // Single instance: second launches hand their .nzb (or a dashboard
        // request) to the running stack and exit.
        unsafe {
            CreateMutexW(std::ptr::null(), 0, w("Local\\nzbfast-tray-single").as_ptr());
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let port = crate::probe_body::load_port(&data_dir).unwrap_or(BASE_PORT);
                if args.is_empty() && links.is_empty() {
                    open_url(&dash_url(port, &data_dir));
                } else {
                    for p in &args {
                        if let Err(e) = post_nzb(port, &data_dir, p) {
                            message_box(&format!("Couldn't queue {}:\n{e}", p.display()), MB_ICONERROR);
                        }
                    }
                    for l in &links {
                        if let Err(e) = post_nzblnk(port, &data_dir, l) {
                            message_box(&format!("Couldn't add that link:\n{e}"), MB_ICONERROR);
                        }
                    }
                }
                return;
            }
        }

        let (port, child) = ensure_daemon(&exe_dir, &data_dir, &out_dir);
        save_port(&data_dir, port);

        // Hidden message window + tray icon.
        let hwnd = unsafe {
            let hinst = GetModuleHandleW(std::ptr::null());
            let cls = w(MSG_CLASS);
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinst,
                hIcon: std::ptr::null_mut(),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: cls.as_ptr(),
            };
            RegisterClassW(&wc);
            CreateWindowExW(
                0,
                cls.as_ptr(),
                w(MSG_TITLE).as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                hinst,
                std::ptr::null(),
            )
        };

        APP.with(|a| {
            *a.borrow_mut() = Some(App {
                port,
                owner: child.is_some(),
                child,
                child_dead: false,
                paused: false,
                data_dir: data_dir.clone(),
                out_dir,
                exe_dir,
            })
        });
        tray_add(hwnd);
        unsafe { SetTimer(hwnd, TIMER_CHILD, 1000, None) };

        // File-association / drag-onto-exe path: queue, then say so.
        for p in &args {
            match post_nzb(port, &data_dir, p) {
                Ok(name) => balloon(hwnd, "nzbfast", &format!("Queued {name}")),
                Err(e) => {
                    message_box(&format!("Couldn't queue {}:\n{e}", p.display()), MB_ICONERROR);
                }
            }
        }
        // Same, for a link clicked while nothing was running yet.
        for l in &links {
            match post_nzblnk(port, &data_dir, l) {
                Ok(name) => balloon(hwnd, "nzbfast", &format!("Queued {name}")),
                Err(e) => {
                    message_box(&format!("Couldn't add that link:\n{e}"), MB_ICONERROR);
                }
            }
        }
        // First run ever (or --open from the installer): open the
        // dashboard so the welcome banner (add your Usenet server) is
        // actually seen. ensure_daemon has already confirmed the daemon
        // answers on this port, so the page can't land on a dead socket.
        if first_run || open_ui {
            open_url(&dash_url(port, &data_dir));
        }

        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

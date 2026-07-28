//! Opt-in indexing, end to end: the answer a user gives the setup wizard
//! (or the settings card) becomes a scan list, and never anything else.
//!
//! The property under test is a promise made to users: nzbfast indexes
//! NOTHING it was not asked to index. So the interesting assertions here
//! are the negative ones - an untouched install scans nothing, an
//! unrecognised answer resolves to nothing, and unticking removes only
//! what ticking added.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http(port: u16, req: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect daemon");
    write!(s, "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&apikey=sekrit&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

fn set(port: u16, name: &str, value: &str) {
    let enc: String = value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let r = api(port, &format!("mode=config&name={name}&value={enc}"));
    assert_eq!(r["status"], true, "set {name}={value}: {r}");
}

fn groups(port: u16) -> Vec<String> {
    api(port, "mode=get_config")["config"]["nzbfast"]["index_groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect()
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Running {
    _child: KillOnDrop,
    port: u16,
}

/// A scratch install whose group catalogue is already "fetched": the
/// daemon loads `groups.tsv` beside the index db at startup, which is
/// the same cache a real fetch writes. That is what lets this test
/// resolve interests without a provider.
fn scratch(name: &str, carried: &[&str], settings: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-interests-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), settings).unwrap();
    let mut tsv = String::from("#nzbfast-groups\t3\t1700000000\n");
    for g in carried {
        tsv.push_str(&format!("{g}\t1000000\t1700000000\ty\t\n"));
    }
    std::fs::write(dir.join("groups.tsv"), tsv).unwrap();
    dir
}

fn serve(dir: &Path) -> Running {
    let port = free_port();
    let out = std::fs::File::create(dir.join("daemon.log")).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_NO_ENRICH", "1")
        .env_remove("NZBFAST_OPEN")
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("serve")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--apikey")
        .arg("sekrit")
        .arg("--out")
        .arg(dir.join("complete"))
        .arg("--index-db")
        .arg(dir.join("index.db"))
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let running = Running { _child: KillOnDrop(child), port };
    for _ in 0..300 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return running;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("daemon never bound a port");
}

/// Wait for the startup task to turn the stored answer into groups. It
/// runs off a background task, so poll rather than sleep a fixed time.
fn wait_groups(port: u16, want: usize) -> Vec<String> {
    for _ in 0..100 {
        let g = groups(port);
        if g.len() >= want {
            return g;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    groups(port)
}

/// settings.json as it stands on disk right now.
fn saved(dir: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default();
    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
}

/// Poll settings.json until `key` is present, or give up. Applying an
/// interest runs off a background task, so this is a rendezvous, not a
/// sleep - and it is bounded, so a daemon that never writes fails the
/// assertion instead of hanging the suite.
fn wait_saved(dir: &Path, key: &str) -> serde_json::Value {
    for _ in 0..100 {
        let v = saved(dir);
        if !v[key].is_null() {
            return v;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    saved(dir)
}

/// The whole promise in one test: an install nobody has answered for
/// scans nothing at all, no matter how long it runs.
#[test]
fn an_unanswered_install_indexes_nothing() {
    let dir = scratch("unanswered", &["alt.binaries.teevee", "alt.binaries.moovee"], "{}");
    let d = serve(&dir);
    // Give the startup path the same window the answered case needs.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(groups(d.port).is_empty(), "something was indexed without being asked for");
    let j = api(d.port, "mode=interests");
    assert!(j["chosen"].as_array().unwrap().is_empty());
    // Every option is offered with the groups it stands for, so a UI can
    // show them before the user agrees to anything.
    let opts = j["options"].as_array().unwrap();
    assert!(opts.len() >= 5, "{j}");
    let linux = opts.iter().find(|o| o["key"] == "linux").expect("linux offered");
    assert!(!linux["groups"].as_array().unwrap().is_empty());
    assert_eq!(linux["scanning"], 0);
}

/// The wizard's answer, applied at startup from a catalogue that is
/// already on disk - the first-run order of events, since the wizard
/// runs before the daemon has ever connected.
#[test]
fn a_stored_answer_becomes_a_scan_list() {
    let dir = scratch(
        "answered",
        // The provider carries two of the four Linux groups and one of
        // the sport ones. Nothing else may be subscribed.
        &[
            "alt.binaries.linux.iso",
            "alt.binaries.linux",
            "alt.binaries.multimedia.sports",
            "alt.binaries.teevee",
        ],
        r#"{"index_interests":"linux,sports"}"#,
    );
    let d = serve(&dir);
    let g = wait_groups(d.port, 3);
    assert!(g.contains(&"alt.binaries.linux.iso".to_string()), "{g:?}");
    assert!(g.contains(&"alt.binaries.linux".to_string()), "{g:?}");
    assert!(g.contains(&"alt.binaries.multimedia.sports".to_string()), "{g:?}");
    // Not the groups this provider does not carry...
    assert!(!g.contains(&"a.b.cd.image.linux".to_string()), "a dead group was subscribed: {g:?}");
    // ...and emphatically not a TV group nobody asked for, even though
    // the provider has it and it is what the old one-click shortcut
    // would have picked.
    assert!(!g.contains(&"alt.binaries.teevee".to_string()), "{g:?}");
}

/// Ticking and unticking from the settings card, including the part
/// that matters most: unticking must not take a hand-typed group with
/// it, and answering "nothing" must leave nothing behind.
#[test]
fn ticking_and_unticking_are_symmetric() {
    let dir = scratch(
        "symmetric",
        &["alt.binaries.linux.iso", "alt.binaries.multimedia.sports", "alt.binaries.mine"],
        "{}",
    );
    let d = serve(&dir);
    set(d.port, "index_groups", "alt.binaries.mine");

    set(d.port, "index_interests", "linux");
    let g = wait_groups(d.port, 2);
    assert!(g.contains(&"alt.binaries.linux.iso".to_string()), "{g:?}");

    set(d.port, "index_interests", "linux,sports");
    let g = wait_groups(d.port, 3);
    assert!(g.contains(&"alt.binaries.multimedia.sports".to_string()), "{g:?}");

    // Unticking sport stops scanning sport, and only sport.
    set(d.port, "index_interests", "linux");
    std::thread::sleep(std::time::Duration::from_millis(400));
    let g = groups(d.port);
    assert!(!g.contains(&"alt.binaries.multimedia.sports".to_string()), "{g:?}");
    assert!(g.contains(&"alt.binaries.linux.iso".to_string()), "{g:?}");
    assert!(g.contains(&"alt.binaries.mine".to_string()), "a hand-picked group was removed: {g:?}");

    // Answering "nothing at all" leaves only what the user typed.
    set(d.port, "index_interests", "");
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert_eq!(groups(d.port), vec!["alt.binaries.mine".to_string()]);

    // An unrecognised answer resolves to nothing rather than to
    // something - the failure direction that matters.
    set(d.port, "index_interests", "everything,all,*");
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert_eq!(groups(d.port), vec!["alt.binaries.mine".to_string()]);
    assert!(api(d.port, "mode=interests")["chosen"].as_array().unwrap().is_empty());
}

/// What ticking an interest has to leave on disk. The scan list, the
/// record of which groups the preset owns, and the marker saying the
/// answer has been applied are one state: the marker means "these two
/// are already correct". Written separately, a failure between them
/// leaves a marker with no groups behind it, and the answer is then
/// never reconsidered - the interest is silently dropped for good.
#[test]
fn ticking_an_interest_records_groups_provenance_and_marker_together() {
    let dir = scratch("persisted", &["alt.binaries.linux.iso", "alt.binaries.mine"], "{}");
    let d = serve(&dir);
    set(d.port, "index_groups", "alt.binaries.mine");
    set(d.port, "index_interests", "linux");
    assert!(wait_groups(d.port, 2).contains(&"alt.binaries.linux.iso".to_string()));

    let s = wait_saved(&dir, "index_interests_applied");
    assert_eq!(s["index_interests_applied"], "linux", "{s}");
    let listed = |k: &str| -> Vec<String> {
        s[k].as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect()
    };
    assert!(
        listed("index_groups").contains(&"alt.binaries.linux.iso".to_string()),
        "the scan list must be on disk beside its marker: {s}"
    );
    assert_eq!(
        listed("index_interest_groups"),
        vec!["alt.binaries.linux.iso".to_string()],
        "the preset's provenance must be on disk beside the same marker - \
         without it the next untick has nothing to remove: {s}"
    );
    assert!(
        !listed("index_interest_groups").contains(&"alt.binaries.mine".to_string()),
        "a hand-picked group must never be recorded as preset-owned: {s}"
    );
}

/// An install from before provenance was recorded. Its groups really did
/// come from a preset, but nothing on disk says so, and unticking used to
/// remove NOTHING - re-ticking did not repair it either, because a group
/// that is already present is skipped and so never enters the owned set.
/// The only escape was hand-editing the settings file.
#[test]
fn an_upgrade_with_no_recorded_provenance_can_still_untick() {
    let dir = scratch(
        "upgrade",
        &["alt.binaries.linux.iso", "alt.binaries.mine"],
        // Answered and applied, groups in place, provenance key absent -
        // exactly what an upgrading install brings with it.
        r#"{"index_interests":"linux","index_interests_applied":"linux",
            "index_groups":["alt.binaries.linux.iso","alt.binaries.mine"]}"#,
    );
    let d = serve(&dir);
    assert_eq!(wait_groups(d.port, 2).len(), 2, "the stored scan list is carried over");
    // Startup reconstructs what the preset owns, conservatively: the
    // preset's groups intersected with what is actually being indexed.
    let s = wait_saved(&dir, "index_interest_groups");
    assert_eq!(
        s["index_interest_groups"],
        serde_json::json!(["alt.binaries.linux.iso"]),
        "{s}"
    );

    // And now the untick works, which is the whole point.
    set(d.port, "index_interests", "");
    for _ in 0..100 {
        if groups(d.port).len() < 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(
        groups(d.port),
        vec!["alt.binaries.mine".to_string()],
        "unticking a preset on an upgraded install must remove its groups, \
         and only its groups"
    );
}

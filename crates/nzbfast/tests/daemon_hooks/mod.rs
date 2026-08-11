//! §129 4a: the pre-queue hook against a real daemon - rewrite,
//! reject-to-history and the fail-open timeout. A sibling-dir child of
//! daemon.rs (the daemon_chip6 pattern) so the parent stays inside its
//! size-gate baseline; harness via `super::*`.
//!
//! Unix-only: these hooks are shell scripts, and the Windows leg of the
//! script contract is already exercised by the post-proc `.cmd` test.

#![cfg(unix)]

use super::*;

fn hook_nzb(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
         <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/1)\">\n    \
         <groups><group>alt.binaries.hook</group></groups>\n    <segments>\n      \
         <segment bytes=\"5000\" number=\"1\">{name}-seg@test</segment>\n    \
         </segments>\n  </file>\n</nzb>\n"
    )
}

fn write_hook(dir: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let hook = dir.join("prequeue.sh");
    std::fs::write(&hook, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    hook
}

fn upload_named(port: u16, name: &str, xml: &str, query_extra: &str) -> String {
    let boundary = "----prequeue";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"nzbfile\"; \
             filename=\"{name}.nzb\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http(
        port,
        &format!("/api?mode=addfile&apikey=sekrit&output=json{query_extra}"),
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    )
}

async fn hook_daemon(dir: &Path) -> Daemon {
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    serve(dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await
}

fn set_cfg(port: u16, name: &str, value: &str) {
    let value: String = value
        .bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~/".contains(&b) {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect();
    let r = http(
        port,
        &format!("/api?mode=config&apikey=sekrit&output=json&name={name}&value={value}"),
        None,
    );
    assert!(r.contains("\"status\":true"), "set {name}: {r}");
}

/// Accept with a full rewrite: rename, pp, recategorize, reprioritize -
/// and the SAB argument contract on the way in.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_hook_rewrites_the_add() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-rw-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(
        &dir,
        // Record the contract, then answer: accept, rename, pp 2,
        // category tv, keep script, priority 1.
        "printf 'args:%s|%s|%s|%s|%s|%s\\nenv:%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$5\" \"$6\" \
         \"$7\" \"$SAB_FILENAME\" \"$SAB_PP\" \"$SAB_CAT\" \"$SAB_GROUPS\" \
         > \"$(dirname \"$0\")/prequeue.out\"\n\
         printf '1\\nRenamed.Job\\n2\\ntv\\n\\n1\\n'\n",
    );
    let d = hook_daemon(&dir).await;
    let port = d.port;
    // Paused, so the runner never picks the job and the queue row is
    // stable to assert on.
    http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
    set_cfg(port, "pre_queue_script", &hook.to_string_lossy());

    let r = upload_named(
        port,
        "Original.Name",
        &hook_nzb("Original.Name"),
        "&cat=movies&pp=3",
    );
    assert!(r.contains("\"status\":true"), "{r}");

    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&q).unwrap();
    let slot = &v["queue"]["slots"][0];
    assert_eq!(slot["filename"], "Renamed.Job", "{slot}");
    assert_eq!(slot["cat"], "tv", "{slot}");
    // SAB priority 1 = High.
    assert_eq!(slot["priority"], "High", "{slot}");
    // The add asked for pp=3, the hook answered 2, and the hook's
    // answer outranks the request (record_add_params fills, never
    // clobbers).
    assert_eq!(slot["unpackopts"], "2", "{slot}");

    // The contract the script saw: name, the pp the add requested
    // (L6 - this used to be ""), category, priority (-100 = default
    // at hook time), size, first group, and the SAB_* env.
    let out = std::fs::read_to_string(dir.join("prequeue.out")).expect("hook ran");
    assert!(
        out.contains("args:Original.Name|3|movies|-100|5000|alt.binaries.hook"),
        "{out}"
    );
    assert!(
        out.contains("env:Original.Name.nzb|3|movies|alt.binaries.hook"),
        "{out}"
    );
}

/// Reject: the job files to history as Failed with the reason, the
/// spool .nzb survives, and a retry (which deliberately does NOT re-run
/// the hook) brings it back to the queue.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_hook_rejects_to_history_and_retry_escapes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-rj-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(&dir, "printf '0\\n'\n");
    let d = hook_daemon(&dir).await;
    let port = d.port;
    http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
    set_cfg(port, "pre_queue_script", &hook.to_string_lossy());

    let r = upload_named(port, "Unwanted.Post", &hook_nzb("Unwanted.Post"), "");
    assert!(r.contains("\"status\":true"), "{r}");
    let v: serde_json::Value = serde_json::from_str(&r).unwrap();
    let nzo = v["nzo_ids"][0].as_str().expect("nzo id").to_string();

    // Never queued; filed to history as Failed with the reason.
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let qv: serde_json::Value = serde_json::from_str(&q).unwrap();
    assert_eq!(qv["queue"]["noofslots"], 0, "{q}");
    let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
    let hv: serde_json::Value = serde_json::from_str(&h).unwrap();
    let slot = &hv["history"]["slots"][0];
    assert_eq!(slot["status"], "Failed", "{slot}");
    assert!(
        slot["fail_message"]
            .as_str()
            .is_some_and(|m| m.contains("pre-queue")),
        "the reason names the hook: {slot}"
    );

    // The escape hatch: retry re-queues it (and does not consult the
    // hook again - this hook rejects everything, so being back in the
    // queue IS the proof).
    let rr = http(
        port,
        &format!("/api?mode=retry&apikey=sekrit&output=json&value={nzo}"),
        None,
    );
    assert!(rr.contains("\"status\":true"), "{rr}");
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let qv: serde_json::Value = serde_json::from_str(&q).unwrap();
    assert_eq!(qv["queue"]["noofslots"], 1, "retry re-queued: {q}");
}

/// A hook that outlives its budget is killed and the add proceeds
/// untouched - fail-open, with the job's original name.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_hook_timeout_fails_open() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-to-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(&dir, "sleep 30\nprintf '0\\n'\n");
    let d = hook_daemon(&dir).await;
    let port = d.port;
    http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
    set_cfg(port, "pre_queue_script", &hook.to_string_lossy());
    set_cfg(port, "pre_queue_timeout_secs", "1");

    let r = upload_named(port, "Patient.Post", &hook_nzb("Patient.Post"), "");
    assert!(r.contains("\"status\":true"), "{r}");
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&q).unwrap();
    assert_eq!(v["queue"]["noofslots"], 1, "{q}");
    assert_eq!(
        v["queue"]["slots"][0]["filename"], "Patient.Post",
        "accepted untouched: {q}"
    );
}

/// The two knobs survive a restart - the third of the "three places"
/// (write arm, table row, restore path) the settings doctrine demands,
/// and the one that fails silently. String + number, so the boolean
/// sweep in settings_catalogue cannot cover them.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_settings_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-rs-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(&dir, "printf '1\\n'\n");
    {
        let d = hook_daemon(&dir).await;
        set_cfg(d.port, "pre_queue_script", &hook.to_string_lossy());
        set_cfg(d.port, "pre_queue_timeout_secs", "7");
    }
    let d = hook_daemon(&dir).await;
    let c = http(
        d.port,
        "/api?mode=get_config&apikey=sekrit&output=json",
        None,
    );
    let v: serde_json::Value = serde_json::from_str(&c).unwrap();
    let m = &v["config"]["nzbfast"];
    assert_eq!(
        m["pre_queue_script"].as_str(),
        Some(&*hook.to_string_lossy()),
        "{m}"
    );
    assert_eq!(m["pre_queue_timeout_secs"], 7, "{m}");
}

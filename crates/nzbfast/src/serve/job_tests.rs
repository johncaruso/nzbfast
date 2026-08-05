//! Unit tests for the pure helpers in serve/job.rs (TODO 106 phase 3).
//! Covers the gaps the serve/mod.rs test mod does not touch.

use super::*;
use std::path::{Path, PathBuf};

fn tdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-job-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---- choose_out_dir ----

#[test]
fn choose_out_dir_free_base_is_taken_as_is() {
    let base = PathBuf::from("/x/Show");
    let (dir, replaces) = choose_out_dir(&base, "Show", &|_| DirClaim::Free);
    assert_eq!(dir, base);
    assert_eq!(replaces, None);
}

#[test]
fn choose_out_dir_payload_at_base_records_replace_and_climbs() {
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Payload
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.2"));
    assert_eq!(replaces, Some(base));
}

#[test]
fn choose_out_dir_payload_on_numbered_sibling_is_not_replaced() {
    // Base is Active (another job), .2 holds a completed payload: the
    // numbered sibling is left alone and no replace is recorded.
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Active
        } else if p == Path::new("/x/Show.2") {
            DirClaim::Payload
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.3"));
    assert_eq!(replaces, None);
}

#[test]
fn choose_out_dir_active_climbs_without_replace() {
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Active
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.2"));
    assert_eq!(replaces, None);
}

#[test]
fn choose_out_dir_multi_step_climb_keeps_base_replace() {
    // Payload at base, Active at .2: climbs to .3, still replacing base.
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Payload
        } else if p == Path::new("/x/Show.2") {
            DirClaim::Active
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.3"));
    assert_eq!(replaces, Some(base));
}

// ---- is_season_dir ----

#[test]
fn season_dir_shapes() {
    assert!(is_season_dir(Path::new("/lib/Show/Season 01")));
    assert!(is_season_dir(Path::new("/lib/Show/Season 1")));
    assert!(is_season_dir(Path::new("/lib/Show/Season 007")));
    assert!(!is_season_dir(Path::new("/lib/Show/Season ")));
    assert!(!is_season_dir(Path::new("/lib/Show/Season 1a")));
    // Case-sensitive by design.
    assert!(!is_season_dir(Path::new("/lib/Show/season 01")));
    assert!(!is_season_dir(Path::new("/lib/Show")));
}

// ---- disk_full_failure ----

#[test]
fn disk_full_phrasings_match() {
    assert!(disk_full_failure("No space left on device"));
    assert!(disk_full_failure("There is not enough space on the disk."));
    assert!(disk_full_failure("unpack failed: disk full"));
}

#[test]
fn disk_full_is_case_insensitive() {
    assert!(disk_full_failure("NO SPACE LEFT ON DEVICE"));
    assert!(disk_full_failure("Not Enough Space on the disk"));
    assert!(disk_full_failure("DISK FULL"));
}

#[test]
fn disk_full_rejects_unrelated_messages() {
    assert!(!disk_full_failure("connection reset by peer"));
    assert!(!disk_full_failure(""));
}

#[cfg(unix)]
#[test]
fn disk_full_unix_numeric_form() {
    assert!(disk_full_failure("write failed (os error 28)"));
    // The closing paren keeps 28 from matching inside 280.
    assert!(!disk_full_failure("write failed (os error 280)"));
    // 112 is EHOSTDOWN on unix, not disk full.
    assert!(!disk_full_failure("write failed (os error 112)"));
}

// ---- dated_key ----

#[test]
fn dated_key_trims_trailing_group_tag() {
    let tokens = ["epl", "2026", "08", "22", "arsenal", "everton", "grp"];
    let key = dated_key(
        &tokens,
        1,
        4,
        "20260822",
        "EPL.2026.08.22.Arsenal.Everton-GRP",
    );
    assert_eq!(key, "epl/20260822 arsenal everton");
}

#[test]
fn dated_key_without_group_keeps_tail_intact() {
    let tokens = ["epl", "2026", "08", "22", "arsenal", "everton"];
    let key = dated_key(&tokens, 1, 4, "20260822", "EPL.2026.08.22.Arsenal.Everton");
    assert_eq!(key, "epl/20260822 arsenal everton");
}

#[test]
fn dated_key_group_not_last_token_is_kept() {
    // Tail ends in the group's word, but the token list's LAST token is
    // furniture, so the positional guard refuses the pop.
    let tokens = ["epl", "2026", "08", "22", "arsenal", "grp", "1080p"];
    let key = dated_key(&tokens, 1, 4, "20260822", "Whatever-GRP");
    assert_eq!(key, "epl/20260822 arsenal grp");
}

#[test]
fn dated_key_empty_tail_is_head_slash_date() {
    let tokens = ["nfl", "2026", "08", "22"];
    assert_eq!(
        dated_key(&tokens, 1, 4, "20260822", "NFL.2026.08.22"),
        "nfl/20260822"
    );
}

#[test]
fn dated_key_furniture_only_tail_is_empty() {
    let tokens = ["nfl", "2026", "08", "22", "1080p", "web"];
    assert_eq!(
        dated_key(&tokens, 1, 4, "20260822", "NFL.2026.08.22.1080p.WEB"),
        "nfl/20260822"
    );
}

#[test]
fn dated_key_date_first_gives_leading_slash() {
    let tokens = ["2026", "08", "22", "arsenal"];
    assert_eq!(
        dated_key(&tokens, 0, 3, "20260822", "2026.08.22.Arsenal"),
        "/20260822 arsenal"
    );
}

// ---- claim_extra_slot ----

fn slot(rank: u32, stem: &str, nzo: &str) -> crate::watchlist::Slot {
    crate::watchlist::Slot {
        rank,
        stem: stem.to_string(),
        quality: String::new(),
        nzo_id: nzo.to_string(),
        grabbed_at: 0,
        failed: Vec::new(),
    }
}

#[test]
fn claim_extra_slot_vacant_inserts() {
    let mut slots = std::collections::HashMap::new();
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "a", "n1"));
    assert_eq!(slots["k"].nzo_id, "n1");
}

#[test]
fn claim_extra_slot_better_occupant_refuses() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(5, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "b", "n2"));
    assert_eq!(slots["k"].nzo_id, "n1");
}

#[test]
fn claim_extra_slot_same_stem_always_overwrites() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(5, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "a", "n2"));
    assert_eq!(slots["k"].nzo_id, "n2");
    assert_eq!(slots["k"].rank, 3);
}

#[test]
fn claim_extra_slot_equal_rank_takes() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(3, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "b", "n2"));
    assert_eq!(slots["k"].nzo_id, "n2");
}

#[test]
fn claim_extra_slot_higher_rank_takes() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(3, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(5, "b", "n2"));
    assert_eq!(slots["k"].nzo_id, "n2");
}

// ---- nzb_sha ----

#[test]
fn nzb_sha_known_digests() {
    assert_eq!(
        nzb_sha(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        nzb_sha(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn nzb_sha_is_64_lowercase_hex() {
    let s = nzb_sha(b"anything at all");
    assert_eq!(s.len(), 64);
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

// ---- priority_name ----

#[test]
fn priority_names() {
    assert_eq!(priority_name(-3), "Duplicate");
    assert_eq!(priority_name(2), "Force");
    assert_eq!(priority_name(1), "High");
    assert_eq!(priority_name(-1), "Low");
    assert_eq!(priority_name(0), "Normal");
    assert_eq!(priority_name(7), "Normal");
    assert_eq!(priority_name(-100), "Normal");
    assert_eq!(priority_name(i32::MIN), "Normal");
}

// ---- job_json / job_from_json ----

fn minimal_job_value() -> Value {
    json!({
        "nzo_id": "n1",
        "name": "A.Release",
        "nzb_path": "/tmp/a.nzb",
        "out_dir": "/out/A.Release",
        "state": "Queued",
    })
}

#[test]
fn job_round_trip_preserves_fields() {
    let v = json!({
        "nzo_id": "n42",
        "name": "Show.S01E02.1080p",
        "nzb_path": "/tmp/show.nzb",
        "origin": "rss",
        "category": "tv",
        "state": "Completed",
        "total_bytes": 123_456u64,
        "out_dir": "/out/Show",
        "fail_message": "boom",
        "fail_detail": "stack",
        "priority": 1,
        "paused": true,
        "retries": 2,
        "dupe_key": "show/s1e2",
        "library": true,
        "fetched": true,
        "downloaded_bytes": 999u64,
        "elapsed_secs": 12.5,
        "finished_unix": 1_700_000_000i64,
        "nzb_sha": "abcd",
        "finalizing": true,
        "deferred": true,
        "defer_reason": "disk",
        "defer_count": 3,
        "password": "pw",
        "bad_blocks": 4u64,
        "verify_blocks": 10u64,
        "tv_sort": true,
        "smart_rule": "rule",
        "filed": false,
        "filed_suffix": " 1080p",
        "filed_title": " - Pilot",
        "filed_base": "Show - S01E02",
        "password_required": true,
        "eat_volumes_ok": true,
        "zip_packed": true,
        "unpack_blocked_by": "rar5",
        "move_split": "/src/part",
        "archive_shape": "rar",
        "inner_crc": 77u64,
        "identity_name": "Show",
        "identity_imdb": "tt0000001",
        "identity_src": "tmdb",
        "auto_retry_at": 5u64,
        "auto_retry_why": "transport",
        "pp_params": [["k", "v"], ["k2", "v2"]],
        "replaces": "/out/Show.prev",
        "failure_link": "https://x/fail",
        "failure_host": "x",
        "failure_https": true,
        "failure_depth": 2,
        "identify": "Show (2026)",
        "cleaned_files": 5u64,
        "cleaned_par2": 6u64,
        "cleaned_trash": true,
    });
    let j = job_from_json(&v).expect("parses");
    assert_eq!(j.nzo_id, "n42");
    assert_eq!(j.name, "Show.S01E02.1080p");
    assert_eq!(j.nzb_path, PathBuf::from("/tmp/show.nzb"));
    assert_eq!(j.origin, "rss");
    assert_eq!(j.category, "tv");
    assert_eq!(j.state, JobState::Completed);
    assert_eq!(j.total_bytes, 123_456);
    assert_eq!(j.out_dir, PathBuf::from("/out/Show"));
    assert_eq!(j.fail_message, "boom");
    assert_eq!(j.fail_detail, "stack");
    assert_eq!(j.priority, 1);
    assert!(j.paused);
    assert_eq!(j.retries, 2);
    assert_eq!(j.dupe_key.as_deref(), Some("show/s1e2"));
    assert!(j.library);
    assert!(j.fetched);
    assert_eq!(j.downloaded_bytes, 999);
    assert_eq!(j.elapsed_secs, 12.5);
    assert_eq!(j.finished_unix, Some(1_700_000_000));
    assert_eq!(j.nzb_sha, "abcd");
    assert!(j.finalizing);
    assert!(j.deferred);
    assert_eq!(j.defer_reason, "disk");
    assert_eq!(j.defer_count, 3);
    assert_eq!(j.password.as_deref(), Some("pw"));
    assert_eq!(j.bad_blocks, Some(4));
    assert_eq!(j.verify_blocks, 10);
    assert!(j.tv_sort);
    assert_eq!(j.smart_rule, "rule");
    assert!(!j.filed);
    assert_eq!(j.filed_suffix.as_deref(), Some(" 1080p"));
    assert_eq!(j.filed_title.as_deref(), Some(" - Pilot"));
    assert_eq!(j.filed_base.as_deref(), Some("Show - S01E02"));
    assert!(j.password_required);
    assert!(j.eat_volumes_ok);
    assert!(j.zip_packed);
    assert_eq!(j.unpack_blocked_by, "rar5");
    assert_eq!(j.move_split, "/src/part");
    assert_eq!(j.archive_shape, "rar");
    assert_eq!(j.inner_crc, 77);
    assert_eq!(j.identity_name, "Show");
    assert_eq!(j.identity_imdb, "tt0000001");
    assert_eq!(j.identity_src, "tmdb");
    assert_eq!(j.auto_retry_at, Some(5));
    assert_eq!(j.auto_retry_why.as_deref(), Some("transport"));
    assert_eq!(
        j.pp_params,
        vec![
            ("k".to_string(), "v".to_string()),
            ("k2".to_string(), "v2".to_string())
        ]
    );
    assert_eq!(j.replaces, Some(PathBuf::from("/out/Show.prev")));
    assert_eq!(j.failure_link, "https://x/fail");
    assert_eq!(j.failure_host, "x");
    assert!(j.failure_https);
    assert_eq!(j.failure_depth, 2);
    assert_eq!(j.identify, "Show (2026)");
    assert_eq!(j.cleaned_files, 5);
    assert_eq!(j.cleaned_par2, 6);
    assert!(j.cleaned_trash);

    // Serialize and parse again: the persisted form is a fixed point.
    let v1 = job_json(&j);
    let j2 = job_from_json(&v1).expect("round-trips");
    assert_eq!(v1, job_json(&j2));
}

#[test]
fn job_from_json_missing_required_keys() {
    for key in ["nzo_id", "name", "nzb_path", "out_dir", "state"] {
        let mut v = minimal_job_value();
        v.as_object_mut().unwrap().remove(key);
        assert!(job_from_json(&v).is_none(), "missing {key} must be None");
    }
    assert!(job_from_json(&minimal_job_value()).is_some());
}

#[test]
fn job_from_json_unknown_state_reads_queued() {
    let mut v = minimal_job_value();
    v["state"] = json!("Bananas");
    assert_eq!(job_from_json(&v).unwrap().state, JobState::Queued);
    // A job caught mid-Downloading resumes as Queued too.
    v["state"] = json!("Downloading");
    assert_eq!(job_from_json(&v).unwrap().state, JobState::Queued);
    v["state"] = json!("Failed");
    assert_eq!(job_from_json(&v).unwrap().state, JobState::Failed);
}

#[test]
fn job_from_json_legacy_filed_migration() {
    // No `filed` key: tv_sort plus a season-shaped out_dir means filed.
    let mut v = minimal_job_value();
    v["tv_sort"] = json!(true);
    v["out_dir"] = json!("/lib/Show/Season 01");
    assert!(job_from_json(&v).unwrap().filed);

    // Season dir without tv_sort: not filed.
    let mut v = minimal_job_value();
    v["out_dir"] = json!("/lib/Show/Season 01");
    assert!(!job_from_json(&v).unwrap().filed);

    // tv_sort with a private dir: not filed.
    let mut v = minimal_job_value();
    v["tv_sort"] = json!(true);
    assert!(!job_from_json(&v).unwrap().filed);

    // An explicit `filed` wins over the shape test.
    let mut v = minimal_job_value();
    v["tv_sort"] = json!(true);
    v["out_dir"] = json!("/lib/Show/Season 01");
    v["filed"] = json!(false);
    assert!(!job_from_json(&v).unwrap().filed);
}

#[test]
fn job_from_json_bad_blocks_tri_state() {
    // Non-zero count is a verdict on its own.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(3u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, Some(3));

    // Zero with a companion block count: verified clean.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(0u64);
    v["verify_blocks"] = json!(10u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, Some(0));

    // Bare zero from a legacy record: unknowable, so not verified.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(0u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, None);

    // Zero with a zero block count: same unknowable.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(0u64);
    v["verify_blocks"] = json!(0u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, None);

    // Absent entirely.
    assert_eq!(
        job_from_json(&minimal_job_value()).unwrap().bad_blocks,
        None
    );
}

// ---- post_year_of ----

fn nzb_xml(dates: &[i64]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, d) in dates.iter().enumerate() {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"{d}\" subject=\"&quot;f{i}.rar&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"1000\" number=\"1\">id{i}@x</segment>\n    </segments>\n  </file>\n"
        ));
    }
    xml.push_str("</nzb>\n");
    xml
}

#[test]
fn post_year_of_unreadable_path_is_zero() {
    let d = tdir("post-year-missing");
    assert_eq!(post_year_of(&d.join("nope.nzb")), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn post_year_of_uses_newest_file_date() {
    let d = tdir("post-year-newest");
    let p = d.join("a.nzb");
    // 1_000 is 1970; 1_700_000_000 is November 2023. Newest wins.
    std::fs::write(&p, nzb_xml(&[1_000, 1_700_000_000])).unwrap();
    assert_eq!(
        post_year_of(&p),
        crate::identify::year_of_unix(1_700_000_000)
    );
    assert_eq!(post_year_of(&p), 2023);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn post_year_of_non_positive_dates_are_zero() {
    let d = tdir("post-year-zero");
    let p = d.join("a.nzb");
    std::fs::write(&p, nzb_xml(&[0, 0])).unwrap();
    assert_eq!(post_year_of(&p), 0);
    let _ = std::fs::remove_dir_all(&d);
}

// ---- file_count ----

#[test]
fn file_count_missing_dir_is_zero() {
    let d = tdir("file-count-missing");
    assert_eq!(file_count(&d.join("gone")), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn file_count_walks_nested_dirs() {
    let d = tdir("file-count-nested");
    std::fs::write(d.join("a.bin"), b"x").unwrap();
    std::fs::write(d.join("b.bin"), b"x").unwrap();
    let sub = d.join("sub");
    std::fs::create_dir_all(sub.join("deeper")).unwrap();
    std::fs::write(sub.join("c.bin"), b"x").unwrap();
    std::fs::write(sub.join("deeper").join("d.bin"), b"x").unwrap();
    assert_eq!(file_count(&d), 4);
    // An empty subdir adds nothing.
    std::fs::create_dir_all(d.join("empty")).unwrap();
    assert_eq!(file_count(&d), 4);
    let _ = std::fs::remove_dir_all(&d);
}

// ---- same_dir ----

#[test]
fn same_dir_equal_paths_true_even_when_missing() {
    let p = Path::new("/definitely/not/on/disk");
    assert!(same_dir(p, p));
}

#[test]
fn same_dir_distinct_dirs_false() {
    let a = tdir("same-dir-a");
    let b = tdir("same-dir-b");
    assert!(!same_dir(&a, &b));
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}

#[test]
fn same_dir_missing_path_falls_back_to_false() {
    let a = tdir("same-dir-missing");
    assert!(!same_dir(&a, &a.join("gone")));
    let _ = std::fs::remove_dir_all(&a);
}

#[test]
fn same_dir_dot_component_resolves_equal() {
    let a = tdir("same-dir-dot");
    assert!(same_dir(&a, &a.join(".")));
    let _ = std::fs::remove_dir_all(&a);
}

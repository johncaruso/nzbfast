//! Naming a finished job after its .nzb file (issue #32, TODO 142).
//!
//! The multi-file shapes are the point of this file. "Only the largest
//! file takes the name" is a promise about what does NOT move, so every
//! case here asserts the furniture by name after the rename, not just
//! the winner.

use super::super::testkit::*;
use super::*;

/// `name` in `dir`, `bytes` long, by `set_len` - no bytes are written.
///
/// Every size in this file is a THOUSANDTH of the release it stands
/// for: an 8 MB "feature" beside a 40 KB "sample". `main_payload` ranks
/// by length and nothing here reads an absolute size, so the ratios are
/// the whole content of a fixture and the magnitudes are decoration.
///
/// They started at the real figures, and `set_len` is only free on a
/// filesystem that hands back a hole. NTFS is not one: it reserves the
/// clusters, so the ten cases below really allocated ~15 GB, filled the
/// Windows CI runner's disk, and took out every later test in the run
/// with `ERROR_DISK_FULL` - including one in `rars` that had been green
/// for weeks. Sparseness is not portable; small is.
fn file(dir: &Path, name: &str, bytes: u64) -> PathBuf {
    let p = dir.join(name);
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(bytes).unwrap();
    p
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_movie_with_samples_and_subs_renames_only_the_feature() {
    let root = scratch("nzb-movie");
    let out = root.join("Example.Movie.2024.1080p.WEB-DL-GRP");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "Example.Movie.2024.1080p.WEB-DL-GRP.mkv", 8_000_000);
    file(&out, "sample.mkv", 40_000);
    file(&out, "Example.Movie.2024.1080p.WEB-DL-GRP.en.srt", 90);
    file(&out, "example-movie.nfo", 4);
    file(&out, "Example.Movie.2024.1080p.WEB-DL-GRP.par2", 500);

    let dest = rename_from_nzb(&root, &out, "My Movie Night 2024.nzb").unwrap();
    assert_eq!(
        dest,
        root.join("My Movie Night 2024"),
        "folder takes the name"
    );
    assert_portable("My Movie Night 2024");

    // The feature, and nothing else. A sample or a subtitle wearing the
    // release identity is the on-disk version of the wall's junk-rescore
    // hazard: the library imports the wrong file.
    assert_eq!(
        names(&dest),
        vec![
            "Example.Movie.2024.1080p.WEB-DL-GRP.en.srt",
            "Example.Movie.2024.1080p.WEB-DL-GRP.par2",
            "My Movie Night 2024.mkv",
            "example-movie.nfo",
            "sample.mkv",
        ]
    );
}

#[test]
fn an_episode_pack_renames_the_largest_episode_only() {
    let root = scratch("nzb-pack");
    let out = root.join("Example.Show.S01.1080p.WEB-GRP");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "Example.Show.S01E01.1080p.WEB-GRP.mkv", 2_000_000);
    // The biggest episode is deliberately NOT the first or the last.
    file(&out, "Example.Show.S01E02.1080p.WEB-GRP.mkv", 3_000_000);
    file(&out, "Example.Show.S01E03.1080p.WEB-GRP.mkv", 2_500_000);
    file(&out, "Example.Show.S01E02.1080p.WEB-GRP.srt", 80);

    let dest = rename_from_nzb(&root, &out, "Example Show season one").unwrap();
    assert_eq!(
        names(&dest),
        vec![
            "Example Show season one.mkv",
            "Example.Show.S01E01.1080p.WEB-GRP.mkv",
            "Example.Show.S01E02.1080p.WEB-GRP.srt",
            "Example.Show.S01E03.1080p.WEB-GRP.mkv",
        ],
        "every other episode keeps its own name"
    );
}

/// The reporter's "any download": no video at all, and the payload is
/// whatever the biggest real file is.
#[test]
fn a_non_video_job_names_its_biggest_payload_file() {
    let root = scratch("nzb-other");
    let out = root.join("some.software.post");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "setup.iso", 900_000);
    file(&out, "readme.txt", 2);
    file(&out, "post.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Installer disc").unwrap();
    assert_eq!(
        names(&dest),
        vec!["Installer disc.iso", "post.nfo", "readme.txt"]
    );
}

/// A job that never unpacked: the biggest file is a RAR volume, and
/// renaming one member of a multi-volume set breaks the set.
#[test]
fn a_still_packed_set_is_never_renamed() {
    let root = scratch("nzb-packed");
    let out = root.join("blob");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "blob.part01.rar", 500_000);
    file(&out, "blob.part02.rar", 500_000);
    file(&out, "blob.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Whatever This Is").unwrap();
    assert_eq!(
        names(&dest),
        vec!["blob.nfo", "blob.part01.rar", "blob.part02.rar"],
        "the volumes keep their names; only the folder moved"
    );
}

/// Our own state files are hidden on macOS and Linux and NOTHING on
/// Windows. A failed job keeps its journal so a retry fetches only what
/// is missing, so "it will not be there" is not a defence either.
#[test]
fn our_own_dotfiles_are_never_the_main_file() {
    let root = scratch("nzb-dot");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, ".nzbfast.journal", 900_000);
    file(&out, "payload.mkv", 100_000);

    let dest = rename_from_nzb(&root, &out, "Chosen Name").unwrap();
    assert_eq!(names(&dest), vec![".nzbfast.journal", "Chosen Name.mkv"]);
}

#[test]
fn a_folder_already_named_after_the_nzb_is_left_alone() {
    let root = scratch("nzb-noop");
    // Exactly what `enqueue` builds: the same sanitiser on the same
    // string. The common case is that only the file needs renaming.
    let out = root.join("Chosen Name");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "hash1fRbH6e0eX8v.mkv", 100_000);
    assert_eq!(rename_from_nzb(&root, &out, "Chosen Name.nzb"), None);
    assert_eq!(names(&out), vec!["Chosen Name.mkv"]);

    // A collision suffix is load-bearing - the unsuffixed name is
    // another job's payload - so it is not "tidied" back onto it.
    let out2 = root.join("Chosen Name.2");
    std::fs::create_dir_all(&out2).unwrap();
    file(&out2, "hash9zQ.mkv", 100_000);
    assert_eq!(rename_from_nzb(&root, &out2, "Chosen Name"), None);
    assert!(out.is_dir() && out2.is_dir());
}

#[test]
fn the_name_is_sanitised_the_way_the_job_folder_was() {
    let root = scratch("nzb-sanitize");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "payload.mkv", 10);
    // Path separators and control characters cannot reach the
    // filesystem; a name that survives that is used AS WRITTEN, dots
    // and all - tidying it up is what this option exists to stop.
    let dest = rename_from_nzb(&root, &out, "sub/dir\u{7}Name.2024.1080p").unwrap();
    let leaf = dest.file_name().unwrap().to_string_lossy().into_owned();
    assert_eq!(leaf, "sub_dir_Name.2024.1080p");
    assert_portable(&leaf);
    assert_eq!(names(&dest), vec!["sub_dir_Name.2024.1080p.mkv"]);
}

#[test]
fn a_name_with_nothing_usable_left_renames_nothing() {
    let root = scratch("nzb-empty");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "payload.mkv", 10);
    assert_eq!(rename_from_nzb(&root, &out, "  ...  "), None);
    assert_eq!(names(&out), vec!["payload.mkv"]);
}

/// An existing file already holds the target name. Leaving the main
/// file alone is the cheap outcome; overwriting a payload is not.
#[test]
fn a_taken_filename_is_not_overwritten() {
    let root = scratch("nzb-taken");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    file(&out, "big.mkv", 100);
    file(&out, "Taken.mkv", 50);
    let dest = rename_from_nzb(&root, &out, "Taken").unwrap();
    assert_eq!(names(&dest), vec!["Taken.mkv", "big.mkv"]);
    assert_eq!(
        std::fs::metadata(dest.join("Taken.mkv")).unwrap().len(),
        50,
        "the file that was already there is untouched"
    );
}

#[test]
fn an_extracted_subdirectory_is_reached_and_the_folder_still_moves() {
    let root = scratch("nzb-sub");
    let out = root.join("job");
    let inner = out.join("Example.Movie.2024");
    std::fs::create_dir_all(&inner).unwrap();
    file(&inner, "Example.Movie.2024.mkv", 4_000_000);
    file(&out, "job.nfo", 1);

    let dest = rename_from_nzb(&root, &out, "Movie Night").unwrap();
    assert_eq!(names(&dest), vec!["Example.Movie.2024", "job.nfo"]);
    assert_eq!(
        names(&dest.join("Example.Movie.2024")),
        vec!["Movie Night.mkv"],
        "renamed in place, one level down"
    );
}

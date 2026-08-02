//! One table mapping every container's spelling of a codec to one
//! canonical name, and one verdict per codec about how far it is from a
//! browser.
//!
//! The canonical spellings match [`crate::media::normalise_codec`]'s,
//! which the renamer and the identity oracles already use, with ONE
//! deliberate exception: HEVC is `hevc` here and `h265` there. The
//! difference is the audience - `h265` is the spelling release names
//! use, `hevc` is the spelling `MediaSource.isTypeSupported()` and the
//! RFC 6381 codec string use, and this table feeds the second. The
//! `the_two_codec_tables_agree` test pins the pair so neither can drift
//! into a third spelling.

use super::{Container, SubKind};

/// How far a codec is from playing in a browser tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecSupport {
    /// Browsers decode it directly.
    Native,
    /// The bytes are fine; only the container is wrong (phase 2's fMP4
    /// remux fixes that without touching a sample).
    RemuxOk,
    /// Needs a real transcoder - detected on PATH, never bundled.
    Transcode,
    /// Not in the table at all.
    NotRecognized,
}

struct Row {
    canon: &'static str,
    video: bool,
    /// Matroska CodecIDs, matched by PREFIX so sub-profiles
    /// (`A_AAC/MPEG4/LC`) land on their family.
    mkv: &'static [&'static str],
    /// MP4 sample-entry fourccs, matched exactly (lowercased).
    fourcc: &'static [&'static str],
    /// AVI biCompression fourccs, or `0x`-prefixed WAVE format tags.
    avi: &'static [&'static str],
    support: CodecSupport,
}

use CodecSupport::{Native, RemuxOk, Transcode};

const TABLE: &[Row] = &[
    // --- video ---
    Row {
        canon: "h264",
        video: true,
        mkv: &["v_mpeg4/iso/avc"],
        fourcc: &["avc1", "avc3"],
        avi: &["h264", "x264", "avc1"],
        support: Native,
    },
    Row {
        canon: "av1",
        video: true,
        mkv: &["v_av1"],
        fourcc: &["av01"],
        avi: &[],
        support: Native,
    },
    Row {
        canon: "vp9",
        video: true,
        mkv: &["v_vp9"],
        fourcc: &["vp09"],
        avi: &[],
        support: Native,
    },
    Row {
        canon: "vp8",
        video: true,
        mkv: &["v_vp8"],
        fourcc: &["vp08"],
        avi: &[],
        support: RemuxOk,
    },
    Row {
        canon: "hevc",
        video: true,
        mkv: &["v_mpegh/iso/hevc"],
        fourcc: &["hev1", "hvc1", "dvh1", "dvhe"],
        avi: &["hevc", "h265", "x265"],
        support: Transcode,
    },
    Row {
        canon: "mpeg2",
        video: true,
        mkv: &["v_mpeg2"],
        fourcc: &["mp2v"],
        avi: &["mpg2"],
        support: Transcode,
    },
    Row {
        canon: "mpeg4",
        video: true,
        mkv: &["v_mpeg4/iso/asp"],
        fourcc: &["mp4v"],
        avi: &["xvid", "divx", "dx50", "fmp4", "mp4v"],
        support: Transcode,
    },
    Row {
        canon: "vc1",
        video: true,
        // Matroska carries VC-1 through the VFW wrapper, so its id is
        // resolved from the CodecPrivate fourcc, not from this column.
        mkv: &["v_ms/vfw/wvc1"],
        fourcc: &["vc-1"],
        avi: &["wvc1"],
        support: Transcode,
    },
    Row {
        canon: "mjpeg",
        video: true,
        mkv: &["v_mjpeg"],
        fourcc: &["mjpg"],
        avi: &["mjpg"],
        support: Transcode,
    },
    // --- audio ---
    Row {
        canon: "aac",
        video: false,
        mkv: &["a_aac"],
        fourcc: &["mp4a"],
        avi: &["0x00ff", "0x1600"],
        support: Native,
    },
    Row {
        canon: "opus",
        video: false,
        mkv: &["a_opus"],
        fourcc: &["opus"],
        avi: &[],
        support: Native,
    },
    Row {
        canon: "flac",
        video: false,
        mkv: &["a_flac"],
        fourcc: &["flac"],
        avi: &[],
        support: Native,
    },
    Row {
        canon: "mp3",
        video: false,
        mkv: &["a_mpeg/l3"],
        fourcc: &[".mp3"],
        avi: &["0x0055"],
        support: Native,
    },
    Row {
        canon: "mp2",
        video: false,
        mkv: &["a_mpeg/l2"],
        fourcc: &[],
        avi: &["0x0050"],
        support: Transcode,
    },
    Row {
        canon: "vorbis",
        video: false,
        mkv: &["a_vorbis"],
        fourcc: &[],
        avi: &[],
        support: RemuxOk,
    },
    Row {
        canon: "ac3",
        video: false,
        mkv: &["a_ac3"],
        fourcc: &["ac-3"],
        avi: &["0x2000"],
        support: Transcode,
    },
    Row {
        canon: "eac3",
        video: false,
        mkv: &["a_eac3"],
        fourcc: &["ec-3"],
        avi: &["0x2001"],
        support: Transcode,
    },
    Row {
        canon: "dts",
        video: false,
        mkv: &["a_dts"],
        fourcc: &["dtsc", "dtsh", "dtse", "dtsl"],
        avi: &["0x2001"],
        support: Transcode,
    },
    Row {
        canon: "truehd",
        video: false,
        mkv: &["a_truehd", "a_mlp"],
        fourcc: &["mlpa"],
        avi: &[],
        support: Transcode,
    },
    Row {
        canon: "pcm",
        video: false,
        mkv: &["a_pcm/"],
        fourcc: &["lpcm", "sowt", "twos"],
        avi: &["0x0001"],
        support: Transcode,
    },
    Row {
        canon: "wma",
        video: false,
        mkv: &["a_wmav"],
        fourcc: &[],
        avi: &["0x0161", "0x0162"],
        support: Transcode,
    },
];

/// Container spelling to (canonical name, support). An id we do not
/// recognise comes back lowercased and untouched rather than dropped -
/// it is still a fact about the file, and the panel shows it.
pub fn lookup(container: Container, raw: &str, is_video: bool) -> (String, CodecSupport) {
    let low = raw.trim().to_ascii_lowercase();
    for row in TABLE {
        if row.video != is_video {
            continue;
        }
        let hit = match container {
            Container::Mkv | Container::Webm => row.mkv.iter().any(|p| low.starts_with(p)),
            Container::Mp4 => row.fourcc.iter().any(|p| low == *p),
            Container::Avi => row.avi.iter().any(|p| low == *p),
            Container::Unknown => false,
        };
        if hit {
            return (row.canon.to_string(), row.support);
        }
    }
    (low, CodecSupport::NotRecognized)
}

/// The verdict for an already-canonical name. Used by the playback rule,
/// which sees tracks after the container spelling has been resolved.
pub fn support_of(canon: &str, is_video: bool) -> CodecSupport {
    TABLE
        .iter()
        .find(|r| r.video == is_video && r.canon == canon)
        .map_or(CodecSupport::NotRecognized, |r| r.support)
}

/// Subtitle codecs. They never affect playback - a bitmap subtitle just
/// means the panel says "picture subtitles", which is exactly the kind
/// of thing a user wants to know BEFORE the download finishes.
pub fn lookup_sub(container: Container, raw: &str) -> (String, SubKind) {
    let low = raw.trim().to_ascii_lowercase();
    let table: &[(&str, &str, SubKind)] = match container {
        Container::Mp4 => &[
            ("tx3g", "tx3g", SubKind::Text),
            ("stpp", "ttml", SubKind::Text),
            ("wvtt", "webvtt", SubKind::Text),
            ("mp4s", "vobsub", SubKind::Bitmap),
            ("c608", "eia608", SubKind::Text),
        ],
        _ => &[
            ("s_text/utf8", "srt", SubKind::Text),
            ("s_text/srt", "srt", SubKind::Text),
            ("s_text/ass", "ass", SubKind::Text),
            ("s_text/ssa", "ass", SubKind::Text),
            ("s_text/webvtt", "webvtt", SubKind::Text),
            ("s_hdmv/pgs", "pgs", SubKind::Bitmap),
            ("s_hdmv/textst", "textst", SubKind::Text),
            ("s_vobsub", "vobsub", SubKind::Bitmap),
            ("s_dvbsub", "dvbsub", SubKind::Bitmap),
            ("s_kate", "kate", SubKind::Text),
        ],
    };
    for (pat, canon, kind) in table {
        let hit = match container {
            Container::Mp4 => low == *pat,
            _ => low.starts_with(pat),
        };
        if hit {
            return (canon.to_string(), *kind);
        }
    }
    (low, SubKind::Text)
}

/// Channel count to the name a viewer recognises.
pub fn channel_layout(n: u32) -> String {
    match n {
        0 => "unknown".to_string(),
        1 => "mono".to_string(),
        2 => "stereo".to_string(),
        3 => "2.1".to_string(),
        6 => "5.1".to_string(),
        8 => "7.1".to_string(),
        n => format!("{n} ch"),
    }
}

// ---------------------------------------------------------------------------
// H.273 colour code points - both containers write the same numbers
// ---------------------------------------------------------------------------

pub fn matrix_name(v: u64) -> Option<&'static str> {
    Some(match v {
        1 => "bt709",
        4 => "fcc",
        5 => "bt470bg",
        6 => "bt601",
        7 => "smpte240m",
        9 => "bt2020nc",
        10 => "bt2020c",
        14 => "ictcp",
        _ => return None,
    })
}

pub fn transfer_name(v: u64) -> Option<&'static str> {
    Some(match v {
        1 | 6 | 14 | 15 => "bt709",
        4 => "gamma22",
        5 => "gamma28",
        7 => "smpte240m",
        8 => "linear",
        16 => "pq",
        18 => "hlg",
        _ => return None,
    })
}

pub fn primaries_name(v: u64) -> Option<&'static str> {
    Some(match v {
        1 => "bt709",
        5 => "bt470bg",
        6 | 7 => "bt601",
        9 => "bt2020",
        11 | 12 => "dcip3",
        _ => return None,
    })
}

/// The badge the panel shows. PQ is HDR10 (or HDR10+ / Dolby Vision,
/// which we do not distinguish without reading the sample data), HLG is
/// broadcast HDR, and wide primaries with a transfer we could not read
/// is still worth flagging as HDR rather than silently calling it SDR.
pub fn hdr_format(transfer: Option<&str>, primaries: Option<&str>) -> String {
    match (transfer, primaries) {
        (Some("pq"), _) => "HDR10",
        (Some("hlg"), _) => "HLG",
        (_, Some("bt2020")) => "HDR",
        _ => "SDR",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_container_spelling_lands_on_one_name() {
        assert_eq!(
            lookup(Container::Mkv, "V_MPEG4/ISO/AVC", true).0,
            lookup(Container::Mp4, "avc1", true).0
        );
        // Matroska matches by prefix, so a sub-profile lands on its
        // family instead of falling through as unrecognised.
        assert_eq!(lookup(Container::Mkv, "A_AAC/MPEG4/LC/SBR", false).0, "aac");
        assert_eq!(lookup(Container::Mkv, "A_DTS/EXPRESS", false).0, "dts");
        assert_eq!(lookup(Container::Mkv, "A_PCM/INT/LIT", false).0, "pcm");
        assert_eq!(lookup(Container::Avi, "XVID", true).0, "mpeg4");
        assert_eq!(lookup(Container::Avi, "0x2000", false).0, "ac3");
        // An id nobody knows survives as itself.
        let (canon, sup) = lookup(Container::Mkv, "V_SOMETHING_NEW", true);
        assert_eq!(canon, "v_something_new");
        assert_eq!(sup, CodecSupport::NotRecognized);
    }

    /// A video codec name must never be read as an audio one: `mp4a`
    /// with an OTI the esds walk could not read must not accidentally
    /// match a video row.
    #[test]
    fn video_and_audio_rows_do_not_cross() {
        assert_eq!(
            lookup(Container::Mp4, "avc1", false).1,
            CodecSupport::NotRecognized
        );
        assert_eq!(
            lookup(Container::Mp4, "mp4a", true).1,
            CodecSupport::NotRecognized
        );
        assert_eq!(support_of("h264", false), CodecSupport::NotRecognized);
        assert_eq!(support_of("h264", true), CodecSupport::Native);
    }

    /// The one place two canonical spellings exist in this tree, pinned
    /// so a third cannot appear. Everything else must agree exactly with
    /// the naming path's table.
    #[test]
    fn the_two_codec_tables_agree() {
        for row in TABLE {
            for raw in row.mkv.iter().chain(row.fourcc).chain(row.avi) {
                if raw.starts_with("0x") || raw.ends_with('/') {
                    continue; // WAVE tags and prefix stubs are ours alone
                }
                let theirs = crate::media::normalise_codec(raw);
                let expected = if row.canon == "hevc" {
                    "h265"
                } else {
                    row.canon
                };
                // The naming table is allowed to not know an id; it must
                // never map one to a DIFFERENT codec than we do.
                if theirs != raw.trim_start_matches("v_").trim_start_matches("a_") {
                    assert_eq!(theirs, expected, "{raw}: {theirs} vs {}", row.canon);
                }
            }
        }
    }

    #[test]
    fn hdr_badges_follow_the_transfer_function() {
        assert_eq!(hdr_format(Some("pq"), Some("bt2020")), "HDR10");
        assert_eq!(hdr_format(Some("hlg"), Some("bt2020")), "HLG");
        // Wide primaries, transfer unreadable: still worth flagging.
        assert_eq!(hdr_format(None, Some("bt2020")), "HDR");
        assert_eq!(hdr_format(Some("bt709"), Some("bt709")), "SDR");
        assert_eq!(hdr_format(None, None), "SDR");
    }

    #[test]
    fn channel_counts_read_as_layouts() {
        assert_eq!(channel_layout(1), "mono");
        assert_eq!(channel_layout(2), "stereo");
        assert_eq!(channel_layout(6), "5.1");
        assert_eq!(channel_layout(8), "7.1");
        assert_eq!(channel_layout(12), "12 ch");
        assert_eq!(channel_layout(0), "unknown");
    }

    #[test]
    fn subtitle_kinds_separate_text_from_pictures() {
        assert_eq!(
            lookup_sub(Container::Mkv, "S_TEXT/UTF8"),
            ("srt".to_string(), SubKind::Text)
        );
        assert_eq!(
            lookup_sub(Container::Mkv, "S_HDMV/PGS"),
            ("pgs".to_string(), SubKind::Bitmap)
        );
        assert_eq!(
            lookup_sub(Container::Mp4, "stpp"),
            ("ttml".to_string(), SubKind::Text)
        );
    }
}

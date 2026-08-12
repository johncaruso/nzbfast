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

// ---------------------------------------------------------------------------
// RFC 6381 codec strings - the form a browser can be ASKED about
// ---------------------------------------------------------------------------

/// The RFC 6381 codec parameter for a video track, built from the very
/// bytes the container carries it in (§73 phase 2).
///
/// This is what makes the panel's playback verdict worth trusting. A
/// canonical name alone ("h264") cannot answer "will this play here":
/// browsers refuse H.264 High 10, and Safari plays HEVC while Chrome
/// does not. `canPlayType('video/mp4; codecs="avc1.6E0028"')` answers
/// exactly, and only the codec-private bytes can spell that string.
/// `None` when the container gave us no configuration record (AVI
/// always, a truncated MKV sometimes) - the client then falls back to a
/// coarse family test.
///
/// `cfg` is the raw configuration record: Matroska's CodecPrivate, or
/// the MP4 sample entry's `avcC` / `hvcC` / `av1C` / `vpcC` child.
pub fn rfc6381_video(canon: &str, cfg: Option<&[u8]>) -> Option<String> {
    let cfg = cfg?;
    match canon {
        // avcC: [1] profile_idc, [2] constraint flags, [3] level_idc.
        "h264" if cfg.len() >= 4 => {
            Some(format!("avc1.{:02X}{:02X}{:02X}", cfg[1], cfg[2], cfg[3]))
        }
        // hvcC, ISO/IEC 14496-15 Annex E: profile space as a letter,
        // profile idc, the compatibility flags with their BITS REVERSED
        // (Main's 0x60000000 is written "6"), tier + level, then the six
        // constraint bytes with trailing zero bytes dropped.
        "hevc" if cfg.len() >= 13 => {
            let space = match cfg[1] >> 6 {
                1 => "A",
                2 => "B",
                3 => "C",
                _ => "",
            };
            let idc = cfg[1] & 0x1F;
            let compat = u32::from_be_bytes([cfg[2], cfg[3], cfg[4], cfg[5]]).reverse_bits();
            let tier = if (cfg[1] >> 5) & 1 == 1 { 'H' } else { 'L' };
            let mut cons = String::new();
            let end = cfg[6..12]
                .iter()
                .rposition(|b| *b != 0)
                .map_or(0, |i| i + 1);
            for b in &cfg[6..6 + end] {
                use std::fmt::Write as _;
                let _ = write!(cons, ".{b:02X}");
            }
            Some(format!(
                "hvc1.{space}{idc}.{compat:X}.{tier}{}{cons}",
                cfg[12]
            ))
        }
        // av1C: [1] seq_profile + seq_level_idx, [2] tier, bit-depth bits.
        "av1" if cfg.len() >= 3 => {
            let profile = cfg[1] >> 5;
            let level = cfg[1] & 0x1F;
            let tier = if cfg[2] >> 7 == 1 { 'H' } else { 'M' };
            let depth = match ((cfg[2] >> 6) & 1, (cfg[2] >> 5) & 1) {
                (1, 1) => 12,
                (1, 0) => 10,
                _ => 8,
            };
            Some(format!("av01.{profile}.{level:02}{tier}.{depth:02}"))
        }
        // vpcC is a FullBox: four bytes of version+flags first.
        "vp9" if cfg.len() >= 7 => Some(format!(
            "vp09.{:02}.{:02}.{:02}",
            cfg[4],
            cfg[5],
            cfg[6] >> 4
        )),
        _ => None,
    }
}

/// The RFC 6381 codec parameter for an audio track.
///
/// No configuration record is needed: every one of these is a constant
/// per family, and the question the panel asks is "can this browser
/// decode this at all", not "at which profile". AAC answers as LC
/// (`mp4a.40.2`) because a browser that decodes LC decodes the HE
/// variants of it too, and nothing here distinguishes them.
pub fn rfc6381_audio(canon: &str) -> Option<String> {
    Some(
        match canon {
            "aac" => "mp4a.40.2",
            "mp3" => "mp4a.40.34",
            "ac3" => "ac-3",
            "eac3" => "ec-3",
            "opus" => "opus",
            "flac" => "flac",
            "vorbis" => "vorbis",
            "dts" => "dtsc",
            "truehd" => "mlpa",
            _ => return None,
        }
        .to_string(),
    )
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

    /// The strings a browser is asked about. Each expectation is a real
    /// one: `avc1.640029` is High@4.1, `hvc1.1.6.L93.B0` is the Main
    /// profile HEVC every phone records, `av01.0.05M.08` is AV1 Main.
    #[test]
    fn rfc6381_strings_match_the_configuration_bytes() {
        // avcC: version, profile_idc=100 (High), constraints, level=41.
        assert_eq!(
            rfc6381_video("h264", Some(&[1, 100, 0, 41])).as_deref(),
            Some("avc1.640029")
        );
        // High 10 spells itself out, which is the whole point: browsers
        // decode 8-bit H.264 and refuse this one.
        assert_eq!(
            rfc6381_video("h264", Some(&[1, 110, 0, 40])).as_deref(),
            Some("avc1.6E0028")
        );
        // hvcC: profile_space 0, tier L, profile_idc 1, compatibility
        // 0x60000000 (reversed -> 6), constraints B0, level 93.
        let hvcc = [1u8, 0x01, 0x60, 0, 0, 0, 0xB0, 0, 0, 0, 0, 0, 93];
        assert_eq!(
            rfc6381_video("hevc", Some(&hvcc)).as_deref(),
            Some("hvc1.1.6.L93.B0")
        );
        // Main 10, high tier.
        let hvcc10 = [1u8, 0x22, 0x20, 0, 0, 0, 0xB0, 0, 0, 0, 0, 0, 120];
        assert_eq!(
            rfc6381_video("hevc", Some(&hvcc10)).as_deref(),
            Some("hvc1.2.4.H120.B0")
        );
        // av1C: seq_profile 0, seq_level_idx 5, main tier, 8-bit.
        assert_eq!(
            rfc6381_video("av1", Some(&[0x81, 0x05, 0x00])).as_deref(),
            Some("av01.0.05M.08")
        );
        // vpcC carries four bytes of version+flags before its payload.
        assert_eq!(
            rfc6381_video("vp9", Some(&[0, 0, 0, 0, 2, 41, 0xA0])).as_deref(),
            Some("vp09.02.41.10")
        );
        // No configuration record, or a codec with no string worth
        // asking about: the client falls back to a family test.
        assert_eq!(rfc6381_video("h264", None), None);
        assert_eq!(rfc6381_video("mpeg4", Some(&[1, 2, 3, 4])), None);
        // A record too short to hold what it claims is not guessed at.
        assert_eq!(rfc6381_video("hevc", Some(&[1, 0x01, 0x60])), None);

        assert_eq!(rfc6381_audio("aac").as_deref(), Some("mp4a.40.2"));
        assert_eq!(rfc6381_audio("eac3").as_deref(), Some("ec-3"));
        assert_eq!(rfc6381_audio("pcm"), None);
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

//! AVI / RIFF: the header list only.
//!
//! AVI is a legacy container with no language tags, no chapters and no
//! colour signalling, so this reads exactly what it does carry: the
//! frame geometry, the frame rate, and one codec per stream. Everything
//! lives in `LIST hdrl` before `LIST movi`, which is the first two
//! megabytes of any real file.

use super::{
    AudioTrack, Container, MAX_TRACKS, MediaInfo, ProbeError, Rd, SubKind, SubTrack, VideoTrack,
    codec, normalize_lang, round3,
};
use std::io::{Read, Seek};

/// AVI headers sit at the very front; anything claiming otherwise is a
/// file we stop reading rather than scan.
const MAX_HEADER_BYTES: u64 = 2 << 20;

#[derive(Default)]
struct Stream {
    kind: [u8; 4],
    handler: [u8; 4],
    scale: u32,
    rate: u32,
}

pub(super) fn parse<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
) -> Result<(), ProbeError> {
    let file_end = rd.end;
    let end = file_end.min(MAX_HEADER_BYTES);
    let mut pos = 12u64; // past "RIFF" + size + "AVI "
    let mut stack: Vec<u64> = Vec::new();
    let mut stream = Stream::default();
    let mut us_per_frame = 0u32;
    let mut total_frames = 0u32;
    loop {
        while let Some(&fend) = stack.last() {
            if pos < fend {
                break;
            }
            stack.pop();
        }
        let limit = stack.last().copied().unwrap_or(end);
        if pos + 8 > limit {
            break;
        }
        if rd.budget.charge_element().is_err() {
            info.incomplete("file is too complex to inspect fully");
            break;
        }
        let mut h = [0u8; 8];
        match rd.read_exact_at(pos, &mut h) {
            Ok(()) => {}
            Err(e) if e.is_gap() => {
                info.incomplete("the header has not downloaded yet");
                break;
            }
            Err(_) => break,
        }
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&h[..4]);
        let size = u64::from(u32::from_le_bytes([h[4], h[5], h[6], h[7]]));
        let body = pos + 8;
        // Chunks are word-aligned: an odd size is followed by one pad
        // byte that belongs to nobody.
        let next = body.saturating_add(size).saturating_add(size & 1);
        if next <= pos || body > limit {
            break;
        }
        if &kind == b"LIST" || &kind == b"RIFF" {
            let mut t = [0u8; 4];
            if rd.read_exact_at(body, &mut t).is_err() {
                break;
            }
            // The payload list: every header we came for is behind us.
            if &t == b"movi" {
                break;
            }
            if stack.len() >= super::MAX_DEPTH {
                break;
            }
            stack.push(next.min(limit));
            pos = body + 4;
            continue;
        }
        match &kind {
            b"avih" => {
                let b = rd.read_leaf_at(body, size.min(56), 56)?;
                us_per_frame = u32_le(&b, 0).unwrap_or(0);
                total_frames = u32_le(&b, 16).unwrap_or(0);
            }
            b"strh" => {
                let b = rd.read_leaf_at(body, size.min(40), 40)?;
                stream = Stream::default();
                if b.len() >= 8 {
                    stream.kind.copy_from_slice(&b[..4]);
                    stream.handler.copy_from_slice(&b[4..8]);
                }
                stream.scale = u32_le(&b, 20).unwrap_or(0);
                stream.rate = u32_le(&b, 24).unwrap_or(0);
            }
            b"strf" => {
                let b = rd.read_leaf_at(body, size.min(64), 64)?;
                file_stream(info, &stream, &b);
            }
            _ => {}
        }
        pos = next.min(limit);
        if pos <= body {
            break;
        }
    }
    if us_per_frame > 0 && total_frames > 0 {
        info.duration_ms = Some(u64::from(total_frames) * u64::from(us_per_frame) / 1000);
    }
    if info.video.is_empty() && info.audio.is_empty() {
        info.incomplete("the header has not downloaded yet");
    }
    Ok(())
}

/// One `strf`, judged against the `strh` that introduced it.
fn file_stream(info: &mut MediaInfo, s: &Stream, b: &[u8]) {
    if info.video.len() + info.audio.len() + info.subtitles.len() >= MAX_TRACKS {
        return;
    }
    match &s.kind {
        b"vids" => {
            // BITMAPINFOHEADER. biCompression is the real codec id;
            // some muxers leave it zero and only the stream header's
            // handler says what the samples are.
            let width = u32_le(b, 4).unwrap_or(0);
            let height = i32::from_le_bytes(
                b.get(8..12)
                    .and_then(|x| x.try_into().ok())
                    .unwrap_or([0; 4]),
            )
            .unsigned_abs();
            let mut cc = [0u8; 4];
            cc.copy_from_slice(b.get(16..20).unwrap_or(&[0; 4]));
            if cc == [0; 4] {
                cc = s.handler;
            }
            let raw = String::from_utf8_lossy(&cc)
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_string();
            let (canon, _) = codec::lookup(Container::Avi, &raw, true);
            info.video.push(VideoTrack {
                codec: canon,
                codec_id: raw,
                width,
                height,
                display_ar: None,
                fps: (s.scale > 0)
                    .then(|| f64::from(s.rate) / f64::from(s.scale))
                    .and_then(round3),
                bit_depth: None,
                hdr: None,
                profile: None,
                level: None,
                bitrate: None,
                enabled: true,
                default: info.video.is_empty(),
            });
        }
        b"auds" => {
            // WAVEFORMATEX. The format tag is a number, not a fourcc,
            // so the raw id is written the way the table indexes it.
            let tag = u16_le(b, 0).unwrap_or(0);
            let raw = format!("0x{tag:04x}");
            let (canon, _) = codec::lookup(Container::Avi, &raw, false);
            let channels = u32::from(u16_le(b, 2).unwrap_or(0));
            info.audio.push(AudioTrack {
                codec: canon,
                codec_id: raw,
                // AVI has no language tags at all.
                lang: normalize_lang("und"),
                channels,
                channel_layout: codec::channel_layout(channels),
                sample_rate: u32_le(b, 4).filter(|v| *v > 0),
                title: None,
                default: info.audio.is_empty(),
                forced: false,
                bitrate: u32_le(b, 8).filter(|v| *v > 0).map(|v| u64::from(v) * 8),
                enabled: true,
            });
        }
        b"txts" => {
            let first = info.subtitles.is_empty();
            info.subtitles.push(SubTrack {
                codec: "text".into(),
                codec_id: String::from_utf8_lossy(&s.handler).trim().to_string(),
                lang: normalize_lang("und"),
                title: None,
                default: first,
                forced: false,
                kind: SubKind::Text,
            });
        }
        _ => {}
    }
}

fn u16_le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn an_avi_yields_its_geometry_codecs_and_runtime() {
        let b = super::super::testmux::avi();
        let i = super::super::probe(
            &mut Cursor::new(&b),
            super::super::ProbeHint {
                filename: Some("Some.Old.Rip.avi".into()),
                known_size: Some(b.len() as u64),
            },
        )
        .expect("a well-formed AVI probes");
        assert_eq!(i.container, Container::Avi);
        assert_eq!(i.video[0].codec, "mpeg4");
        assert_eq!(i.video[0].codec_id, "XVID");
        assert_eq!((i.video[0].width, i.video[0].height), (640, 352));
        assert_eq!(i.video[0].fps, Some(24.0));
        assert_eq!(i.audio[0].codec, "mp3");
        assert_eq!(i.audio[0].lang, "und");
        assert_eq!(i.duration_ms, Some(500));
        // Nothing a browser opens, but everything a viewer needs to
        // decide whether this is the right file.
        assert_eq!(i.playback, super::super::PlaybackPath::Transcode);
    }
}

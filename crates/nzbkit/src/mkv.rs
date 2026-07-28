//! Minimal Matroska/WebM header probe: duration and pixel dimensions.
//!
//! The renamer's resolution tag comes from whatever the POSTER wrote in
//! the subject, and posters lie - a "1080p" name over a 720p stream gets
//! stamped onto the final filename. The container itself knows. This is
//! a deliberately tiny EBML walk that answers exactly two questions -
//! how long, how wide - and nothing else: no external tools (the no-
//! bundled-ffmpeg rule), no seeking, no allocation beyond the head read.
//!
//! Untrusted input: completed downloads are attacker-shaped bytes, so
//! `parse` is pure over a slice, every offset is checked, containers are
//! depth-capped, and the walk is bounded by an element budget. The fuzz
//! harness drives `parse` directly (fuzz_targets/mkv_parse.rs).

/// What the head of the file said. Fields are independent - a muxer that
/// wrote no Duration still yields dimensions, and vice versa.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct MkvInfo {
    pub duration_secs: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// How much of the file `probe` reads. Info and Tracks sit in the first
/// few KB of every ordinary mux; the slack is for muxers that front-load
/// SeekHead padding, attachments or chapter furniture before them.
const HEAD: u64 = 4 << 20;

/// Containers we descend into. Everything else is skipped by size, so an
/// unknown or hostile element costs one size read and a bounds check.
const SEGMENT: u32 = 0x1853_8067;
const INFO: u32 = 0x1549_A966;
const TRACKS: u32 = 0x1654_AE6B;
const TRACK_ENTRY: u32 = 0xAE;
const VIDEO: u32 = 0xE0;
// Leaves.
const EBML_HEAD: u32 = 0x1A45_DFA3;
const TIMESTAMP_SCALE: u32 = 0x2A_D7B1;
const DURATION: u32 = 0x4489;
const TRACK_TYPE: u32 = 0x83;
const PIXEL_WIDTH: u32 = 0xB0;
const PIXEL_HEIGHT: u32 = 0xBA;

const MAX_DEPTH: usize = 8;
const MAX_ELEMENTS: usize = 10_000;

/// Read the head of `path` and parse it. `None` means "not a Matroska
/// file we could read", never an error worth reporting - the caller's
/// fallback is the filename claim it already had.
pub fn probe(path: &std::path::Path) -> Option<MkvInfo> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut head = Vec::new();
    f.take(HEAD).read_to_end(&mut head).ok()?;
    parse(&head)
}

/// EBML id: length from the leading-zero count of the first byte, value
/// kept WITH its marker bits, the way ids are written in the spec.
fn read_id(b: &[u8], at: usize) -> Option<(u32, usize)> {
    let first = *b.get(at)?;
    let len = (first.leading_zeros() as usize) + 1;
    if len > 4 || at + len > b.len() {
        return None;
    }
    let mut id: u32 = 0;
    for i in 0..len {
        id = (id << 8) | u32::from(b[at + i]);
    }
    Some((id, len))
}

/// EBML size vint: marker bit stripped. `None` in the value slot means
/// the all-ones "unknown size" - legal only on Segment, where it means
/// "to end of file".
fn read_size(b: &[u8], at: usize) -> Option<(Option<u64>, usize)> {
    let first = *b.get(at)?;
    let len = (first.leading_zeros() as usize) + 1;
    if len > 8 || at + len > b.len() {
        return None;
    }
    let mut v: u64 = u64::from(first) & (0xFF >> len);
    for i in 1..len {
        v = (v << 8) | u64::from(b[at + i]);
    }
    let all_ones = (1u64 << (7 * len)) - 1;
    Some(((v != all_ones).then_some(v), len))
}

fn read_uint(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 8 {
        return None;
    }
    Some(b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x)))
}

fn read_float(b: &[u8]) -> Option<f64> {
    match b.len() {
        0 => Some(0.0),
        4 => Some(f64::from(f32::from_be_bytes(b.try_into().ok()?))),
        8 => Some(f64::from_be_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

pub fn parse(b: &[u8]) -> Option<MkvInfo> {
    // The file must open with the EBML header; anything else is not
    // Matroska and not worth walking.
    let (first_id, _) = read_id(b, 0)?;
    if first_id != EBML_HEAD {
        return None;
    }

    let mut info = MkvInfo::default();
    let mut scale: f64 = 1_000_000.0; // TimestampScale default, ns
    let mut raw_duration: Option<f64> = None;

    // (container id, end offset) for every container we are inside.
    let mut stack: Vec<(u32, usize)> = Vec::new();
    // Per-TrackEntry fields; a muxer orders them freely, so they are
    // judged when the entry CLOSES, not when they are read.
    let mut track: (Option<u64>, Option<u32>, Option<u32>) = (None, None, None);

    let mut pos = 0usize;
    for _ in 0..MAX_ELEMENTS {
        // Close every container whose extent we have walked past.
        while let Some(&(id, end)) = stack.last() {
            if pos < end {
                break;
            }
            if id == TRACK_ENTRY {
                let (ty, w, h) = track;
                // TrackType 1 = video. Only the FIRST video track wins:
                // a second one is cover art or a hostile duplicate.
                if ty == Some(1) && info.width.is_none() && info.height.is_none() {
                    info.width = w;
                    info.height = h;
                }
                track = (None, None, None);
            }
            stack.pop();
        }
        if pos >= b.len() {
            break;
        }

        let (id, id_len) = read_id(b, pos)?;
        let (size, size_len) = read_size(b, pos + id_len)?;
        let body = pos + id_len + size_len;
        let end = match size {
            Some(s) => body.checked_add(usize::try_from(s).ok()?)?,
            // Unknown size: tolerated on the Segment alone, running to
            // the end of what we read.
            None if id == SEGMENT => b.len(),
            None => return None,
        };

        let descend = matches!(id, SEGMENT | INFO | TRACKS | TRACK_ENTRY | VIDEO);
        if descend {
            if stack.len() >= MAX_DEPTH {
                return None;
            }
            if id == TRACK_ENTRY {
                track = (None, None, None);
            }
            stack.push((id, end.min(b.len())));
            pos = body;
            continue;
        }

        // Leaf: the payload must be inside what we read to be believed.
        if end <= b.len() {
            let payload = &b[body..end];
            match id {
                TIMESTAMP_SCALE => {
                    if let Some(v) = read_uint(payload) {
                        if v > 0 {
                            scale = v as f64;
                        }
                    }
                }
                DURATION => raw_duration = read_float(payload),
                TRACK_TYPE => track.0 = read_uint(payload),
                PIXEL_WIDTH => track.1 = read_uint(payload).and_then(|v| u32::try_from(v).ok()),
                PIXEL_HEIGHT => track.2 = read_uint(payload).and_then(|v| u32::try_from(v).ok()),
                _ => {}
            }
            pos = end;
        } else {
            // Truncated leaf (the head read stopped mid-file): keep what
            // we have.
            break;
        }
    }

    // Flush containers still open at the end of the head.
    while let Some((id, _)) = stack.pop() {
        if id == TRACK_ENTRY {
            let (ty, w, h) = track;
            if ty == Some(1) && info.width.is_none() && info.height.is_none() {
                info.width = w;
                info.height = h;
            }
            track = (None, None, None);
        }
    }

    if let Some(d) = raw_duration {
        if d.is_finite() && d >= 0.0 {
            let secs = d * scale / 1e9;
            if secs.is_finite() {
                info.duration_secs = Some(secs);
            }
        }
    }
    (info.duration_secs.is_some() || info.width.is_some() || info.height.is_some())
        .then_some(info)
}

/// The resolution tag the measured dimensions deserve, in the same
/// spelling `release::res_of` produces. Buckets are Sonarr's, chosen off
/// real-world encodes: a 1912x800 scope crop is 1080p, not 800p.
pub fn res_bucket(width: u32, height: u32) -> &'static str {
    if width >= 3200 || height >= 2100 {
        "2160p"
    } else if width >= 1800 || height >= 1000 {
        "1080p"
    } else if width >= 1200 || height >= 700 {
        "720p"
    } else if width >= 1000 || height >= 560 {
        "576p"
    } else {
        "480p"
    }
}

/// id bytes as written, payload appended under a 1-or-2-byte size.
#[doc(hidden)]
pub fn el(id: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = id.to_vec();
    if payload.len() < 0x7F {
        v.push(0x80 | payload.len() as u8);
    } else {
        assert!(payload.len() < 0x3FFF);
        v.push(0x40 | (payload.len() >> 8) as u8);
        v.push((payload.len() & 0xFF) as u8);
    }
    v.extend_from_slice(payload);
    v
}

/// A minimal, valid mux for tests and fuzz seeds - ours and the callers'
/// (`smart` exercises the probe against real files on disk).
#[doc(hidden)]
pub fn test_mux(duration: Option<f64>, dims: Option<(u32, u32)>) -> Vec<u8> {
    let mut infos = el(&[0x2A, 0xD7, 0xB1], &1_000_000u32.to_be_bytes()); // scale 1ms
    if let Some(d) = duration {
        // Duration in scale units: d seconds = d * 1000 ms.
        infos.extend(el(&[0x44, 0x89], &((d * 1000.0) as f32).to_be_bytes()));
    }
    let mut entry = el(&[0x83], &[1]); // TrackType video
    if let Some((w, h)) = dims {
        let mut video = el(&[0xB0], &w.to_be_bytes()[2..]);
        video.extend(el(&[0xBA], &h.to_be_bytes()[2..]));
        entry.extend(el(&[0xE0], &video));
    }
    let mut seg = el(&[0x15, 0x49, 0xA9, 0x66], &infos);
    seg.extend(el(&[0x16, 0x54, 0xAE, 0x6B], &el(&[0xAE], &entry)));
    let mut out = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]); // EBML header, empty
    out.extend(el(&[0x18, 0x53, 0x80, 0x67], &seg));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mkv(duration: Option<f64>, dims: Option<(u32, u32)>) -> Vec<u8> {
        test_mux(duration, dims)
    }

    #[test]
    fn a_plain_mux_yields_duration_and_dimensions() {
        let b = sample_mkv(Some(5400.0), Some((1920, 1080)));
        let i = parse(&b).unwrap();
        assert!((i.duration_secs.unwrap() - 5400.0).abs() < 1.0);
        assert_eq!((i.width, i.height), (Some(1920), Some(1080)));
    }

    #[test]
    fn fields_are_independent() {
        let i = parse(&sample_mkv(None, Some((1280, 720)))).unwrap();
        assert_eq!(i.duration_secs, None);
        assert_eq!((i.width, i.height), (Some(1280), Some(720)));
        let i = parse(&sample_mkv(Some(90.0), None)).unwrap();
        assert!((i.duration_secs.unwrap() - 90.0).abs() < 1.0);
        assert_eq!((i.width, i.height), (None, None));
    }

    #[test]
    fn an_unknown_size_segment_still_parses() {
        // Streamed muxes write Segment with the unknown-size vint.
        let b = sample_mkv(Some(60.0), Some((1920, 800)));
        // Rebuild with Segment size FF (unknown, 1-byte vint all ones).
        let ebml = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
        let seg_body_at = {
            // sample_mkv wrote: ebml, then segment id(4) + size + body.
            let at = ebml.len() + 4;
            let (sz, sl) = super::read_size(&b, at).unwrap();
            (at + sl, sz.unwrap() as usize)
        };
        let mut out = ebml.clone();
        out.extend_from_slice(&[0x18, 0x53, 0x80, 0x67, 0xFF]);
        out.extend_from_slice(&b[seg_body_at.0..seg_body_at.0 + seg_body_at.1]);
        let i = parse(&out).unwrap();
        assert_eq!((i.width, i.height), (Some(1920), Some(800)));
    }

    #[test]
    fn a_non_video_track_contributes_no_dimensions() {
        // TrackType 2 (audio) carrying a Video element anyway: hostile
        // or broken, either way its numbers must not be believed.
        let mut entry = el(&[0x83], &[2]);
        let mut video = el(&[0xB0], &1920u32.to_be_bytes()[2..]);
        video.extend(el(&[0xBA], &1080u32.to_be_bytes()[2..]));
        entry.extend(el(&[0xE0], &video));
        let seg = el(&[0x16, 0x54, 0xAE, 0x6B], &el(&[0xAE], &entry));
        let mut out = el(&[0x1A, 0x45, 0xDF, 0xA3], &[]);
        out.extend(el(&[0x18, 0x53, 0x80, 0x67], &seg));
        assert_eq!(parse(&out), None);
    }

    #[test]
    fn hostile_shapes_return_none_not_panic() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"\x00"), None);
        assert_eq!(parse(b"not matroska at all"), None);
        // EBML magic then garbage sizes.
        assert_eq!(parse(&[0x1A, 0x45, 0xDF, 0xA3, 0xFF, 0xFF, 0xFF]), None);
        // Truncated mid-element.
        let b = sample_mkv(Some(60.0), Some((1920, 1080)));
        for cut in 0..b.len() {
            let _ = parse(&b[..cut]); // must not panic; value is free
        }
    }

    #[test]
    fn the_checked_in_fixture_parses() {
        // The same file seeds the fuzz corpus (fixtures/mkv/head.mkv);
        // this pins fixture and parser to each other.
        let b = include_bytes!("../tests/fixtures/mkv/head.mkv");
        let i = parse(b).unwrap();
        assert_eq!((i.width, i.height), (Some(1920), Some(1080)));
        assert!((i.duration_secs.unwrap() - 5400.0).abs() < 1.0);
    }

    #[test]
    fn buckets_match_real_encode_shapes() {
        assert_eq!(res_bucket(3840, 2160), "2160p");
        assert_eq!(res_bucket(1920, 1080), "1080p");
        assert_eq!(res_bucket(1912, 800), "1080p"); // scope crop
        assert_eq!(res_bucket(1280, 720), "720p");
        assert_eq!(res_bucket(1280, 536), "720p"); // scope crop
        assert_eq!(res_bucket(1024, 576), "576p");
        assert_eq!(res_bucket(720, 480), "480p");
        assert_eq!(res_bucket(640, 352), "480p");
    }
}

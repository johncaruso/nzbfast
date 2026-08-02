//! MP4 / ISO base media: the box walk.
//!
//! The property that makes this work on a file that is 3% downloaded:
//! `mdat` is never READ, only stepped over by arithmetic. A faststart
//! mux puts `moov` second, so the front of the file is enough. A mux
//! without faststart puts it at the very end, and then the only reads
//! are the 8-to-16 byte headers at each top-level boundary plus the
//! trailing `moov` itself - which is exactly the region the daemon's
//! playhead promotion keeps hot (`serve::stream::TAIL_KEEP`).

use super::{
    AudioTrack, Chapter, Container, Hdr, MAX_CHAPTERS, MAX_DEPTH, MAX_TRACKS, MediaInfo,
    PlaybackPath, ProbeError, Rd, SubTrack, VideoTrack, codec, normalize_lang, ratio, round3,
};
use std::io::{Read, Seek};

/// Boxes we descend into. Everything else is skipped by its size.
const CONTAINERS: [&[u8; 4]; 7] = [
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"udta",
];

const MAX_STSD_ENTRIES: u32 = 8;
const MAX_STTS_ENTRIES: u32 = 65_536;
/// `ftyp` is a brand list; nothing past a handful of brands matters.
const MAX_FTYP: usize = 256;
const MAX_ESDS: usize = 4 << 10;
/// A sample entry's child boxes (avcC, colr, btrt) are all small.
const MAX_CHILD: usize = 4 << 10;

#[derive(Default)]
struct TrackBuf {
    handler: Option<[u8; 4]>,
    enabled: bool,
    codec_id: Option<String>,
    canon: Option<String>,
    width: u32,
    height: u32,
    tk_width: u64,
    tk_height: u64,
    pasp: Option<(u64, u64)>,
    bit_depth: Option<u8>,
    profile: Option<String>,
    level: Option<String>,
    bitrate: Option<u64>,
    matrix: Option<String>,
    transfer: Option<String>,
    primaries: Option<String>,
    max_cll: Option<u32>,
    max_fall: Option<u32>,
    lang: Option<String>,
    channels: u32,
    sample_rate: Option<u32>,
    timescale: Option<u32>,
    duration: Option<u64>,
    sub_kind: Option<super::SubKind>,
    stts_samples: Option<u64>,
    stts_exact_fps: Option<f64>,
}

#[derive(Default)]
struct State {
    track: TrackBuf,
    saw_moov: bool,
}

pub(super) fn parse<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
) -> Result<(), ProbeError> {
    let mut st = State::default();
    let file_end = rd.end;
    let mut pos = 0u64;
    // Top-level scan. The loop's only reads are box headers, so the
    // cost of reaching a trailing moov is one read per top-level box.
    loop {
        if pos >= file_end {
            break;
        }
        if rd.budget.charge_element().is_err() {
            info.incomplete("file is too complex to inspect fully");
            break;
        }
        let hdr = match read_header(rd, pos, file_end) {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) if e.is_gap() => {
                info.incomplete(if st.saw_moov {
                    "the end of the file has not downloaded yet"
                } else {
                    "the index (moov) has not downloaded yet"
                });
                break;
            }
            Err(e) => return Err(e),
        };
        match &hdr.kind {
            b"ftyp" => {
                let brands = rd.read_leaf(hdr.end - hdr.body, MAX_FTYP)?;
                if brands.len() >= 4 && &brands[..4] == b"qt  " {
                    info.warn("QuickTime brand");
                }
            }
            b"moov" => {
                st.saw_moov = true;
                walk(rd, info, &mut st, hdr.body, hdr.end)?;
            }
            b"moof" => {
                info.warn("fragmented MP4");
            }
            _ => {}
        }
        pos = hdr.end;
    }
    if !st.saw_moov {
        info.incomplete("the index (moov) has not downloaded yet");
        info.playback = PlaybackPath::Unknown;
    }
    Ok(())
}

struct BoxHdr {
    kind: [u8; 4],
    body: u64,
    end: u64,
}

/// Read the 8-to-16 byte header at `at`. `Ok(None)` means "no box here"
/// (a truncated tail or a size that cannot advance), which ends the
/// walk without condemning what came before it.
fn read_header<R: Read + Seek>(
    rd: &mut Rd<R>,
    at: u64,
    limit: u64,
) -> Result<Option<BoxHdr>, ProbeError> {
    if at + 8 > limit {
        return Ok(None);
    }
    let mut h = [0u8; 8];
    rd.read_exact_at(at, &mut h)?;
    let size32 = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as u64;
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&h[4..8]);
    let (size, hlen) = match size32 {
        1 => {
            if at + 16 > limit {
                return Ok(None);
            }
            let mut big = [0u8; 8];
            rd.read_exact_at(at + 8, &mut big)?;
            (u64::from_be_bytes(big), 16u64)
        }
        // Size 0 means "to the end of the enclosing box", legal on the
        // last one only.
        0 => (limit - at, 8),
        _ => (size32, 8),
    };
    // A box smaller than its own header, or one claiming to run past
    // its parent, is a lie we do not follow.
    if size < hlen {
        return Ok(None);
    }
    let end = match at.checked_add(size) {
        Some(e) if e <= limit => e,
        _ => return Ok(None),
    };
    Ok(Some(BoxHdr {
        kind,
        body: at + hlen,
        end,
    }))
}

fn walk<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
    st: &mut State,
    start: u64,
    end: u64,
) -> Result<(), ProbeError> {
    let mut stack: Vec<([u8; 4], u64)> = Vec::new();
    let mut pos = start;
    loop {
        while let Some(&(kind, fend)) = stack.last() {
            if pos < fend {
                break;
            }
            if &kind == b"trak" {
                flush_track(info, st);
            }
            stack.pop();
        }
        let limit = stack.last().map_or(end, |&(_, e)| e);
        if pos >= limit {
            break;
        }
        if rd.budget.charge_element().is_err() {
            info.incomplete("file is too complex to inspect fully");
            break;
        }
        let hdr = match read_header(rd, pos, limit) {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) if e.is_gap() => {
                info.incomplete("the index (moov) has not fully downloaded yet");
                break;
            }
            Err(_) => break,
        };
        if hdr.end <= pos {
            break;
        }
        if CONTAINERS.contains(&&hdr.kind) {
            if stack.len() >= MAX_DEPTH {
                info.incomplete("the container nests too deeply to inspect");
                break;
            }
            if &hdr.kind == b"trak" {
                st.track = TrackBuf {
                    enabled: true,
                    ..TrackBuf::default()
                };
            }
            stack.push((hdr.kind, hdr.end));
            pos = hdr.body;
            continue;
        }
        match leaf(rd, info, st, &hdr) {
            Ok(()) => {}
            Err(e) if e.is_gap() => info.incomplete("part of the index has not downloaded yet"),
            Err(ProbeError::BudgetExceeded) => {
                info.incomplete("file is too complex to inspect fully");
                break;
            }
            Err(_) => info.incomplete("part of the index could not be read"),
        }
        pos = hdr.end;
    }
    while let Some((kind, _)) = stack.pop() {
        if &kind == b"trak" {
            flush_track(info, st);
        }
    }
    Ok(())
}

fn leaf<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
    st: &mut State,
    hdr: &BoxHdr,
) -> Result<(), ProbeError> {
    let len = hdr.end - hdr.body;
    match &hdr.kind {
        b"mvhd" => {
            let b = rd.read_leaf_at(hdr.body, len, 128)?;
            let (ts, dur) = match b.first() {
                Some(0) => (u32_at(&b, 12).map(u64::from), u32_at(&b, 16).map(u64::from)),
                Some(1) => (u32_at(&b, 20).map(u64::from), u64_at(&b, 24)),
                _ => (None, None),
            };
            if let (Some(ts), Some(d)) = (ts, dur)
                && ts > 0
                // u32::MAX / u64::MAX is how a fragmented mux writes
                // "I do not know" - not a 49-day movie.
                && d != u64::from(u32::MAX)
                && d != u64::MAX
            {
                info.duration_ms = Some(d.saturating_mul(1000) / ts);
            }
        }
        b"tkhd" => {
            let b = rd.read_leaf_at(hdr.body, len, 128)?;
            if let Some(flags) = u32_at(&b, 0) {
                st.track.enabled = flags & 1 != 0;
            }
            // Width and height are the last two 16.16 fields of the
            // box, in both versions.
            if b.len() >= 8 {
                st.track.tk_width = u32_at(&b, b.len() - 8).unwrap_or(0) as u64 >> 16;
                st.track.tk_height = u32_at(&b, b.len() - 4).unwrap_or(0) as u64 >> 16;
            }
        }
        b"mdhd" => {
            let b = rd.read_leaf_at(hdr.body, len, 64)?;
            let (ts, dur, lang_at) = match b.first() {
                Some(0) => (u32_at(&b, 12), u32_at(&b, 16).map(u64::from), 20),
                Some(1) => (u32_at(&b, 20), u64_at(&b, 24), 32),
                _ => (None, None, 0),
            };
            st.track.timescale = ts;
            st.track.duration = dur;
            if lang_at > 0
                && let Some(packed) = u16_at(&b, lang_at)
            {
                st.track.lang = Some(unpack_lang(packed));
            }
        }
        b"hdlr" => {
            let b = rd.read_leaf_at(hdr.body, len, 32)?;
            if b.len() >= 12 {
                let mut h = [0u8; 4];
                h.copy_from_slice(&b[8..12]);
                st.track.handler = Some(h);
            }
        }
        b"elst" => {
            let b = rd.read_leaf_at(hdr.body, len, 64)?;
            // Entry 0 with a positive media_time shifts playback; the
            // remuxer (phase 2) has to know, so flag it now.
            let media_time = match b.first() {
                Some(0) => u32_at(&b, 12).map(u64::from),
                Some(1) => u64_at(&b, 16),
                _ => None,
            };
            if media_time.is_some_and(|m| m > 0 && m != u64::from(u32::MAX)) {
                info.warn("edit list offsets playback");
            }
        }
        b"stsd" => stsd(rd, info, st, hdr.body, hdr.end)?,
        b"stts" => {
            let b = rd.read_leaf_at(hdr.body, len, 16)?;
            let count = u32_at(&b, 4).unwrap_or(0).min(MAX_STTS_ENTRIES);
            let mut total = 0u64;
            let mut single: Option<f64> = None;
            let mut at = hdr.body + 8;
            for i in 0..count {
                if at + 8 > hdr.end {
                    break;
                }
                let e = rd.read_leaf_at(at, 8, 8)?;
                let (n, delta) = (u32_at(&e, 0).unwrap_or(0), u32_at(&e, 4).unwrap_or(0));
                total += u64::from(n);
                if i == 0 && count == 1 && delta > 0 {
                    single = st
                        .track
                        .timescale
                        .map(|ts| f64::from(ts) / f64::from(delta));
                }
                at += 8;
            }
            st.track.stts_samples = Some(total);
            st.track.stts_exact_fps = single.and_then(round3);
        }
        b"chpl" => {
            // 9, not 8: the entry count sits AT byte 8 (the entries then
            // start at 9, which `at` below agrees with), so a leaf capped
            // at 8 bytes can only ever index 0..7 - `get(8)` was always
            // None and every Nero chapter list read as empty.
            let b = rd.read_leaf_at(hdr.body, len, 9)?;
            let count = usize::from(*b.get(8).unwrap_or(&0));
            let mut at = hdr.body + 9;
            for _ in 0..count.min(MAX_CHAPTERS) {
                if at + 9 > hdr.end || info.chapters.len() >= MAX_CHAPTERS {
                    break;
                }
                let head = rd.read_leaf_at(at, 9, 9)?;
                let start = u64_at(&head, 0).unwrap_or(0);
                let nlen = u64::from(head[8]);
                at += 9;
                let title = rd
                    .read_string_at(at, nlen.min(hdr.end.saturating_sub(at)))?
                    .unwrap_or_default();
                at += nlen;
                info.chapters.push(Chapter {
                    // Nero chapter times are in 100 ns units.
                    start_ms: start / 10_000,
                    title,
                });
            }
        }
        // QuickTime's own title atom, the MP4 twin of Matroska's
        // Segment>Info>Title.
        [0xA9, b'n', b'a', b'm'] => {
            if info.title.is_none() && len > 4 {
                // A 2-byte length and a 2-byte language precede the
                // text in the classic udta layout.
                info.title = rd.read_string_at(hdr.body + 4, len - 4)?;
            }
        }
        b"tref" => info.warn("chapter track present (not read)"),
        _ => {}
    }
    Ok(())
}

/// The sample description: one entry per codec configuration. Its own
/// sub-walk rather than a stack frame, because the entries are not
/// plain boxes - each has a fixed prologue before its children.
fn stsd<R: Read + Seek>(
    rd: &mut Rd<R>,
    info: &mut MediaInfo,
    st: &mut State,
    body: u64,
    end: u64,
) -> Result<(), ProbeError> {
    let head = rd.read_leaf_at(body, 8, 8)?;
    let count = u32_at(&head, 4).unwrap_or(0);
    if count > MAX_STSD_ENTRIES {
        info.incomplete("sample description is not a shape we recognise");
        return Ok(());
    }
    let mut at = body + 8;
    for _ in 0..count {
        let Some(e) = read_header(rd, at, end)? else {
            break;
        };
        let fourcc = String::from_utf8_lossy(&e.kind).trim().to_string();
        let is_video = st.track.handler.as_ref() == Some(b"vide");
        let is_audio = st.track.handler.as_ref() == Some(b"soun");
        if is_video {
            let b = rd.read_leaf_at(e.body, (e.end - e.body).min(78), 78)?;
            st.track.width = u32::from(u16_at(&b, 24).unwrap_or(0));
            st.track.height = u32::from(u16_at(&b, 26).unwrap_or(0));
            let (canon, _) = codec::lookup(Container::Mp4, &fourcc, true);
            st.track.canon = Some(canon);
            children(rd, st, e.body + 78, e.end, true)?;
        } else if is_audio {
            let b = rd.read_leaf_at(e.body, (e.end - e.body).min(28), 28)?;
            st.track.channels = u32::from(u16_at(&b, 16).unwrap_or(0));
            // The sample rate is 16.16 fixed point; only the integer
            // half is ever meaningful.
            st.track.sample_rate = u32_at(&b, 24).map(|v| v >> 16).filter(|v| *v > 0);
            let (canon, _) = codec::lookup(Container::Mp4, &fourcc, false);
            st.track.canon = Some(canon);
            children(rd, st, e.body + 28, e.end, false)?;
        } else {
            let (canon, kind) = codec::lookup_sub(Container::Mp4, &fourcc);
            st.track.canon = Some(canon);
            st.track.sub_kind = Some(kind);
        }
        st.track.codec_id = Some(fourcc);
        at = e.end;
    }
    Ok(())
}

/// A sample entry's child boxes: the codec configuration records, the
/// colour signalling, the bitrate.
fn children<R: Read + Seek>(
    rd: &mut Rd<R>,
    st: &mut State,
    start: u64,
    end: u64,
    is_video: bool,
) -> Result<(), ProbeError> {
    let mut at = start;
    while at < end {
        if rd.budget.charge_element().is_err() {
            return Err(ProbeError::BudgetExceeded);
        }
        let Some(c) = read_header(rd, at, end)? else {
            break;
        };
        let len = c.end - c.body;
        let b = rd.read_leaf_at(c.body, len, MAX_CHILD)?;
        match &c.kind {
            b"avcC" if b.len() >= 4 => {
                st.track.profile = Some(
                    match b[1] {
                        66 => "Baseline",
                        77 => "Main",
                        88 => "Extended",
                        100 => "High",
                        110 => "High 10",
                        122 => "High 4:2:2",
                        244 => "High 4:4:4",
                        _ => "",
                    }
                    .to_string(),
                )
                .filter(|s: &String| !s.is_empty());
                st.track.level = Some(format!("{}.{}", b[3] / 10, b[3] % 10));
                st.track.bit_depth = Some(if matches!(b[1], 110 | 122 | 244) {
                    10
                } else {
                    8
                });
            }
            b"hvcC" if b.len() >= 13 => {
                let prof = b[1] & 0x1F;
                st.track.profile = match prof {
                    1 => Some("Main".into()),
                    2 => Some("Main 10".into()),
                    3 => Some("Main Still Picture".into()),
                    _ => None,
                };
                st.track.level = Some(format!("{}.{}", b[12] / 30, (b[12] % 30) / 3));
                st.track.bit_depth = Some(if prof == 2 { 10 } else { 8 });
            }
            b"av1C" if b.len() >= 3 => {
                let idx = b[1] & 0x1F;
                st.track.profile = Some(format!("Profile {}", (b[1] >> 5) & 0x07));
                st.track.level = Some(format!("{}.{}", 2 + idx / 4, idx % 4));
                st.track.bit_depth = Some(if (b[2] >> 6) & 1 == 1 { 10 } else { 8 });
            }
            b"vpcC" if b.len() >= 7 => {
                st.track.profile = Some(format!("Profile {}", b[4]));
                st.track.level = Some(format!("{}.{}", b[5] / 10, b[5] % 10));
                st.track.bit_depth = Some(b[6] >> 4);
            }
            b"pasp" if b.len() >= 8 => {
                let (hs, vs) = (
                    u32_at(&b, 0).unwrap_or(1) as u64,
                    u32_at(&b, 4).unwrap_or(1) as u64,
                );
                if hs > 0 && vs > 0 && hs != vs {
                    st.track.pasp = Some((hs, vs));
                }
            }
            b"colr" if b.len() >= 10 => {
                if &b[..4] == b"nclx" || &b[..4] == b"nclc" {
                    st.track.primaries = u16_at(&b, 4)
                        .and_then(|v| codec::primaries_name(u64::from(v)))
                        .map(str::to_string);
                    st.track.transfer = u16_at(&b, 6)
                        .and_then(|v| codec::transfer_name(u64::from(v)))
                        .map(str::to_string);
                    st.track.matrix = u16_at(&b, 8)
                        .and_then(|v| codec::matrix_name(u64::from(v)))
                        .map(str::to_string);
                }
            }
            b"clli" if b.len() >= 4 => {
                st.track.max_cll = u16_at(&b, 0).map(u32::from);
                st.track.max_fall = u16_at(&b, 2).map(u32::from);
            }
            b"btrt" if b.len() >= 12 => {
                st.track.bitrate = u32_at(&b, 8)
                    .filter(|v| *v > 0)
                    .or_else(|| u32_at(&b, 4).filter(|v| *v > 0))
                    .map(u64::from);
            }
            b"dac3" => st.track.canon = Some("ac3".into()),
            b"dec3" => st.track.canon = Some("eac3".into()),
            b"dOps" if b.len() >= 2 => {
                st.track.canon = Some("opus".into());
                st.track.channels = u32::from(b[1]);
            }
            b"esds" if !is_video => {
                let b = rd.read_leaf_at(c.body, len, MAX_ESDS)?;
                if let Some((oti, bitrate)) = esds(&b) {
                    st.track.canon = Some(
                        match oti {
                            0x40 | 0x66 | 0x67 | 0x68 => "aac",
                            0x69 | 0x6B => "mp3",
                            0xA9..=0xAB => "dts",
                            0xA5 => "ac3",
                            0xA6 => "eac3",
                            0xDD => "vorbis",
                            _ => "",
                        }
                        .to_string(),
                    )
                    .filter(|s: &String| !s.is_empty())
                    .or(st.track.canon.take());
                    st.track.bitrate = st.track.bitrate.or(bitrate);
                }
            }
            _ => {}
        }
        if c.end <= at {
            break;
        }
        at = c.end;
    }
    Ok(())
}

/// The MPEG-4 descriptor chain inside `esds`: returns the object type
/// indication (which is what says "this mp4a is really MP3") and the
/// average bitrate.
fn esds(b: &[u8]) -> Option<(u8, Option<u64>)> {
    // Skip the box's version+flags.
    let mut at = 4usize;
    let mut depth = 0;
    while at < b.len() && depth < 8 {
        let tag = b[at];
        at += 1;
        let mut len: u64 = 0;
        // Length is 1-4 bytes, each carrying 7 bits and a continue bit.
        for _ in 0..4 {
            let byte = *b.get(at)?;
            at += 1;
            len = (len << 7) | u64::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                break;
            }
        }
        match tag {
            // ES_Descr: skip its own header and keep walking inward.
            0x03 => {
                let flags = *b.get(at + 2)?;
                let mut skip = 3usize;
                if flags & 0x80 != 0 {
                    skip += 2; // dependsOn_ES_ID
                }
                if flags & 0x40 != 0 {
                    skip += 1 + usize::from(*b.get(at + skip)?); // URL
                }
                if flags & 0x20 != 0 {
                    skip += 2; // OCR_ES_Id
                }
                at += skip;
                depth += 1;
            }
            // DecoderConfigDescriptor: what we came for.
            0x04 => {
                let body = b.get(at..at + len.min(64) as usize)?;
                let oti = *body.first()?;
                let avg = u32_at(body, 9).filter(|v| *v > 0).map(u64::from);
                let max = u32_at(body, 5).filter(|v| *v > 0).map(u64::from);
                return Some((oti, avg.or(max)));
            }
            _ => at += len as usize,
        }
    }
    None
}

fn flush_track(info: &mut MediaInfo, st: &mut State) {
    let t = std::mem::take(&mut st.track);
    if info.video.len() + info.audio.len() + info.subtitles.len() >= MAX_TRACKS {
        info.incomplete("this file has more tracks than we will list");
        return;
    }
    let raw = t.codec_id.clone().unwrap_or_default();
    let canon = t.canon.clone().unwrap_or_else(|| raw.to_ascii_lowercase());
    let lang = normalize_lang(t.lang.as_deref().unwrap_or("und"));
    // MP4 has no "forced" concept and no per-track name in the layout
    // this walk reads, so both are reported as the container states
    // them: absent.
    match t.handler.as_ref() {
        Some(b"vide") => {
            let hdr =
                (t.transfer.is_some() || t.primaries.is_some() || t.max_cll.is_some()).then(|| {
                    Hdr {
                        format: codec::hdr_format(t.transfer.as_deref(), t.primaries.as_deref()),
                        matrix: t.matrix.clone(),
                        transfer: t.transfer.clone(),
                        primaries: t.primaries.clone(),
                        max_cll: t.max_cll,
                        max_fall: t.max_fall,
                    }
                });
            // A pixel aspect ratio, or a tkhd display size that
            // disagrees with the coded size, means non-square pixels.
            let coded = ratio(u64::from(t.width), u64::from(t.height));
            let display_ar = match t.pasp {
                Some((hs, vs)) => ratio(u64::from(t.width) * hs, u64::from(t.height) * vs),
                None if t.tk_width > 0 && t.tk_height > 0 => ratio(t.tk_width, t.tk_height),
                None => None,
            }
            .filter(|r| Some(r) != coded.as_ref());
            let fps = t.stts_exact_fps.or_else(|| {
                let (n, ts, dur) = (t.stts_samples?, t.timescale?, t.duration?);
                (ts > 0 && dur > 0).then_some(())?;
                round3(n as f64 * f64::from(ts) / dur as f64)
            });
            info.video.push(VideoTrack {
                codec: canon,
                codec_id: raw,
                width: t.width,
                height: t.height,
                display_ar,
                fps,
                bit_depth: t.bit_depth,
                hdr,
                profile: t.profile,
                level: t.level,
                bitrate: t.bitrate,
                enabled: t.enabled,
                // MP4 has no default-track flag; the first track of a
                // kind is what a player picks.
                default: info.video.is_empty(),
            });
        }
        Some(b"soun") => {
            let first = info.audio.is_empty();
            info.audio.push(AudioTrack {
                codec: canon,
                codec_id: raw,
                lang,
                channels: t.channels,
                channel_layout: codec::channel_layout(t.channels),
                sample_rate: t.sample_rate,
                title: None,
                default: first,
                forced: false,
                bitrate: t.bitrate,
                enabled: t.enabled,
            });
        }
        Some(b"subt") | Some(b"sbtl") | Some(b"text") | Some(b"clcp") => {
            let first = info.subtitles.is_empty();
            info.subtitles.push(SubTrack {
                codec: canon,
                codec_id: raw,
                lang,
                title: None,
                default: first,
                forced: false,
                kind: t.sub_kind.unwrap_or(super::SubKind::Text),
            });
        }
        // hint tracks, timed metadata: nothing a viewer is checking for.
        _ => {}
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// `mdhd`'s packed language: three 5-bit values, each offset from 0x60.
fn unpack_lang(v: u16) -> String {
    if v == 0 || v == 0x7FFF {
        return "und".to_string();
    }
    let mut out = String::with_capacity(3);
    for shift in [10, 5, 0] {
        let c = ((v >> shift) & 0x1F) as u8 + 0x60;
        if !c.is_ascii_lowercase() {
            return "und".to_string();
        }
        out.push(char::from(c));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn probe(b: &[u8]) -> MediaInfo {
        super::super::probe(
            &mut Cursor::new(b),
            super::super::ProbeHint {
                filename: None,
                known_size: Some(b.len() as u64),
            },
        )
        .expect("a well-formed mux probes")
    }

    #[test]
    fn a_faststart_mp4_reads_from_the_front() {
        let b = super::super::testmux::mp4_faststart();
        let i = probe(&b);
        assert_eq!(i.container, Container::Mp4);
        assert_eq!(i.playback, PlaybackPath::Native);
        assert_eq!(i.duration_ms, Some(60_000));
        assert_eq!(i.video[0].codec, "h264");
        assert_eq!(i.video[0].codec_id, "avc1");
        assert_eq!((i.video[0].width, i.video[0].height), (1920, 1080));
        assert_eq!(i.video[0].profile.as_deref(), Some("High"));
        assert_eq!(i.video[0].level.as_deref(), Some("4.0"));
        assert_eq!(i.video[0].fps, Some(24.0));
        assert_eq!(i.audio[0].codec, "aac");
        assert_eq!(i.audio[0].lang, "en");
        assert_eq!(i.audio[0].channels, 2);
        assert_eq!(i.audio[0].sample_rate, Some(48_000));
        assert!(i.complete, "warnings: {:?}", i.warnings);
    }

    /// The case the whole design is for: the index is at the END of a
    /// file whose middle is a multi-gigabyte mdat nobody has downloaded.
    /// The walk must reach it by arithmetic, never by reading through.
    #[test]
    fn a_moov_at_the_end_is_reached_without_reading_the_payload() {
        let b = super::super::testmux::mp4_moov_at_end();
        let i = probe(&b);
        assert_eq!(i.playback, PlaybackPath::Native);
        assert_eq!(i.video[0].codec, "h264");
        assert_eq!(i.audio[0].codec, "aac");
        assert!(i.complete, "warnings: {:?}", i.warnings);
    }

    #[test]
    fn the_packed_language_field_decodes() {
        assert_eq!(unpack_lang(0x15C7), "eng");
        assert_eq!(unpack_lang(0x7FFF), "und");
        assert_eq!(unpack_lang(0), "und");
        // A zero 5-bit group decodes to a character below 'a', which
        // is a corrupt field rather than a language.
        assert_eq!(unpack_lang(0x0001), "und");
    }
}

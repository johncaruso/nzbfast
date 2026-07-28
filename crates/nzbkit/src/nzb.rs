//! NZB file parsing.
//!
//! An NZB is XML: `<nzb><file ...><groups><group>…</groups>
//! <segments><segment bytes number>message-id</segment></segments></file></nzb>`.
//! We keep the model deliberately close to the wire format; scheduling
//! concepts (server tiers, block accounting) live elsewhere.

use quick_xml::Reader;
use quick_xml::events::Event;

#[derive(Debug, thiserror::Error)]
pub enum NzbError {
    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("XML attribute error: {0}")]
    Attr(#[from] quick_xml::events::attributes::AttrError),
    #[error("XML encoding error: {0}")]
    Encoding(#[from] quick_xml::encoding::EncodingError),
    #[error("NZB contains no files")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nzb {
    pub files: Vec<NzbFile>,
    /// `<head><meta type="…">value</meta></head>` pairs (type lowercased).
    /// Indexers use these for password/category/title hints.
    pub meta: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NzbFile {
    pub subject: String,
    pub poster: String,
    /// Unix timestamp from the `date` attribute (0 if absent/unparseable).
    pub date: i64,
    pub groups: Vec<String>,
    pub segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// 1-based part number within the file.
    pub number: u32,
    /// Encoded article size in bytes, per the NZB (approximate; trust yEnc headers).
    pub bytes: u64,
    /// Message-ID without angle brackets.
    pub message_id: String,
}

/// Coarse role of a file within the download, used by the minimality logic:
/// PAR2 volumes are never fetched speculatively, and only the main .par2
/// packet is needed up front for filenames + block hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// The small main `.par2` (index) file - fetch eagerly.
    Par2Main,
    /// A `.volNN+MM.par2` recovery volume - fetch only when repairing.
    Par2Volume,
    /// Actual payload.
    Data,
}

/// Is this NZB-supplied token safe to interpolate into an NNTP command line?
///
/// Message-ids and group names go straight into `BODY <{id}>` / `GROUP {name}`,
/// and NNTP is a CRLF-delimited protocol, so a CR or LF inside one ENDS our
/// command and starts an attacker's. A hostile NZB carrying
/// `a@b&#13;&#10;POST&#13;&#10;c@d` (the char-ref path resolves those to real
/// control characters, and a CDATA body can hold the raw bytes) would run
/// arbitrary commands - POST/IHAVE among them - on the user's authenticated,
/// paid provider session, and desync every pipelined reply after it.
///
/// A real message-id contains none of these (RFC 5536 forbids whitespace and
/// the delimiters), so rejecting is free on legitimate input.
pub(crate) fn is_wire_safe(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>'))
}

impl Nzb {
    pub fn parse(xml: &[u8]) -> Result<Nzb, NzbError> {
        let mut reader = Reader::from_reader(xml);
        reader.config_mut().trim_text(true);

        let mut files: Vec<NzbFile> = Vec::new();
        let mut meta: Vec<(String, String)> = Vec::new();
        let mut cur_file: Option<NzbFile> = None;
        let mut cur_segment: Option<Segment> = None;
        let mut cur_meta: Option<(String, String)> = None;
        let mut in_group = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Start(e) => match e.local_name().as_ref() {
                    b"file" => {
                        let mut f = NzbFile::default();
                        for attr in e.attributes() {
                            let attr = attr?;
                            let val = attr.unescape_value()?;
                            match attr.key.local_name().as_ref() {
                                b"subject" => f.subject = val.into_owned(),
                                b"poster" => f.poster = val.into_owned(),
                                b"date" => f.date = val.trim().parse().unwrap_or(0),
                                _ => {}
                            }
                        }
                        cur_file = Some(f);
                    }
                    b"group" => in_group = true,
                    b"meta" => {
                        let mut ty = String::new();
                        for attr in e.attributes() {
                            let attr = attr?;
                            if attr.key.local_name().as_ref() == b"type" {
                                ty = attr.unescape_value()?.trim().to_lowercase();
                            }
                        }
                        cur_meta = Some((ty, String::new()));
                    }
                    b"segment" => {
                        let mut seg = Segment {
                            number: 0,
                            bytes: 0,
                            message_id: String::new(),
                        };
                        for attr in e.attributes() {
                            let attr = attr?;
                            let val = attr.unescape_value()?;
                            match attr.key.local_name().as_ref() {
                                b"bytes" => seg.bytes = val.trim().parse().unwrap_or(0),
                                b"number" => seg.number = val.trim().parse().unwrap_or(0),
                                _ => {}
                            }
                        }
                        cur_segment = Some(seg);
                    }
                    _ => {}
                },
                Event::Text(t) => {
                    let text = t.xml10_content()?;
                    let text = text.trim();
                    if text.is_empty() {
                        // nothing
                    } else if let Some(seg) = cur_segment.as_mut() {
                        seg.message_id.push_str(text);
                    } else if let Some((_, v)) = cur_meta.as_mut() {
                        v.push_str(text);
                    } else if in_group {
                        if let Some(f) = cur_file.as_mut() {
                            if is_wire_safe(text) {
                                f.groups.push(text.to_string());
                            }
                        }
                    }
                }
                Event::CData(c) => {
                    // quick-xml emits `<![CDATA[...]]>` as its own event,
                    // distinct from Text/GeneralRef. Without this arm a
                    // CDATA-wrapped message-id (or meta value / group name)
                    // is silently dropped and the article never fetched.
                    // CDATA content is literal - no entity unescaping.
                    let raw = String::from_utf8_lossy(&c);
                    let text = raw.trim();
                    if text.is_empty() {
                        // nothing
                    } else if let Some(seg) = cur_segment.as_mut() {
                        seg.message_id.push_str(text);
                    } else if let Some((_, v)) = cur_meta.as_mut() {
                        v.push_str(text);
                    } else if in_group {
                        if let Some(f) = cur_file.as_mut() {
                            if is_wire_safe(text) {
                                f.groups.push(text.to_string());
                            }
                        }
                    }
                }
                Event::GeneralRef(r) => {
                    // Entities inside text arrive as their own event
                    // ("p&amp;w" = Text/GeneralRef/Text): resolve the
                    // predefined five + char refs and append wherever the
                    // surrounding text is accumulating.
                    let resolved = if let Some(c) = r.resolve_char_ref()? {
                        Some(c.to_string())
                    } else {
                        match r.xml10_content()?.as_ref() {
                            "amp" => Some("&".to_string()),
                            "lt" => Some("<".to_string()),
                            "gt" => Some(">".to_string()),
                            "quot" => Some("\"".to_string()),
                            "apos" => Some("'".to_string()),
                            _ => None,
                        }
                    };
                    if let Some(text) = resolved {
                        if let Some(seg) = cur_segment.as_mut() {
                            seg.message_id.push_str(&text);
                        } else if let Some((_, v)) = cur_meta.as_mut() {
                            v.push_str(&text);
                        }
                    }
                }
                Event::End(e) => match e.local_name().as_ref() {
                    b"file" => {
                        if let Some(mut f) = cur_file.take() {
                            // Segments arrive in document order which is not
                            // guaranteed to be part order.
                            f.segments.sort_by_key(|s| s.number);
                            files.push(f);
                        }
                    }
                    b"group" => in_group = false,
                    b"meta" => {
                        if let Some((ty, val)) = cur_meta.take() {
                            if !ty.is_empty() && !val.is_empty() {
                                meta.push((ty, val));
                            }
                        }
                    }
                    b"segment" => {
                        if let (Some(f), Some(seg)) = (cur_file.as_mut(), cur_segment.take()) {
                            if !seg.message_id.is_empty() && is_wire_safe(&seg.message_id) {
                                f.segments.push(seg);
                            }
                        }
                    }
                    _ => {}
                },
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        if files.is_empty() {
            return Err(NzbError::Empty);
        }
        Ok(Nzb { files, meta })
    }

    /// Archive password embedded by the indexer, if any: a
    /// `<meta type="password">` entry (the x264/scene convention used by
    /// most newznab sites).
    pub fn password(&self) -> Option<&str> {
        self.meta
            .iter()
            .find(|(t, v)| t == "password" && !v.is_empty())
            .map(|(_, v)| v.as_str())
    }

    /// Total encoded bytes across all files (what a naive client downloads).
    pub fn total_bytes(&self) -> u64 {
        // Saturating: the per-segment `bytes` come from an untrusted NZB
        // attribute (up to u64::MAX); a plain sum panics in debug and wraps
        // in release, corrupting size-based routing/display.
        self.files.iter().map(NzbFile::bytes).fold(0u64, u64::saturating_add)
    }

    /// Encoded bytes excluding PAR2 recovery volumes (what we download
    /// up front - layer 1 of the minimality plan).
    pub fn eager_bytes(&self) -> u64 {
        self.files
            .iter()
            .filter(|f| f.kind() != FileKind::Par2Volume)
            .map(NzbFile::bytes)
            .fold(0u64, u64::saturating_add)
    }
}

impl NzbFile {
    pub fn bytes(&self) -> u64 {
        self.segments.iter().map(|s| s.bytes).fold(0u64, u64::saturating_add)
    }

    /// The filename quoted in the subject, per the near-universal posting
    /// convention `… "filename.ext" yEnc …`. Obfuscated posts may lie;
    /// the PAR2 main packet is the authority once we have it.
    pub fn filename_hint(&self) -> Option<&str> {
        quoted_filename(&self.subject)
    }

    pub fn kind(&self) -> FileKind {
        let name = self
            .filename_hint()
            .unwrap_or(&self.subject)
            .to_ascii_lowercase();
        if !name.contains(".par2") {
            return FileKind::Data;
        }
        // Recovery volumes look like "foo.vol012+10.par2" (par2cmdline:
        // first slice + count) or "foo.vol000-001.par2" (range convention,
        // end-exclusive - some posters' tooling chains 000-001, 001-003,
        // 003-007…). Anything else with .par2 is the index.
        if par2_vol_count(&name).is_some() {
            FileKind::Par2Volume
        } else {
            FileKind::Par2Main
        }
    }
}

/// The quoted filename in a subject: the first `"…"` run that looks like
/// a filename (contains a dot), else the first non-empty quoted run.
/// Posts like `"S01E01" - "Show.part01.rar" yEnc (1/2)` put a decoy
/// first - taking quote #1 unconditionally misclassified the file.
pub fn quoted_filename(s: &str) -> Option<&str> {
    let mut first: Option<&str> = None;
    let mut rest = s;
    while let Some(a) = rest.find('"') {
        let after = &rest[a + 1..];
        let Some(b) = after.find('"') else { break };
        let name = after[..b].trim();
        if !name.is_empty() {
            if name.contains('.') {
                return Some(name);
            }
            first.get_or_insert(name);
        }
        rest = &after[b + 1..];
    }
    first
}

/// Declared recovery-slice count from a PAR2 volume filename:
/// `.vol<first>+<count>` → count; `.vol<start>-<end>` (end-exclusive
/// range) → end − start. `None` if the name doesn't carry a strict
/// `.vol<digits><+|-><digits>` tail - i.e. not a recovery volume.
pub fn par2_vol_count(name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    let vol = lower.rfind(".vol")?;
    let rest = &lower[vol + 4..];
    let sep = rest.find(['+', '-'])?;
    let first: u64 = rest[..sep].parse().ok()?;
    let after = &rest[sep + 1..];
    let end = after.find('.').unwrap_or(after.len());
    let second: u64 = after[..end].parse().ok()?;
    match rest.as_bytes()[sep] {
        b'+' => Some(second as usize),
        _ => Some(second.saturating_sub(first).max(1) as usize),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message-id carrying CR/LF would end our `BODY <id>` command and start
    /// the attacker's next command on the user's authenticated, paid provider
    /// session (POST/IHAVE among them), and desync every pipelined reply after
    /// it. Both routes into the id are covered: numeric char refs, which
    /// quick-xml resolves to the real control characters, and a CDATA body,
    /// which can hold the raw bytes. Such segments are dropped at parse.
    #[test]
    fn segments_with_crlf_message_ids_are_dropped() {
        let xml = br#"<?xml version="1.0"?>
<nzb>
  <file subject="x" poster="p" date="1700000000">
    <groups><group>alt.binaries.test&#13;&#10;POST</group></groups>
    <segments>
      <segment bytes="1" number="1">a@b&#13;&#10;POST&#13;&#10;c@d</segment>
      <segment bytes="1" number="2"><![CDATA[e@f
POST]]></segment>
      <segment bytes="1" number="3">clean@example.com</segment>
    </segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).expect("parses");
        let f = &nzb.files[0];
        assert_eq!(f.segments.len(), 1, "only the clean segment may survive: {:?}", f.segments);
        assert_eq!(f.segments[0].message_id, "clean@example.com");
        for seg in &f.segments {
            assert!(is_wire_safe(&seg.message_id), "unsafe id survived: {:?}", seg.message_id);
        }
        // The group name takes the same route into `GROUP {name}`.
        assert!(f.groups.iter().all(|g| is_wire_safe(g)), "unsafe group survived: {:?}", f.groups);
    }

    fn sample() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="poster@example.com" date="1700000000" subject="Big Release [1/3] - &quot;release.part1.rar&quot; yEnc (1/2)">
    <groups>
      <group>alt.binaries.test</group>
      <group>alt.binaries.misc</group>
    </groups>
    <segments>
      <segment bytes="750000" number="2">seg2@news.example</segment>
      <segment bytes="750000" number="1">seg1@news.example</segment>
    </segments>
  </file>
  <file poster="poster@example.com" date="1700000001" subject="Big Release [2/3] - &quot;release.par2&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="50000" number="1">par2main@news.example</segment>
    </segments>
  </file>
  <file poster="poster@example.com" date="1700000002" subject="Big Release [3/3] - &quot;release.vol000+01.par2&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="100000" number="1">par2vol@news.example</segment>
    </segments>
  </file>
</nzb>"#
    }

    #[test]
    fn meta_password_entities_resolved() {
        // No <head> at all → None.
        assert_eq!(Nzb::parse(sample()).unwrap().password(), None);
        // Entities inside the password ("s3cret&amp;pw") arrive as their
        // own GeneralRef events and must be stitched back in.
        let with_head = String::from_utf8_lossy(sample()).replace(
            "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">",
            "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <head>\n    <meta type=\"title\">Big Release</meta>\n    <meta type=\"PASSWORD\">s3cret&amp;pw</meta>\n  </head>",
        );
        let nzb = Nzb::parse(with_head.as_bytes()).unwrap();
        assert_eq!(nzb.password(), Some("s3cret&pw"));
        assert_eq!(nzb.files.len(), 3, "head must not disturb file parsing");
    }

    #[test]
    fn parses_files_groups_segments() {
        let nzb = Nzb::parse(sample()).unwrap();
        assert_eq!(nzb.files.len(), 3);

        let f = &nzb.files[0];
        assert_eq!(f.poster, "poster@example.com");
        assert_eq!(f.date, 1700000000);
        assert_eq!(f.groups, vec!["alt.binaries.test", "alt.binaries.misc"]);
        assert_eq!(f.segments.len(), 2);
        // Sorted by part number despite reversed document order.
        assert_eq!(f.segments[0].number, 1);
        assert_eq!(f.segments[0].message_id, "seg1@news.example");
        assert_eq!(f.segments[1].number, 2);
        assert_eq!(f.filename_hint(), Some("release.part1.rar"));
    }

    #[test]
    fn cdata_segment_id_and_group_preserved() {
        // A CDATA-wrapped message-id / group must not be silently dropped
        // (quick-xml emits it as Event::CData, a distinct event).
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="x" date="0" subject="&quot;a.rar&quot; yEnc (1/1)">
    <groups><group><![CDATA[alt.binaries.cdata]]></group></groups>
    <segments>
      <segment bytes="750000" number="1"><![CDATA[seg-cdata@news.example]]></segment>
    </segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).unwrap();
        assert_eq!(nzb.files.len(), 1);
        let f = &nzb.files[0];
        assert_eq!(f.segments.len(), 1, "CDATA segment must not be dropped");
        assert_eq!(f.segments[0].message_id, "seg-cdata@news.example");
        assert_eq!(f.groups, vec!["alt.binaries.cdata"]);
    }

    #[test]
    fn classifies_par2_roles() {
        let nzb = Nzb::parse(sample()).unwrap();
        assert_eq!(nzb.files[0].kind(), FileKind::Data);
        assert_eq!(nzb.files[1].kind(), FileKind::Par2Main);
        assert_eq!(nzb.files[2].kind(), FileKind::Par2Volume);
    }

    #[test]
    fn classifies_dash_range_volumes() {
        // Range-style names ("vol000-001" … "vol127-199", end-exclusive)
        // are recovery volumes, not extra copies of the main index - a
        // Par2Main misclassification pulls the whole recovery set (GBs)
        // ahead of the data and buffers it in memory.
        let mut f = NzbFile {
            subject: r#"< Rel > - "Rel.vol127-199.par2" yEnc (01/99)"#.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(f.kind(), FileKind::Par2Volume);
        f.subject = r#"< Rel > - "Rel.vol000-001.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Volume);
        // A dash in the release name alone must not demote the index.
        f.subject = r#"< Rel > - "Some.Film.2026.H.265-GRP.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Main);
        f.subject = r#"< Rel > - "Some.Film-GRP.vol.par2" yEnc (1/1)"#.to_string();
        assert_eq!(f.kind(), FileKind::Par2Main);
    }

    #[test]
    fn filename_hint_skips_decoy_quotes() {
        // A quoted non-filename before the real one ("S01E01" here) made
        // kind() classify a recovery volume as Data - eager-fetching it.
        let f = NzbFile {
            subject: r#""S01E01" - "Show.vol000+50.par2" yEnc (1/60)"#.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(f.filename_hint(), Some("Show.vol000+50.par2"));
        assert_eq!(f.kind(), FileKind::Par2Volume);
        // No dotted quoted run at all → first non-empty run still wins.
        let g = NzbFile {
            subject: r#"post "some label" yEnc (1/2)"#.to_string(),
            ..NzbFile::default()
        };
        assert_eq!(g.filename_hint(), Some("some label"));
    }

    #[test]
    fn vol_count_both_conventions() {
        assert_eq!(par2_vol_count("Rel.vol012+10.par2"), Some(10));
        assert_eq!(par2_vol_count("Rel.vol127-199.par2"), Some(72));
        assert_eq!(par2_vol_count("Rel.vol000-001.par2"), Some(1));
        assert_eq!(par2_vol_count("Rel.vol003-007.par2"), Some(4));
        assert_eq!(par2_vol_count("Rel.par2"), None);
        assert_eq!(par2_vol_count("Rel-GRP.par2"), None);
        assert_eq!(par2_vol_count("Rel.volume-2.par2"), None);
    }

    #[test]
    fn minimality_accounting() {
        let nzb = Nzb::parse(sample()).unwrap();
        assert_eq!(nzb.total_bytes(), 1_650_000);
        // Eager set skips the recovery volume.
        assert_eq!(nzb.eager_bytes(), 1_550_000);
    }

    #[test]
    fn parses_head_meta_password() {
        let xml = br#"<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="title">Big Release</meta>
    <meta type="PASSWORD">s3cret pass</meta>
    <meta type="category"></meta>
  </head>
  <file poster="p" date="1" subject="s">
    <groups><group>alt.binaries.test</group></groups>
    <segments><segment bytes="1" number="1">a@b</segment></segments>
  </file>
</nzb>"#;
        let nzb = Nzb::parse(xml).unwrap();
        // Type is lowercased; empty-valued metas are dropped.
        assert_eq!(
            nzb.meta,
            vec![
                ("title".to_string(), "Big Release".to_string()),
                ("password".to_string(), "s3cret pass".to_string()),
            ]
        );
        assert_eq!(nzb.password(), Some("s3cret pass"));

        let plain = Nzb::parse(sample()).unwrap();
        assert_eq!(plain.password(), None);
    }

    #[test]
    fn rejects_empty() {
        let err = Nzb::parse(br#"<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"></nzb>"#);
        assert!(matches!(err, Err(NzbError::Empty)));
    }
}

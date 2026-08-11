#![no_main]
//! Fuzz the pesto uploader-family adapter (TODO 131, red-team 5a).
//! Message-ids come straight off OVER headers from anonymous posters
//! and are parsed for every scanned article, so the grammar parser is
//! the hot untrusted surface; the FileDesc gate consumes lengths and
//! hashes read out of attacker-authored PAR2 bodies. The PAR2 packet
//! walk itself is already covered by the `par2_parse` target.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    // The grammar parser sees arbitrary header bytes.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(id) = nzbkit::pesto::parse_msgid(s) {
            // Grammar invariants: a 4-or-5-hex counter and 16-hex clock
            // can never exceed these widths.
            assert!(id.counter <= 0xF_FFFF);
            let _ = id.clock;
        }
    }
    // The gate and ratio band over attacker-shaped descriptor values:
    // carve the input into (length, hash) pairs and a head span. Must
    // never panic regardless of declared lengths (0, huge, > head).
    let mid = data.len() / 2;
    let (desc_bytes, head) = data.split_at(mid);
    let descs: Vec<nzbkit::pesto::PestoDesc> = desc_bytes
        .chunks(24)
        .map(|c| {
            let mut len = [0u8; 8];
            len[..c.len().min(8)].copy_from_slice(&c[..c.len().min(8)]);
            nzbkit::pesto::PestoDesc {
                name: String::from_utf8_lossy(&c[c.len().min(8)..]).into_owned(),
                length: u64::from_le_bytes(len),
                md5: String::new(),
                md5_16k: c.iter().map(|b| format!("{b:02x}")).collect(),
            }
        })
        .collect();
    let _ = nzbkit::pesto::match_filedesc(&descs, head);
    if let Some(d) = descs.first() {
        let _ = nzbkit::pesto::length_ratio_ok(head.len() as u64, d.length);
    }
});

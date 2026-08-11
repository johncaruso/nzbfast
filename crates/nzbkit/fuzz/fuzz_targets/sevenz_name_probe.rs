#![no_main]
//! Fuzz the 7z end-header naming probe (TODO 131 B3). The probe parses
//! bytes fetched straight off usenet from anonymous posters: the
//! 32-byte start header, the end header, and every entry name inside it
//! are attacker-chosen. Two surfaces are driven:
//!
//! 1. The natural path: input split into a head and a tail, exactly as
//!    the worker hands decoded articles over. Almost everything rejects
//!    at the magic/CRC gates - kept because those gates ARE the armor.
//! 2. The deep path: the input wrapped as a CRC-valid end header behind
//!    a synthesized start header, so the fuzzer reaches sevenz-rust2's
//!    header parser (kHeader and kEncodedHeader decode included) with
//!    arbitrary bytes instead of being stopped at the checksum door.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Bound the input: the live probe caps the end header at
    // SEVENZ_END_MAX before any fetch, so bigger inputs exercise
    // nothing real and only measure RAM.
    if data.is_empty() || data.len() > 1 << 20 {
        return;
    }
    // Natural split: first half head, second half tail.
    let mid = data.len() / 2;
    if let Ok(entries) = nzbkit::nameprobe::sevenz_tail_names(&data[..mid], &data[mid..]) {
        let _ = nzbkit::nameprobe::pick_media_name(&entries);
    }
    // Deep path: seal the input as the end header of a well-formed
    // container so the parse gets past the gates.
    let mut head = Vec::with_capacity(32);
    head.extend_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04]);
    head.extend_from_slice(&[0u8; 4]); // start-header CRC, sealed below
    head.extend_from_slice(&0u64.to_le_bytes()); // header_off
    head.extend_from_slice(&(data.len() as u64).to_le_bytes()); // header_size
    head.extend_from_slice(&crc32fast::hash(data).to_le_bytes()); // header_crc
    let crc = crc32fast::hash(&head[12..32]);
    head[8..12].copy_from_slice(&crc.to_le_bytes());
    if let Ok(entries) = nzbkit::nameprobe::sevenz_tail_names(&head, data) {
        let _ = nzbkit::nameprobe::pick_media_name(&entries);
    }
});

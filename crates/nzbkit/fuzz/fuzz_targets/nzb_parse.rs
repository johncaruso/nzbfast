#![no_main]
//! Fuzz the NZB XML parser on arbitrary bytes (untrusted, user-supplied
//! .nzb files and RSS payloads), plus the posted-NZB identity
//! extraction that consumes the parse (REDTEAM 5c: a posted NZB is
//! attacker-controlled input all the way through the msgid-join rung).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = nzbkit::nzb::Nzb::parse(data);
    let _ = nzbkit::nzbimport::nzb_identity(data);
});

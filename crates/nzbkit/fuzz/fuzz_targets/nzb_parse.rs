#![no_main]
//! Fuzz the NZB XML parser on arbitrary bytes (untrusted, user-supplied
//! .nzb files and RSS payloads).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = nzbkit::nzb::Nzb::parse(data);
});

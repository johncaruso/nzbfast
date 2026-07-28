#![no_main]
//! Fuzz the Matroska header probe on arbitrary bytes (untrusted,
//! completed downloads are opened to read duration and dimensions
//! before renaming and sample-sweep decisions).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = nzbkit::mkv::parse(data);
});

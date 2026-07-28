#![no_main]
//! Fuzz the PAR2 recovery-file parser on arbitrary bytes (untrusted,
//! downloaded .par2 volumes drive repair decisions).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The real path can receive several concatenated packets; split the
    // input so the multi-input framing is exercised too.
    let mid = data.len() / 2;
    let (a, b) = data.split_at(mid);
    let _ = nzbkit::par2::Par2Set::parse(&[data]);
    let _ = nzbkit::par2::Par2Set::parse(&[a, b]);
});

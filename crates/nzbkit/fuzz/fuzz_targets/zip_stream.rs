#![no_main]
//! Fuzz the zip parser as the CHASE drives it, over an in-memory source.
//!
//! `zip_parse` already covers the disk reader, and the two share one
//! `Source`-generic parser - but not one call ORDER. The chase resolves
//! an entry's crypto framing by reading ABOVE the body it is about to
//! stream, wraps a bounded range reader rather than a file, and drains
//! the source explicitly so a WinZip-AE HMAC is reached even when the
//! deflate decoder stopped at its own stream end. Those are the pieces
//! this target exercises.
//!
//! It covers the encrypted path deliberately: encrypted entries stream
//! in-stream now, and since the depth guard came off a zip chases at
//! every nesting level, so these bytes can arrive from inside another
//! attacker-supplied archive with nothing upstream having vetted them.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Without an end-of-central-directory signature the parser bails
    // immediately, and those inputs teach the fuzzer nothing.
    if data.len() < 22 {
        return;
    }
    // Both key states: no password (the decline path and the plaintext
    // ciphers) and a password (ZipCrypto check byte, AE PBKDF2 +
    // verifier + HMAC). The attacker controls the archive, not the
    // password, so a fixed one is right - but it has to be the one the
    // committed `tests/fixtures/zip` encrypted archives were written
    // with, or every seed stops at the verifier and the keystream-carry
    // and HMAC code past it is never reached from the corpus.
    nzbkit::zip::fuzz_stream_pass(data, None);
    nzbkit::zip::fuzz_stream_pass(data, Some("SECRET"));
});

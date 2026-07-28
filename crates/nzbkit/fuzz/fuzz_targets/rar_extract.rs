#![no_main]
//! Fuzz the RAR reader + decompressor on arbitrary bytes (untrusted
//! archives from a completed download). The window and output are bounded
//! so a decompression bomb can't OOM/hang the fuzzer - we are hunting
//! panics / OOB in the parse + decode paths, not memory pressure.
use libfuzzer_sys::fuzz_target;
use std::io::Write;

use rars::{ArchiveReadOptions, ArchiveReader};

/// Discards output but caps the total so a bomb terminates the run.
struct CapSink(usize);
impl Write for CapSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        if self.0 > 64 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "output cap"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let opts = || {
        ArchiveReadOptions::new()
            .with_rar50_max_window(1 << 20)
            .with_rar50_buffered_decode_limit(1 << 20)
    };
    if let Ok(archive) = ArchiveReader::read_with_options(data, opts()) {
        let _ = archive.extract_to_with_options(opts(), |_meta| {
            Ok(Box::new(CapSink(0)) as Box<dyn Write>)
        });
    }
});

//! External-tool resolution - nzbfast ships as ONE executable with NO
//! embedded tools.
//!
//! RAR extraction (all families, incl. compressed/encrypted/filtered) is
//! native via the vendored `rars` crate; verify, extraction and
//! Reed-Solomon repair (incl. obfuscated-set block adoption) have long
//! been native. A separately installed `unrar` or `par2` still resolves
//! here purely as an operator escape hatch - nzbfast invokes it as an
//! ordinary external program (mere aggregation; nothing is shipped).
//!
//! Resolution order:
//!   1. a file next to the nzbfast executable - for power users who want
//!      their own tool version;
//!   2. the bare name - whatever `$PATH` provides.

use std::path::PathBuf;

pub(crate) fn resolve(name: &str) -> PathBuf {
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    if let Some(p) = std::env::current_exe()
        .ok()
        .and_then(|p| Some(p.parent()?.join(&file)))
        .filter(|p| p.is_file())
    {
        return p;
    }
    PathBuf::from(name)
}

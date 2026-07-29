//! nzbkit - the nzbfast engine.
//!
//! Module map (grows per the roadmap):
//! - [`nzb`]      NZB XML parsing → files → segments → message-IDs
//! - [`yenc`]     reference (scalar) yEnc codec with CRC32; rapidyenc FFI later
//! - [`nntp`]     async NNTP client: TLS, AUTHINFO, pipelined BODY primitives
//! - [`config`]   local config (`config.local.json`, gitignored credentials)
//!
//! Coming: `sched` (article scheduler, server tiers, completability math),
//! `par2` (main-packet parsing, incremental block verification),
//! `disk` (preallocated offset writer).

pub mod benchserve;
pub mod categories;
pub mod config;
pub mod disk;
pub mod extract;
pub mod gf16;
pub mod index;
pub mod journal;
pub mod live;
pub mod logtee;
pub mod media;
pub mod mem;
pub mod mkv;
pub mod mock;
pub mod mp4;
pub mod nntp;
pub mod nzb;
pub mod nzblnk;
pub mod oracle;
pub mod par2;
pub mod par2repair;
pub mod pool;
pub mod post;
pub mod preflight;
pub mod rar;
pub mod release;
pub mod rarcrypt;
pub mod spot;
pub mod sysbench;
pub mod warmbench;
pub mod warmpool;
pub mod yenc;
pub mod yenc_simd;
pub mod zip;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

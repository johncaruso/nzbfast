//! RAR4 header-framing tests: the CRC16 that makes a plaintext header
//! authoritative, and the cursor arithmetic over the geometry it
//! protects. A child module (the par2repair.rs pattern) so rar.rs stays
//! inside its size-gate entry; `super::*` reaches the private parser.

use super::*;
use fixtures::{V4_FIRST_BLOCK, restamp_v4_block};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Codex sweep 10 Aug M5: a RAR4 header carries a CRC16 and nothing on
/// the PLAINTEXT path ever checked it, so damaged or crafted
/// name/flag/geometry bytes were taken as authoritative - and the
/// extractor turns that geometry straight into pwrite destinations.
/// RAR5 has always rejected its own CRC miss; RAR4 now matches.
///
/// Every byte of the header is walked so the check cannot be passing for
/// some narrower reason than "the header is intact", and the DATA area
/// is walked too: those bytes are outside the CRC by design and must
/// stay mappable, or the gate would be refusing the ordinary damaged
/// downloads that repair exists to fix.
#[test]
fn a_flipped_plaintext_v4_header_byte_is_refused() {
    let data = payload(4_000, 61);
    let good = fixtures::rar4_volume(&[("c.bin", 4_000, &data, false, false)]);
    let mut m = VolumeMapper::new(good.len() as u64);
    m.feed(0, &good);
    assert_eq!(m.blocker, None, "the untouched fixture must map");
    assert_eq!(m.entries.len(), 1);

    // The file header: block base 20, its own `hsize` bytes long.
    let base = V4_FIRST_BLOCK;
    let hsize = u16::from_le_bytes(good[base + 5..base + 7].try_into().unwrap()) as usize;
    for i in base..base + hsize {
        let mut bad = good.clone();
        bad[i] ^= 0x40;
        let mut m = VolumeMapper::new(bad.len() as u64);
        m.feed(0, &bad);
        // Either the CRC refuses it outright, or the flip broke the
        // framing badly enough that the walk never reaches the end
        // block. What must never happen is a COMPLETE, unblocked map
        // built on bytes the header's own CRC disowns - that map is what
        // the extractor pwrites through.
        assert!(
            m.blocker.is_some() || !m.complete,
            "header byte {} flipped and the volume still mapped clean",
            i - base
        );
    }
    // Restamping makes the same flip legitimate again - so the loop
    // above is the CRC talking, not a field-plausibility check.
    let mut restamped = good.clone();
    restamped[base + 25] = 0x33; // method byte: compressed
    restamp_v4_block(&mut restamped, base);
    let mut m = VolumeMapper::new(restamped.len() as u64);
    m.feed(0, &restamped);
    assert_eq!(
        m.blocker,
        Some(MapBlocker::NotStore),
        "an intact header must be read on its merits"
    );
    // Damage in the DATA area is what PAR2 repair is for; the header
    // gate must not swallow it.
    let mut hole = good.clone();
    let payload_at = base + hsize;
    hole[payload_at + 7] ^= 0xff;
    let mut m = VolumeMapper::new(hole.len() as u64);
    m.feed(0, &hole);
    assert_eq!(m.blocker, None, "damaged DATA must still map");
}

/// RAR4 >4 GiB store piece: `next` must use the full 64-bit packed size
/// (add_size + high_pack), not just the low 32 bits - otherwise the
/// cursor walks into the data area and ends in a Corrupt/NotStore
/// fallback.
#[test]
fn v4_large_piece_advances_cursor_past_full_data_len() {
    // Hand-build a v4 file header claiming a 5 GiB piece (no actual
    // data needed - we only check the returned cursor).
    let name = b"huge.bin";
    let data_len: u64 = 5 << 30; // 5 GiB
    let hsize = (7 + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + 8 + name.len()) as u16;
    let mut blk = Vec::new();
    blk.extend_from_slice(&0u16.to_le_bytes()); // head crc, stamped below
    blk.push(0x74);
    blk.extend_from_slice(&(0x8000u16 | 0x0100).to_le_bytes()); // add size + high fields
    blk.extend_from_slice(&hsize.to_le_bytes());
    blk.extend_from_slice(&((data_len & 0xFFFF_FFFF) as u32).to_le_bytes()); // add size lo
    blk.extend_from_slice(&((data_len & 0xFFFF_FFFF) as u32).to_le_bytes()); // unp lo
    blk.push(0); // host
    blk.extend_from_slice(&0u32.to_le_bytes()); // crc
    blk.extend_from_slice(&0u32.to_le_bytes()); // time
    blk.push(29); // unp_ver
    blk.push(0x30); // store
    blk.extend_from_slice(&(name.len() as u16).to_le_bytes());
    blk.extend_from_slice(&0u32.to_le_bytes()); // attr
    blk.extend_from_slice(&((data_len >> 32) as u32).to_le_bytes()); // high_pack
    blk.extend_from_slice(&((data_len >> 32) as u32).to_le_bytes()); // high_unp
    blk.extend_from_slice(name);
    fixtures::stamp_v4_head_crc(&mut blk);
    let base = 20u64;
    match parse_block_v4(&blk, base) {
        BlockResult::File { entry, next } => {
            assert_eq!(entry.data_len, data_len);
            assert_eq!(entry.unpacked_size, data_len);
            assert_eq!(
                next,
                base + hsize as u64 + data_len,
                "cursor must skip the FULL piece"
            );
        }
        _ => panic!("expected a file block"),
    }
}

/// Found by the RAR4 plaintext fuzz half that landed with the M5 CRC
/// gate: `high_pack = 0xFFFF_FFFF` puts the declared piece within a few
/// bytes of `u64::MAX`, and summing it with the block's own offset
/// panicked in debug and wrapped in release. A wrapped cursor is the
/// shape that walks the parse loop backwards over itself.
///
/// Not academic just because the CRC gate now stands in front of it: a
/// poster stamps a correct CRC over whatever fields they like. The twin
/// of the test above - same field, the value it cannot carry.
#[test]
fn a_v4_piece_declaring_the_whole_address_space_is_refused() {
    let name = b"huge.bin";
    let hsize = (7 + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + 8 + name.len()) as u16;
    let mut blk = Vec::new();
    blk.extend_from_slice(&0u16.to_le_bytes()); // head crc, stamped below
    blk.push(0x74);
    blk.extend_from_slice(&(0x8000u16 | 0x0100).to_le_bytes()); // add size + high fields
    blk.extend_from_slice(&hsize.to_le_bytes());
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // add size lo
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // unp lo
    blk.push(0); // host
    blk.extend_from_slice(&0u32.to_le_bytes()); // crc
    blk.extend_from_slice(&0u32.to_le_bytes()); // time
    blk.push(29); // unp_ver
    blk.push(0x30); // store
    blk.extend_from_slice(&(name.len() as u16).to_le_bytes());
    blk.extend_from_slice(&0u32.to_le_bytes()); // attr
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // high_pack
    blk.extend_from_slice(&u32::MAX.to_le_bytes()); // high_unp
    blk.extend_from_slice(name);
    fixtures::stamp_v4_head_crc(&mut blk);
    assert!(
        matches!(parse_block_v4(&blk, 20), BlockResult::Corrupt(_)),
        "a piece that cannot be addressed must be refused, not summed"
    );
}

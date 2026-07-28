//! Proves the group model against real RARLab output before any of it is
//! built on: is a group's state vector the CRC64 of THAT GROUP'S slice of
//! each data shard? Dev-only.
//!
//!   cargo run -q --release -p rars --example verify_groups -- <archive.rar>

use rars::recovery::rar5::crc64_rar_state;

const MAXP: u64 = 64 * 1024;

fn u16le(b: &[u8], o: usize) -> u64 { u16::from_le_bytes(b[o..o+2].try_into().unwrap()) as u64 }
fn u32le(b: &[u8], o: usize) -> u64 { u32::from_le_bytes(b[o..o+4].try_into().unwrap()) as u64 }
fn u64le(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o+8].try_into().unwrap()) }

fn main() {
    let path = std::env::args().nth(1).expect("usage: verify_groups <archive.rar>");
    let data = std::fs::read(&path).expect("read archive");

    let mut off = 0usize;
    let mut recs: Vec<(usize, u64, u64, Vec<u64>)> = Vec::new(); // offset, idx, parity_len, states
    let (mut gc, mut prot, mut ds, mut rs, mut hdr, mut shard_span) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    while let Some(rel) = data[off..].windows(4).position(|w| w == b"{RB}") {
        let s = off + rel;
        if data.len() - s < 0x48 { break; }
        let total = u32le(&data, s + 0x0c);
        let h = u32le(&data, s + 0x10);
        if total < h || (data.len() - s) < total as usize { off = s + 1; continue; }
        prot = u64le(&data, s + 0x22);
        gc = u64le(&data, s + 0x2a);
        shard_span = u64le(&data, s + 0x32);
        ds = u16le(&data, s + 0x3a);
        rs = u16le(&data, s + 0x3c);
        hdr = h;
        let idx = u16le(&data, s + 0x3e);
        let states: Vec<u64> = (0..ds as usize)
            .map(|k| u64le(&data, s + 0x40 + k * 8))
            .collect();
        recs.push((s, idx, total - h, states));
        off = s + total as usize;
    }

    // Group layout is fully determined by group_count.
    let g = gc.div_ceil(MAXP);
    let groups: Vec<(u64, u64)> = (0..g)
        .map(|k| (k * MAXP, MAXP.min(gc - k * MAXP)))
        .collect();
    println!("protected={prot} data_shards={ds} recovery_shards={rs} group_count={gc} groups={g}");
    println!("predicted shard record span = {}*{hdr} + {gc} = {}  declared shard_size = {shard_span}  MATCH={}",
        g, g * hdr + gc, g * hdr + gc == shard_span);

    // Record (i,k) sits at base + i*shard_span + sum_{j<k}(hdr+len_j).
    let mut cum = vec![0u64; g as usize];
    let mut acc = 0u64;
    for (k, &(_, len)) in groups.iter().enumerate() { cum[k] = acc; acc += hdr + len; }
    let base = recs.iter().map(|r| r.0 as u64 - r.1 * shard_span).min().unwrap();
    println!("derived base offset = {base}");

    let mut checked = 0usize;
    let mut good = 0usize;
    let mut placed = 0usize;
    for (offset, idx, plen, states) in &recs {
        let within = *offset as u64 - base - idx * shard_span;
        let Some(k) = cum.iter().position(|&c| c == within) else {
            println!("  record @{offset} idx={idx}: NO GROUP for within={within}");
            continue;
        };
        if groups[k].1 != *plen {
            println!("  record @{offset} idx={idx}: group {k} len {} != parity {plen}", groups[k].1);
            continue;
        }
        placed += 1;
        // Now the real question: does states[d] equal the CRC of shard d's
        // group-k slice of the protected prefix?
        let (goff, glen) = groups[k];
        for d in 0..ds {
            let start = d * gc + goff;
            let end = (start + glen).min(prot);
            let slice = if start >= prot { &[][..] } else { &data[start as usize..end as usize] };
            checked += 1;
            if crc64_rar_state(slice) == states[d as usize] { good += 1; }
        }
    }
    println!("records placed into a group: {placed}/{}", recs.len());
    println!("state-vector entries matching their group slice: {good}/{checked}");
    println!("{}", if good == checked && checked > 0 { "MODEL CONFIRMED" } else { "MODEL WRONG" });
}

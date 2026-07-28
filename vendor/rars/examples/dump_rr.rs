//! Dumps the {RB} recovery records of a real archive, so the group model can
//! be read off RARLab's own output rather than inferred. Dev-only.
//!
//!   cargo run -q --release -p rars --example dump_rr -- <archive.rar>

fn u16le(b: &[u8], o: usize) -> u64 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) as u64
}
fn u32le(b: &[u8], o: usize) -> u64 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as u64
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_rr <archive.rar>");
    let data = std::fs::read(&path).expect("read archive");
    println!("file {} bytes", data.len());

    let mut offset = 0usize;
    let mut n = 0usize;
    let mut by_index: std::collections::BTreeMap<u64, usize> = Default::default();
    let mut parity_lens: std::collections::BTreeMap<u64, usize> = Default::default();
    while let Some(rel) = data[offset..]
        .windows(4)
        .position(|w| w == b"{RB}")
    {
        let s = offset + rel;
        if data.len() - s < 0x48 {
            break;
        }
        let total_size = u32le(&data, s + 0x0c);
        let header_size = u32le(&data, s + 0x10);
        if total_size < header_size || (data.len() - s) < total_size as usize {
            offset = s + 1;
            continue;
        }
        let protected_size = u64le(&data, s + 0x22);
        let group_count = u64le(&data, s + 0x2a);
        let shard_size = u64le(&data, s + 0x32);
        let data_shards = u16le(&data, s + 0x3a);
        let recovery_shards = u16le(&data, s + 0x3c);
        let shard_index = u16le(&data, s + 0x3e);
        let parity_len = total_size - header_size;

        if n < 6 || shard_index == 0 {
            println!(
                "rec {n:4} @{s:<12} total={total_size:<8} hdr={header_size:<6} \
                 parity={parity_len:<8} idx={shard_index:<4} \
                 data={data_shards} rec={recovery_shards} \
                 shard_size={shard_size:<8} group_count={group_count} prot={protected_size}"
            );
        }
        *by_index.entry(shard_index).or_default() += 1;
        *parity_lens.entry(parity_len).or_default() += 1;
        n += 1;
        offset = s + total_size as usize;
    }

    println!("--- {n} records total");
    println!("--- records per shard_index: {by_index:?}");
    println!("--- parity lengths seen (len -> count): {parity_lens:?}");
}

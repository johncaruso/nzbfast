//! RAR5 AES-256 decryption: key schedule + CBC helpers.
//!
//! Obfuscated releases are overwhelmingly encrypted RAR5 STORE archives -
//! the data is already-compressed media, so `-m0 -p`/`-hp` is the norm.
//! Decrypting those natively keeps them on the one-pass in-stream
//! extraction path; the embedded unrar is only needed for genuinely
//! COMPRESSED sets (full RAR decompression is explicitly out of scope).
//!
//! Key schedule (matches unrar's `CryptData::SetKey` for RAR5):
//! PBKDF2-HMAC-SHA256 over the UTF-8 password with a 16-byte salt and
//! 2^lg2_count iterations yields the AES key; the SAME PBKDF2 block-1
//! chain continued 16 more rounds yields the hash key (tweaked-checksum
//! MAC, unused here), and 16 further rounds the password-check source,
//! XOR-folded to 8 bytes. The stored 12-byte check value is those 8 bytes
//! plus the first 4 of their SHA-256 (a corruption guard, not a secret).
//!
//! RAR4 encryption (AES-128, proprietary SHA-1 key schedule) is NOT
//! implemented: real-world obfuscated posts are RAR5 (WinRAR ≥5.0,
//! 2013), and RAR4-encrypted sets keep falling back to unrar.

use std::collections::HashMap;
use std::sync::Mutex;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Block = GenericArray<u8, aes::cipher::consts::U16>;

/// View a 16-aligned byte buffer as AES blocks - the batched
/// `{en,de}crypt_blocks_mut` APIs let the backend pipeline several
/// blocks per call (4x on soft AES, ~1.2x on hardware; measured).
/// GenericArray<u8, U16> is layout-identical to [u8; 16] (align 1), so
/// the cast is sound for any len % 16 == 0 slice.
fn as_blocks(data: &mut [u8]) -> &mut [Block] {
    debug_assert_eq!(data.len() % 16, 0);
    unsafe { core::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<Block>(), data.len() / 16) }
}

/// Iteration exponents above this are hostile (unrar caps at 24 too):
/// 2^24 ≈ 16M HMAC rounds is already ~10 s of KDF.
pub const MAX_KDF_LG2: u8 = 24;

#[derive(Clone, PartialEq, Eq)]
pub struct Rar5Keys {
    /// AES-256 key.
    pub key: [u8; 32],
    /// Tweaked-checksum HMAC key (derived for completeness; extraction
    /// trusts PAR2-verified volume bytes, not per-file checksums).
    pub hash_key: [u8; 32],
    /// 8-byte password check value - compare against a header's stored
    /// check to reject a wrong password BEFORE writing garbage.
    pub psw_check: [u8; 8],
}

/// PBKDF2-HMAC-SHA256, block 1 only (RAR5 never needs more than 32
/// bytes), with the RAR twist: three outputs off one U-chain at
/// `count`, `count+16`, and `count+32` iterations.
fn pbkdf2_chain(password: &[u8], salt: &[u8; 16], lg2_count: u8) -> Rar5Keys {
    let count: u64 = 1u64 << lg2_count.min(MAX_KDF_LG2);
    let prf = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
    // U1 = HMAC(pw, salt || INT_BE(1))
    let mut mac = prf.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut t = u;
    let mut key = [0u8; 32];
    let mut hash_key = [0u8; 32];
    let mut check_src = [0u8; 32];
    let mut i: u64 = 1;
    for (target, out) in [
        (count, &mut key),
        (count + 16, &mut hash_key),
        (count + 32, &mut check_src),
    ] {
        while i < target {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
            for (tb, ub) in t.iter_mut().zip(u.iter()) {
                *tb ^= ub;
            }
            i += 1;
        }
        *out = t;
    }
    let mut psw_check = [0u8; 8];
    for (i, b) in check_src.iter().enumerate() {
        psw_check[i % 8] ^= b;
    }
    Rar5Keys { key, hash_key, psw_check }
}

/// KDF cache: a multi-volume set repeats ONE (salt, count) pair in every
/// volume's file header, and header-encrypted sets run one KDF per
/// volume - either way the same tuple recurs, and at 2^15 HMAC rounds a
/// miss costs ~10 ms inside the extractor's routing lock. Bounded: a
/// hostile NZB can't grow it past a few hundred entries.
static KDF_CACHE: Mutex<Option<HashMap<(Vec<u8>, [u8; 16], u8), Rar5Keys>>> = Mutex::new(None);
const KDF_CACHE_MAX: usize = 512;

/// Derive (or fetch cached) RAR5 keys. Returns None for a hostile
/// iteration count.
pub fn derive_keys(password: &str, salt: &[u8; 16], lg2_count: u8) -> Option<Rar5Keys> {
    if lg2_count > MAX_KDF_LG2 {
        return None;
    }
    let ck = (password.as_bytes().to_vec(), *salt, lg2_count);
    {
        let g = KDF_CACHE.lock().unwrap();
        if let Some(hit) = g.as_ref().and_then(|m| m.get(&ck)) {
            return Some(hit.clone());
        }
    }
    let keys = pbkdf2_chain(password.as_bytes(), salt, lg2_count);
    let mut g = KDF_CACHE.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= KDF_CACHE_MAX {
        m.clear();
    }
    m.insert(ck, keys.clone());
    Some(keys)
}

/// The 12-byte stored check = 8-byte value + first 4 bytes of its
/// SHA-256. Only a csum-valid stored check can veto a password: a
/// corrupted check value must not condemn a correct password (unrar
/// behaves the same way).
pub fn check_rejects_password(keys: &Rar5Keys, stored: &[u8; 12]) -> bool {
    check_is_wellformed(stored) && stored[..8] != keys.psw_check
}

/// Does the stored check value carry a valid self-csum, i.e. can it decide
/// anything at all about a password?
///
/// Callers must not read "did not reject" as "verified": a check whose csum is
/// wrong rejects NOTHING, for every password. Such a value is exactly as
/// useless as no check at all, and an entry carrying one has to take the
/// same conservative route (hand it to a tool that validates the password
/// itself) rather than the native-decrypt-with-a-verified-password route.
pub fn check_is_wellformed(stored: &[u8; 12]) -> bool {
    let csum = Sha256::digest(&stored[..8]);
    stored[8..12] == csum[..4]
}

/// Streaming AES-256-CBC decryptor. `data` length must be a multiple of
/// 16; chaining state carries across calls, so a multi-gigabyte file
/// decrypts in bounded chunks.
pub struct CbcStream {
    dec: Aes256CbcDec,
}

impl CbcStream {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> CbcStream {
        CbcStream {
            dec: Aes256CbcDec::new(key.into(), iv.into()),
        }
    }

    /// Decrypt `data` in place (len % 16 == 0).
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.dec.decrypt_blocks_mut(as_blocks(data));
    }
}

/// One-shot decrypt of an aligned buffer (header blocks).
pub fn cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    CbcStream::new(key, iv).decrypt(data);
}

/// Encrypt helper - the test-fixture writers build real encrypted
/// archives with it (streaming, chaining across calls like CbcStream).
#[doc(hidden)]
pub struct CbcEncStream {
    enc: Aes256CbcEnc,
}

#[doc(hidden)]
impl CbcEncStream {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> CbcEncStream {
        CbcEncStream {
            enc: Aes256CbcEnc::new(key.into(), iv.into()),
        }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.enc.encrypt_blocks_mut(as_blocks(data));
    }
}

/// Build the stored 12-byte check value for a key set (fixture writers).
#[doc(hidden)]
pub fn make_check(keys: &Rar5Keys) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&keys.psw_check);
    let csum = Sha256::digest(keys.psw_check);
    out[8..].copy_from_slice(&csum[..4]);
    out
}

/// Round a byte count up to the AES block size.
pub fn align16(n: u64) -> u64 {
    (n + 15) & !15
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test against real `rar 7.23` output: salt and stored
    /// password-check captured from a `-m0 -ptestpw123` archive's file
    /// crypto record (lg2 count 15). The committed `testdata/rar5/`
    /// fixtures exercise the same path through the full parser.
    #[test]
    fn kdf_matches_real_rar_check_values() {
        let salt: [u8; 16] = [
            0x9b, 0xcb, 0x5d, 0x14, 0x2e, 0x58, 0x5c, 0x72, 0xa8, 0xcd, 0x18, 0x11, 0x5f, 0x1c,
            0x61, 0x09,
        ];
        let keys = derive_keys("testpw123", &salt, 15).unwrap();
        assert_eq!(
            keys.psw_check,
            [0x54, 0x1b, 0x2d, 0xd4, 0x84, 0xea, 0xc7, 0x7d],
            "PBKDF2 chain diverges from real rar output"
        );
        // The stored 12-byte check from the same archive must NOT reject.
        let stored: [u8; 12] = [
            0x54, 0x1b, 0x2d, 0xd4, 0x84, 0xea, 0xc7, 0x7d, 0x3b, 0x09, 0xf3, 0xc2,
        ];
        assert!(!check_rejects_password(&keys, &stored));
        // …and its csum field really is SHA-256 of the first 8 bytes
        // (otherwise the assertion above passed vacuously).
        let csum = Sha256::digest(&stored[..8]);
        assert_eq!(stored[8..12], csum[..4]);
        // A wrong password must be rejected by the same stored check.
        let wrong = derive_keys("testpw124", &salt, 15).unwrap();
        assert!(check_rejects_password(&wrong, &stored));
        // A corrupted check value (bad csum) must not veto anything.
        let mut bad = stored;
        bad[0] ^= 0xff;
        assert!(!check_rejects_password(&wrong, &bad));
    }

    /// Header-encryption KAT: salt/check captured from a real `-hp`
    /// archive's type-4 (archive encryption) block.
    #[test]
    fn kdf_matches_header_crypt_check() {
        let salt: [u8; 16] = [
            0x15, 0x5c, 0xde, 0x80, 0x9e, 0x10, 0x18, 0x0c, 0xa2, 0xa4, 0x48, 0xcc, 0x58, 0x9c,
            0x70, 0x57,
        ];
        let keys = derive_keys("testpw123", &salt, 15).unwrap();
        assert_eq!(
            keys.psw_check,
            [0xf9, 0x31, 0xa0, 0xd2, 0x5a, 0x07, 0xb5, 0xe4]
        );
    }

    #[test]
    fn cbc_roundtrip_streaming() {
        let key = [7u8; 32];
        let iv = [3u8; 16];
        let plain: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut buf = plain.clone();
        let mut enc = CbcEncStream::new(&key, &iv);
        enc.encrypt(&mut buf);
        assert_ne!(buf, plain);
        // Decrypt in mismatched chunk sizes to prove chaining carries.
        let mut dec = CbcStream::new(&key, &iv);
        let (a, b) = buf.split_at_mut(1024 + 16);
        dec.decrypt(a);
        dec.decrypt(b);
        assert_eq!(buf, plain);
    }

    #[test]
    fn hostile_kdf_count_refused() {
        assert!(derive_keys("x", &[0u8; 16], 25).is_none());
        assert!(derive_keys("x", &[0u8; 16], 255).is_none());
    }
}

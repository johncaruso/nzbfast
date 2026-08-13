# External-corpus RAR 1.5-4.0 Fixtures

Archives promoted from other projects' regression corpora, kept because they
pin a header or codec shape our own encoder does not produce.

| Fixture | Upstream | Purpose |
|---|---|---|
| `rar2_unix_owner.rar` | [markokr/rarfile](https://github.com/markokr/rarfile) `test/files/rar2-unix-owner.rar`, sha256 `899724d4ac341fee19567a23a4d3b08b35d69cca0d14a4d01a6e08a5869d2281` | RAR 2.x unix-owner sub-block (`0x77`, sub type `UO_HEAD` = `0x0101`). Its `HEAD_CRC` covers the owner and group names, which sit in the block's DATA area past `head_size`; checksumming only `head_size` gave `expected 0x1fc3, got 0x974d` and the archive would not open. Payload `file.txt` = `foo\n`, CRC32 `0x7e3265a8`. The archive also carries a `Protect!` recovery record. |

Reference behaviour, measured 12 Aug 2026: `rar` 7.23 extracts `file.txt`
(sha256 `b5bb9d80...`). 7-Zip 24 `7zz` reads the headers but cannot decode the
RAR 2.0 method, so it reports `Unsupported Method` and writes a 0-byte file.

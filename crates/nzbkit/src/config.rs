//! Local configuration (`config.local.json`, gitignored - holds credentials).

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing config: {0}")]
    Json(#[from] serde_json::Error),
    #[error("parsing sabnzbd.ini: {0}")]
    Ini(String),
    #[error("config has no servers")]
    NoServers,
    #[error(
        "config has {0} servers; the maximum is {max}. Routing state (which \
         servers have 430'd an article, which are live, retention windows) is \
         a bitmask with one bit per server, so servers past the {max}th have \
         no bit of their own and would be treated as already-tried",
        max = crate::pool::MAX_SERVERS
    )]
    TooManyServers(usize),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub servers: Vec<ServerConfig>,
    /// M13: TMDB API key for poster-wall metadata/artwork. Absent =
    /// wall runs text-only. (TMDB_API_KEY env var also works.)
    #[serde(default)]
    pub tmdb_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Stored obfuscated (`obf1:…`), read as either that or cleartext. See
    /// [`obfuscate`] - it is obfuscation, not encryption.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_secret",
        serialize_with = "ser_secret"
    )]
    pub password: Option<String>,
    /// Provider's allowed concurrent connections (we typically use far fewer).
    #[serde(default = "default_connections")]
    pub connections: u32,
    /// Socket receive buffer in bytes (best-effort; kernel may clamp).
    /// Leave unset: kernels autotune per-connection windows (Linux to
    /// ~6 MB via tcp_rmem, macOS to 4 MB via autorcvbufmax), and bench
    /// probes show real usenet paths cap per-connection rate far below
    /// where those ceilings bind (~40 Mbps/conn transatlantic vs the
    /// ~420 Mbps a 4 MB window sustains at 77 ms). On Linux an explicit
    /// value is usually a DOWNGRADE: setting SO_RCVBUF disables
    /// autotuning and is clamped to net.core.rmem_max (~208 KB stock),
    /// shrinking the window ~30x. Only set this on a host whose
    /// rmem_max has been raised to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcvbuf: Option<u32>,
    /// M14e tier (NZBGet "Level"): 0 = primary; a level-N server only
    /// fetches articles every live lower-level server has already missed.
    /// Fill-server economics - pay-per-GB blocks never see bytes the
    /// flatrate primaries can serve.
    #[serde(default)]
    pub level: u32,
    /// Servers sharing a group name are mirrors of one backbone: a 430
    /// from one marks the article tried on all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Provider retention in days; articles older than this are never
    /// requested from this server (routed to deeper servers instead).
    /// 0 = unlimited.
    #[serde(default)]
    pub retention_days: u32,
    /// Block account: total prepaid bytes. The daemon tracks lifetime
    /// usage per host and stops using the server once the block is
    /// spent. None/0 = unlimited (flatrate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_bytes: Option<u64>,
    /// M32: bind outgoing connections for this server to
    /// a specific local IP - multi-homed boxes and VPN split-tunnel
    /// setups. The address family also picks the target family (a v4
    /// bind connects to the server's v4 address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_ip: Option<String>,
    /// M32 (nzbdav#315): SOCKS5 proxy for this server's NNTP traffic -
    /// "host:port" or "user:pass@host:port". The server hostname is
    /// resolved BY the proxy (no local DNS leak).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5: Option<String>,
    /// Soft on/off switch: a disabled server stays configured (and
    /// testable) but never joins a download pool.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Park this server's drained connections between jobs (§36).
    ///
    /// OFF by default and settled PER SERVER, because the decision is a
    /// property of the link, not of the installation. Measured: on a
    /// controlled 50 ms path pooling is worth -19.5% of job time, but on
    /// a real Starlink link 60 paired reps could not separate it from
    /// nothing (-0.1%, CI -6.2% to +5.9%) - the link's own jitter is far
    /// larger than the 1-2 s the pool saves, so the saving is real and
    /// simply gets buried. We cannot know a user's link, so we do not
    /// guess:  measures THIS server and recommends.
    #[serde(default)]
    pub warm_pool: bool,
}

fn default_port() -> u16 {
    563
}
fn default_true() -> bool {
    true
}
fn default_connections() -> u32 {
    8
}

/// Password OBFUSCATION - deliberately not encryption.
///
/// What this is for: a config file holds provider passwords, and those files
/// end up in screenshots, in forum posts, in bug reports, and on screens other
/// people can see. Storing them as plain readable text makes every one of
/// those an instant disclosure. Obfuscation removes the *casual* leak.
///
/// What this is NOT: protection from anyone who has the file. The key is
/// below, in public source, and the decoder ships in the binary. Anybody who
/// can read the config can recover the password in seconds. Never describe
/// this as encryption anywhere in the UI, the docs or a release note - a user
/// who believes their config is encrypted will attach it to a public issue.
/// The file is still written 0600 and still has to be kept private.
///
/// Neither NZBGet nor SABnzbd obfuscates (both store `password = <cleartext>`),
/// so this is a small improvement on the field norm rather than catching up.
///
/// Format: `obf1:<hex>`. Reading accepts BOTH forms - a cleartext password
/// keeps working, so hand-edited configs and SABnzbd/NZBGet imports are never
/// broken by this. Writing always obfuscates.
const OBF_PREFIX: &str = "obf1:";
const OBF_KEY: &[u8] = b"nzbfast-config-obfuscation-not-encryption";

fn obf_xor(bytes: &[u8]) -> Vec<u8> {
    // Mix the index in as well as the key, so a repeated character does not
    // produce a repeated output byte and the result carries no visible
    // pattern for something like "aaaaaa".
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ OBF_KEY[i % OBF_KEY.len()] ^ (i as u8))
        .collect()
}

/// Obfuscate a secret for writing to disk. Empty stays empty (an empty
/// password is a meaningful "no password", not a secret worth hiding).
pub fn obfuscate(secret: &str) -> String {
    if secret.is_empty() || secret.starts_with(OBF_PREFIX) {
        return secret.to_string();
    }
    let mut out = String::with_capacity(OBF_PREFIX.len() + secret.len() * 2);
    out.push_str(OBF_PREFIX);
    for b in obf_xor(secret.as_bytes()) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Reverse `obfuscate`. Anything that is not in our format is returned
/// unchanged - that is what keeps cleartext configs working.
pub fn deobfuscate(stored: &str) -> String {
    let Some(hex) = stored.strip_prefix(OBF_PREFIX) else {
        return stored.to_string();
    };
    if hex.len() % 2 != 0 {
        return stored.to_string();
    }
    let mut raw = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let Ok(s) = std::str::from_utf8(pair) else { return stored.to_string() };
        let Ok(b) = u8::from_str_radix(s, 16) else { return stored.to_string() };
        raw.push(b);
    }
    // A password is UTF-8; if it does not decode, the value was not ours
    // after all and the caller is better served by the original string.
    String::from_utf8(obf_xor(&raw)).unwrap_or_else(|_| stored.to_string())
}

/// serde hook: de-obfuscate on the way in, so the rest of the program only
/// ever sees the real password and no call site has to remember.
fn de_secret<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(d)?.map(|s| deobfuscate(&s)))
}

/// serde hook: obfuscate on the way out, for any writer that serializes a
/// `ServerConfig` rather than building JSON by hand.
fn ser_secret<S>(v: &Option<String>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match v {
        Some(p) => s.serialize_some(&obfuscate(p)),
        None => s.serialize_none(),
    }
}

impl Config {
    /// Load servers from `path`. A `.ini` extension means SABnzbd's
    /// `sabnzbd.ini` format; anything else is our JSON. If `path` doesn't
    /// exist, fall back to a SABnzbd install's ini in its standard
    /// per-platform location - a machine already running SAB needs no
    /// configuration at all.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let is_ini = |p: &Path| {
            p.extension().is_some_and(|e| e.eq_ignore_ascii_case("ini"))
        };
        let (bytes, ini) = match std::fs::read(path) {
            Ok(b) => (b, is_ini(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(sab) = sabnzbd_ini_path() else { return Err(e.into()) };
                static NOTICE: std::sync::Once = std::sync::Once::new();
                let b = std::fs::read(&sab)?;
                NOTICE.call_once(|| {
                    println!(
                        "[config] {} not found - using SABnzbd servers from {}",
                        path.display(),
                        sab.display()
                    );
                });
                (b, true)
            }
            Err(e) => return Err(e.into()),
        };
        let cfg = if ini {
            let text = String::from_utf8_lossy(&bytes);
            Config { servers: parse_sabnzbd_ini(&text)?, tmdb_key: None }
        } else {
            serde_json::from_slice(&bytes)?
        };
        if cfg.servers.is_empty() {
            return Err(ConfigError::NoServers);
        }
        // Refuse rather than silently alias: past this count the routing
        // bitmasks cannot tell two servers apart, and the failure mode is a
        // provider that never gets asked for articles it holds.
        if cfg.servers.len() > crate::pool::MAX_SERVERS {
            return Err(ConfigError::TooManyServers(cfg.servers.len()));
        }
        Ok(cfg)
    }
}

/// Standard sabnzbd.ini locations, most likely first.
pub fn sabnzbd_ini_path() -> Option<std::path::PathBuf> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(windows)]
    {
        for var in ["LOCALAPPDATA", "APPDATA"] {
            if let Ok(base) = std::env::var(var) {
                candidates.push(
                    std::path::Path::new(&base).join("sabnzbd").join("sabnzbd.ini"),
                );
            }
        }
    }
    #[cfg(not(windows))]
    if let Ok(home) = std::env::var("HOME") {
        let home = std::path::Path::new(&home);
        #[cfg(target_os = "macos")]
        candidates.push(
            home.join("Library/Application Support/SABnzbd/sabnzbd.ini"),
        );
        candidates.push(home.join(".sabnzbd/sabnzbd.ini"));
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Parse the `[servers]` section of a SABnzbd configobj ini. Field
/// mapping: ssl→tls, priority→level, retention→retention_days; servers
/// with `enable = 0` are skipped. Everything else SAB stores per server
/// (timeouts, ciphers, notes…) has no nzbfast equivalent and is ignored.
pub fn parse_sabnzbd_ini(text: &str) -> Result<Vec<ServerConfig>, ConfigError> {
    use std::collections::HashMap;

    fn flush(cur: &mut Option<HashMap<String, String>>, out: &mut Vec<ServerConfig>) {
        let Some(map) = cur.take() else { return };
        let get = |k: &str| map.get(k).map(|s| s.as_str()).unwrap_or("");
        let host = get("host");
        if host.is_empty() || get("enable") == "0" {
            return;
        }
        let tls = get("ssl") != "0"; // SAB default is TLS on
        let opt = |v: &str| (!v.is_empty()).then(|| v.to_string());
        out.push(ServerConfig {
            host: host.to_string(),
            port: get("port")
                .parse()
                .unwrap_or(if tls { 563 } else { 119 }),
            tls,
            username: opt(get("username")),
            password: opt(get("password")),
            connections: get("connections").parse().unwrap_or_else(|_| default_connections()),
            rcvbuf: None,
            level: get("priority").parse().unwrap_or(0),
            group: None,
            retention_days: get("retention").parse().unwrap_or(0),
            block_bytes: None,
            bind_ip: None,
            socks5: None,
            enabled: true,
        warm_pool: false,
        });
    }

    let mut servers = Vec::new();
    let mut in_servers = false;
    let mut cur: Option<HashMap<String, String>> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            flush(&mut cur, &mut servers);
            if in_servers {
                if inner.trim().is_empty() {
                    return Err(ConfigError::Ini("empty server section name".into()));
                }
                cur = Some(HashMap::new());
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush(&mut cur, &mut servers);
            in_servers = line
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .eq_ignore_ascii_case("servers");
            continue;
        }
        if let (Some(map), Some((k, v))) = (cur.as_mut(), line.split_once('=')) {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            map.insert(k.trim().to_ascii_lowercase(), v.to_string());
        }
    }
    flush(&mut cur, &mut servers);
    Ok(servers)
}

/// Parse an NZBGet `nzbget.conf` (flat `ServerN.Key=Value` lines).
/// Mapping: Encryption→tls, Level→level, numeric mirror-group id→group
/// "gN", Retention→retention_days; `Active=no` servers are skipped.
pub fn parse_nzbget_conf(text: &str) -> Vec<ServerConfig> {
    use std::collections::{BTreeMap, HashMap};
    let mut by_idx: BTreeMap<u32, HashMap<String, String>> = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let Some(rest) = k.trim().strip_prefix("Server") else { continue };
        let Some((idx, field)) = rest.split_once('.') else { continue };
        let Ok(idx) = idx.parse::<u32>() else { continue };
        by_idx
            .entry(idx)
            .or_default()
            .insert(field.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    let mut out = Vec::new();
    for m in by_idx.values() {
        let get = |k: &str| m.get(k).map(|s| s.as_str()).unwrap_or("");
        let host = get("host");
        if host.is_empty() || get("active").eq_ignore_ascii_case("no") {
            continue;
        }
        let tls = get("encryption").eq_ignore_ascii_case("yes");
        let opt = |v: &str| (!v.is_empty()).then(|| v.to_string());
        let grp: u32 = get("group").parse().unwrap_or(0);
        out.push(ServerConfig {
            host: host.to_string(),
            port: get("port").parse().unwrap_or(if tls { 563 } else { 119 }),
            tls,
            username: opt(get("username")),
            password: opt(get("password")),
            connections: get("connections").parse().unwrap_or_else(|_| default_connections()),
            rcvbuf: None,
            level: get("level").parse().unwrap_or(0),
            group: (grp > 0).then(|| format!("g{grp}")),
            retention_days: get("retention").parse().unwrap_or(0),
            block_bytes: None,
            bind_ip: None,
            socks5: None,
            enabled: true,
        warm_pool: false,
        });
    }
    out
}

#[cfg(test)]
mod warm_pool_default_tests {
    use super::*;

    /// §36: pooling is OFF unless the server asks for it, and the
    /// absence of the key means off. A config written before this
    /// existed must not silently start pooling on upgrade.
    #[test]
    fn connection_pooling_is_off_unless_a_server_opts_in() {
        let s: ServerConfig =
            serde_json::from_str(r#"{"host":"news.example.com"}"#).unwrap();
        assert!(!s.warm_pool, "a server that never heard of the setting pools nothing");

        let on: ServerConfig =
            serde_json::from_str(r#"{"host":"h","warm_pool":true}"#).unwrap();
        assert!(on.warm_pool);

        // And it is per SERVER: one opting in says nothing about another.
        let cfg: Config = serde_json::from_str(
            r#"{"servers":[{"host":"a","warm_pool":true},{"host":"b"}]}"#,
        )
        .unwrap();
        assert!(cfg.servers[0].warm_pool);
        assert!(!cfg.servers[1].warm_pool, "pooling must not leak between servers");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nzbget_conf_parses_servers_levels_groups() {
        let conf = "\n# comment\nMainDir=/data\nServer1.Active=yes\nServer1.Host=news.prim.com\nServer1.Port=563\nServer1.Username=u1\nServer1.Password=p1\nServer1.Encryption=yes\nServer1.Connections=30\nServer1.Level=0\nServer1.Group=1\nServer2.Active=yes\nServer2.Host=fill.block.com\nServer2.Encryption=no\nServer2.Level=1\nServer2.Retention=4000\nServer3.Active=no\nServer3.Host=off.example.com\n";
        let s = parse_nzbget_conf(conf);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host, "news.prim.com");
        assert!(s[0].tls);
        assert_eq!(s[0].connections, 30);
        assert_eq!(s[0].group.as_deref(), Some("g1"));
        assert_eq!(s[1].host, "fill.block.com");
        assert!(!s[1].tls);
        assert_eq!(s[1].port, 119);
        assert_eq!(s[1].level, 1);
        assert_eq!(s[1].retention_days, 4000);
    }

    use super::*;

    const SAB_INI: &str = r#"
__version__ = 19
[misc]
queue_complete = ""
[servers]
[[main]]
name = news.frugal.com
displayname = Frugal
host = news.frugal.com
port = 563
username = "user@example.com"
password = 's3cr,et"x'
connections = 30
ssl = 1
priority = 0
retention = 0
enable = 1
[[block]]
host = fill.block.co
port = 119
ssl = 0
username = blk
password = pw
connections = 8
priority = 1
retention = 1200
enable = 1
[[old]]
host = dead.example.com
enable = 0
[misc2]
x = y
"#;

    #[test]
    fn sab_ini_maps_fields() {
        let s = parse_sabnzbd_ini(SAB_INI).unwrap();
        assert_eq!(s.len(), 2); // disabled server skipped
        assert_eq!(s[0].host, "news.frugal.com");
        assert_eq!(s[0].port, 563);
        assert!(s[0].tls);
        assert_eq!(s[0].username.as_deref(), Some("user@example.com"));
        assert_eq!(s[0].password.as_deref(), Some("s3cr,et\"x"));
        assert_eq!(s[0].connections, 30);
        assert_eq!(s[0].level, 0);
        assert_eq!(s[1].host, "fill.block.co");
        assert_eq!(s[1].port, 119);
        assert!(!s[1].tls);
        assert_eq!(s[1].level, 1);
        assert_eq!(s[1].retention_days, 1200);
    }

    #[test]
    fn sab_ini_defaults_port_from_ssl() {
        let s = parse_sabnzbd_ini("[servers]\n[[a]]\nhost = h1\n[[b]]\nhost = h2\nssl = 0\n")
            .unwrap();
        assert_eq!((s[0].port, s[0].tls), (563, true));
        assert_eq!((s[1].port, s[1].tls), (119, false));
    }

    #[test]
    fn ini_extension_routes_to_sab_parser() {
        let dir = std::env::temp_dir().join("nzbfast-cfg-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("sabnzbd.ini");
        std::fs::write(&p, SAB_INI).unwrap();
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.servers.len(), 2);
    }
}

#[cfg(test)]
mod obf_tests {
    use super::*;

    #[test]
    fn roundtrips_including_punctuation_and_unicode() {
        // The real password that prompted this work has a '!' in it, which is
        // exactly the class of character rot13 would have left readable.
        for pw in ["gnFr0gfr0g!2", "frogfrog", "a", "p@ss w/ spaces & £unicode✓"] {
            let o = obfuscate(pw);
            assert!(o.starts_with(OBF_PREFIX), "{o}");
            assert!(!o.contains(pw), "obfuscated form still contains the secret: {o}");
            assert_eq!(deobfuscate(&o), pw);
        }
    }

    #[test]
    fn repeated_characters_leave_no_visible_pattern() {
        // Keyed XOR alone would emit the same byte for every 'a'; the index is
        // mixed in so it does not.
        let o = obfuscate("aaaaaaaa");
        let hex = o.strip_prefix(OBF_PREFIX).unwrap();
        let bytes: Vec<&str> = hex.as_bytes().chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap()).collect();
        assert!(bytes.iter().collect::<std::collections::HashSet<_>>().len() > 1);
    }

    #[test]
    fn cleartext_still_loads() {
        // Hand-edited configs and SAB/NZBGet imports must keep working.
        assert_eq!(deobfuscate("frogfrog"), "frogfrog");
        assert_eq!(deobfuscate(""), "");
    }

    #[test]
    fn empty_and_already_obfuscated_are_left_alone() {
        assert_eq!(obfuscate(""), "");
        let once = obfuscate("secret");
        assert_eq!(obfuscate(&once), once, "must not double-obfuscate on re-save");
        assert_eq!(deobfuscate(&once), "secret");
    }

    #[test]
    fn malformed_obf_values_degrade_to_the_original() {
        // Non-hex, and odd-length hex: not ours, hand it back untouched rather
        // than inventing a password.
        for bad in ["obf1:zz", "obf1:abc"] {
            assert_eq!(deobfuscate(bad), bad);
        }
        // An empty payload is not malformed - it means an empty password.
        // Returning the literal "obf1:" here would make us try to authenticate
        // with that string.
        assert_eq!(deobfuscate("obf1:"), "");
    }

    #[test]
    fn config_json_roundtrips_through_serde() {
        let json = r#"{"servers":[{"host":"h","username":"u","password":"gnFr0gfr0g!2"}]}"#;
        let c: Config = serde_json::from_str(json).unwrap();
        assert_eq!(c.servers[0].password.as_deref(), Some("gnFr0gfr0g!2"));
        // Serializing must write the obfuscated form, not the secret.
        let out = serde_json::to_string(&c.servers[0]).unwrap();
        assert!(!out.contains("gnFr0gfr0g"), "cleartext leaked on write: {out}");
        assert!(out.contains("obf1:"), "{out}");
        let back: ServerConfig = serde_json::from_str(&out).unwrap();
        assert_eq!(back.password.as_deref(), Some("gnFr0gfr0g!2"));
    }
}

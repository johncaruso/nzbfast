//! The DNS seam (TODO §129 3a).
//!
//! Every fault shape the §111 campaign raced happens AFTER a TCP
//! connection exists. Name resolution had no seam at all: the dialer
//! called `tokio::net::lookup_host` inline, so a provider hostname that
//! resolves slowly, hands back a dead node ahead of a live one, mixes
//! address families, or stops resolving mid-run had no rig
//! reproduction - which means the client's behavior there was
//! unmeasured and unpinned. (It was also wrong; see the candidate walk
//! in `super::direct_connect_opts`.)
//!
//! Production installs nothing and gets `lookup_host`, unchanged.
//!
//! The override is process-wide rather than per-server on purpose. DNS
//! *is* process-wide, there is exactly one call site to seam, and the
//! alternative - a handle on `ServerConfig`, where `bind_ip`/`rcvbuf`
//! live - would put a runtime object inside a serde config struct and
//! rewrite ~50 struct literals to carry it. Tests inject a registry
//! keyed by hostname ([`crate::mock::dns`]) instead, which is what lets
//! one installed override serve a whole binary of parallel tests: each
//! test owns its own hostname and anything unregistered falls through
//! to the system resolver.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

/// A boxed resolve future. Hand-rolled rather than `async fn` in the
/// trait: the seam has to be `dyn`-compatible and there is no
/// `async-trait` in this tree.
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Resolve a host to the candidate addresses a dial may walk, in the
/// order the resolver wants them tried.
///
/// The order is advisory: [`order_candidates`] still applies the
/// `bind_ip` family filter and the IPv4-first preference on top, and a
/// stable sort means same-family candidates keep the resolver's order.
pub trait Resolve: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// `tokio::net::lookup_host` and nothing else - what every production
/// dial uses.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

static OVERRIDE: OnceLock<Arc<dyn Resolve>> = OnceLock::new();

/// Install the process's resolver.
///
/// Once only, and deliberately so: a resolver swapped mid-flight makes
/// an in-progress dial's candidate list unexplainable after the fact,
/// and nothing needs it - the rig resolver is a registry, so one
/// instance serves every test in a binary. Returns the resolver back in
/// `Err` when one was already installed.
pub fn install_resolver(r: Arc<dyn Resolve>) -> Result<(), Arc<dyn Resolve>> {
    OVERRIDE.set(r)
}

/// True once something has been installed. The rig uses it to tell
/// "nobody asked for a resolver" apart from "my registry lost the
/// race", which are different bugs.
pub fn resolver_installed() -> bool {
    OVERRIDE.get().is_some()
}

/// The one name resolution the NNTP dialer performs.
pub(crate) async fn resolve(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    match OVERRIDE.get() {
        Some(r) => r.resolve(host, port).await,
        // Not `SystemResolver.resolve(..)`: keeping the default arm a
        // direct call means a process that never installs anything pays
        // for the seam with one atomic load and no vtable hop.
        None => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
    }
}

/// Apply the dial's address policy to a resolver's answer.
///
/// Prefer IPv4 - providers count simultaneous source IPs, and macOS can
/// otherwise spread connections across IPv4 plus rotating IPv6 privacy
/// addresses. A `bind_ip`'s family overrides that preference outright:
/// binding a v6 source to a v4 target cannot work.
///
/// Lifted out of `direct_connect_opts` unchanged so the ordering and
/// the three error strings can be unit-tested directly - the strings
/// are what users have already seen in logs, so they are pinned, not
/// reworded.
pub(crate) fn order_candidates(
    host: &str,
    mut addrs: Vec<SocketAddr>,
    bind: Option<IpAddr>,
) -> std::io::Result<Vec<SocketAddr>> {
    match bind {
        Some(ip) => addrs.retain(|a| a.is_ipv4() == ip.is_ipv4()),
        // Stable, so candidates of the same family keep the order the
        // resolver gave them.
        None => addrs.sort_by_key(|a| !a.is_ipv4()),
    }
    if addrs.is_empty() {
        return Err(std::io::Error::other(match bind {
            Some(ip) if ip.is_ipv4() => format!("{host} has no IPv4 address to match bind_ip"),
            Some(_) => format!("{host} has no IPv6 address to match bind_ip"),
            None => format!("{host} did not resolve"),
        }));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(n: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, n], 119))
    }
    fn v6(n: u16) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, n], 119))
    }

    /// The IPv4-first preference, pinned end to end: a resolver that
    /// answers v6 first must still be dialed v4 first. The integration
    /// leg (`family_mix_*`) can only show that a mixed answer connects
    /// - with the candidate walk in place it would connect either way -
    /// so the ORDER is pinned here.
    #[test]
    fn ipv4_sorts_ahead_of_ipv6() {
        let got = order_candidates("h", vec![v6(1), v4(1), v6(2), v4(2)], None).unwrap();
        assert_eq!(got, vec![v4(1), v4(2), v6(1), v6(2)], "v4 must lead");
    }

    /// Same-family candidates keep the resolver's order - a resolver
    /// that puts its healthy node first must not have that undone.
    #[test]
    fn the_sort_is_stable_within_a_family() {
        let got = order_candidates("h", vec![v4(3), v4(1), v4(2)], None).unwrap();
        assert_eq!(got, vec![v4(3), v4(1), v4(2)]);
    }

    /// A bind_ip pins the family and drops everything else, in both
    /// directions.
    #[test]
    fn bind_ip_filters_to_its_own_family() {
        let b4: IpAddr = "127.0.0.1".parse().unwrap();
        let b6: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            order_candidates("h", vec![v6(1), v4(1)], Some(b4)).unwrap(),
            vec![v4(1)]
        );
        assert_eq!(
            order_candidates("h", vec![v6(1), v4(1)], Some(b6)).unwrap(),
            vec![v6(1)]
        );
    }

    /// The three empty-answer messages. Users have seen these strings;
    /// a reword is a support-facing change, so they are pinned.
    #[test]
    fn the_empty_answer_messages_are_pinned() {
        let e = order_candidates("news.example", vec![], None).unwrap_err();
        assert_eq!(e.to_string(), "news.example did not resolve");
        let b6: IpAddr = "::1".parse().unwrap();
        let e = order_candidates("news.example", vec![v4(1)], Some(b6)).unwrap_err();
        assert_eq!(
            e.to_string(),
            "news.example has no IPv6 address to match bind_ip"
        );
        let b4: IpAddr = "127.0.0.1".parse().unwrap();
        let e = order_candidates("news.example", vec![v6(1)], Some(b4)).unwrap_err();
        assert_eq!(
            e.to_string(),
            "news.example has no IPv4 address to match bind_ip"
        );
    }
}

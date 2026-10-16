//! DNS leak detection.
//!
//! Two independent questions are folded into one module because both are about
//! "where does my *name resolution* go", as opposed to where my HTTP traffic
//! goes:
//!
//! 1. **Resolver egress** — who do I appear as when I resolve a special name?
//!    Services like `edns.ip-api.com` and `whoami.akamai.net` (via a soft
//!    resolver) answer with the resolver's own address. If that address belongs
//!    to the local ISP while the egress IP is a proxy, DNS is leaking.
//!
//! 2. **Resolver identity** — which *networks* did the queries traverse? Asking
//!    the same name on many randomised prefixes forces a full delegation walk
//!    and the authoritative servers report the traversing resolvers.
//!
//! We do (1) only. (2) requires authoritative infrastructure we do not control,
//! and faking it by proxying would be worse than not doing it. Better an honest
//! narrow check than a broad fake one.

use crate::http;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioResolver;

/// Query a service that echoes back the *resolver's* address, not ours.
pub async fn resolver_egress() -> Option<String> {
    let client = http::client().ok()?;
    // ip-api's EDNS endpoint reflects the resolver that reached it. Plain text
    // or tiny JSON depending on path; we take the first IP-shaped token.
    for url in [
        "https://edns.ip-api.com/json",
        "http://edns.ip-api.com/json",
    ] {
        if let Ok(r) = client.get(url).send().await {
            if !r.status().is_success() {
                continue;
            }
            if let Ok(body) = r.text().await {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(dns) = v.get("dns") {
                        if let Some(ip) = dns.get("ip").and_then(|x| x.as_str()) {
                            if ip.parse::<std::net::IpAddr>().is_ok() {
                                return Some(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Ask the system resolver to resolve a name we control the shape of, purely to
/// observe whether resolution succeeds at all. A resolver that cannot resolve
/// normal names while HTTP works usually means DNS is being tunnelled or
/// diverted — worth surfacing rather than hiding.
pub async fn system_resolver_works() -> Option<bool> {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(4);
    opts.attempts = 1;
    let resolver = TokioResolver::builder_with_config(ResolverConfig::default(), Default::default())
        .with_options(opts)
        .build()
        .ok()?;

    match resolver.lookup_ip("example.com").await {
        Ok(l) => Some(l.iter().next().is_some()),
        Err(_) => Some(false),
    }
}

/// Compare the resolver's apparent country against the egress IP's country.
/// A mismatch is the classic split-tunnel DNS leak: web traffic goes through
/// the proxy, DNS goes to the local ISP.
pub fn evaluate(
    resolver_ip: Option<&str>,
    resolver_country: Option<&str>,
    egress_country: Option<&str>,
) -> (Option<bool>, String) {
    match (resolver_ip, resolver_country, egress_country) {
        (Some(rip), Some(rc), Some(ec)) if !rc.is_empty() && !ec.is_empty() => {
            if rc.eq_ignore_ascii_case(ec) {
                (
                    Some(true),
                    format!("resolver {rip} ({rc}) matches egress country"),
                )
            } else {
                (
                    Some(false),
                    format!("resolver {rip} in {rc}, but egress reports {ec}"),
                )
            }
        }
        (Some(rip), _, _) => (
            None,
            format!("resolver {rip} seen; country comparison unavailable"),
        ),
        _ => (None, "resolver address not observable".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_countries_agree() {
        let (agree, detail) = evaluate(Some("8.8.8.8"), Some("US"), Some("US"));
        assert_eq!(agree, Some(true));
        assert!(detail.contains("8.8.8.8"));
    }

    #[test]
    fn differing_countries_flagged() {
        let (agree, detail) = evaluate(Some("114.114.114.114"), Some("CN"), Some("US"));
        assert_eq!(agree, Some(false));
        assert!(detail.contains("CN"));
        assert!(detail.contains("US"));
    }

    #[test]
    fn missing_country_degrades_to_unknown_not_false() {
        // We must not report a leak we cannot actually demonstrate.
        let (agree, _) = evaluate(Some("1.1.1.1"), None, Some("US"));
        assert_eq!(agree, None);
    }

    #[test]
    fn no_resolver_is_unknown() {
        let (agree, _) = evaluate(None, None, Some("US"));
        assert_eq!(agree, None);
    }
}

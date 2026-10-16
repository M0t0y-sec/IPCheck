//! DNSBL (DNS blocklist) lookups.
//!
//! Free, no API key, and genuinely independent of the commercial reputation
//! vendors — which makes it valuable: it is the one risk signal that cannot be
//! influenced by which API key you happen to hold.
//!
//! The important subtlety, and the reason this module is longer than a naive
//! implementation: **a DNSBL returning a special "query refused" code must not
//! be reported as a clean result.** Spamhaus refuses queries originating from
//! public resolvers (Google, Cloudflare, Quad9) and signals that with specific
//! return addresses in 127.255.255.0/24. Treating those as "no hit" would tell
//! the user their IP is clean when we in fact learned nothing. We surface them
//! as unavailable instead.

use super::Timed;
use crate::types::{Provenance, SourceStatus};
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::TokioResolver;
use std::time::Duration;

/// (zone, human name). Kept short: each lookup is a DNS round trip, and the
/// card refreshes on a budget.
pub const ZONES: &[(&str, &str)] = &[
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("b.barracudacentral.org", "Barracuda"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("psbl.surriel.com", "PSBL"),
    ("ubl.unsubscore.com", "UCEPROTECT L2"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Resolved to a blocklist address: this IP is listed as a spam/abuse
    /// source. This is the kind of listing that actually matters.
    Listed(String),
    /// Listings that are *expected* for ordinary consumer addresses and say
    /// nothing bad about the IP for non-mail use. Spamhaus PBL (return code
    /// 127.0.0.10/11) is the canonical case: it means "this is a dynamic
    /// residential/mobile range, so don't run a mail server on it". Flagging a
    /// mobile IP for that would be a false positive, and would make the risk
    /// score useless on exactly the connections this tool is used with.
    BenignPolicy(String),
    /// NXDOMAIN: genuinely not listed.
    Clean,
    /// The list refused to answer us, or the query failed. We learned nothing.
    Unavailable(String),
}

#[derive(Debug, Clone, Default)]
pub struct DnsblResult {
    /// Lists that flagged this IP as an actual abuse source.
    pub hits: Vec<String>,
    /// Lists that flagged it under a policy that applies to ordinary consumer
    /// addresses. Shown for transparency, excluded from the risk score.
    pub policy_listings: Vec<String>,
    /// Lists successfully queried (both the hit and clean cases).
    pub checked: u32,
    pub unavailable: u32,
    pub details: Vec<(String, String)>,
}

impl DnsblResult {
    /// Fraction of *successfully queried* lists that flagged the IP as a real
    /// abuse source.
    ///
    /// Two deliberate exclusions:
    ///   - Unavailable lists are out of the denominator entirely. Counting them
    ///     as clean would dilute the ratio toward safety, which is the wrong
    ///     direction to be wrong in for a risk signal.
    ///   - Policy listings (PBL) are out of the numerator, because they are
    ///     normal for residential/mobile ranges and would otherwise flag most
    ///     consumer connections.
    pub fn hit_ratio(&self) -> Option<f32> {
        if self.checked == 0 {
            return None;
        }
        Some(self.hits.len() as f32 / self.checked as f32)
    }
}

/// Reverse an IPv4 address for DNSBL querying: 1.2.3.4 -> 4.3.2.1
pub fn reverse_ipv4(ip: &str) -> Option<String> {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 || octets.iter().any(|o| o.parse::<u8>().is_err()) {
        return None;
    }
    Some(octets.into_iter().rev().collect::<Vec<_>>().join("."))
}

/// Reverse an IPv6 address into nibble form for DNSBL querying.
pub fn reverse_ipv6(ip: &str) -> Option<String> {
    let addr: std::net::Ipv6Addr = ip.parse().ok()?;
    let nibbles: Vec<String> = addr
        .octets()
        .iter()
        .flat_map(|b| {
            let hi = b >> 4;
            let lo = b & 0x0f;
            [format!("{hi:x}"), format!("{lo:x}")]
        })
        .collect();
    Some(nibbles.into_iter().rev().collect::<Vec<_>>().join("."))
}

/// Classify a resolved DNSBL answer.
///
/// Three distinct outcomes have to be separated, and conflating any two of them
/// produces a tool that lies:
///
///   * **Listed** — a genuine spam/abuse listing (Spamhaus SBL/XBL, and the
///     plain 127.0.0.x answers from the smaller lists).
///   * **BenignPolicy** — a listing that is *normal* for consumer addresses.
///     Spamhaus PBL (127.0.0.10 / .11) means "dynamic residential/mobile
///     range, don't run a mail server here". Every mobile IP on earth is on it.
///     Counting that as a risk hit would make the score useless on exactly the
///     connections this tool is built for — verified against a live China
///     Mobile address during development, where SBL/XBL were clean and only
///     PBL matched.
///   * **Unavailable** — the list refused to answer (127.255.255.x) or the
///     reply was not a valid blocklist address. We learned nothing, and must
///     not report that as "clean".
pub fn classify(answer: &str, zone: &str) -> Verdict {
    let Ok(addr) = answer.parse::<std::net::Ipv4Addr>() else {
        return Verdict::Unavailable(format!("odd answer {answer}"));
    };
    let o = addr.octets();

    // Only 127/8 answers are meaningful for a DNSBL.
    if o[0] != 127 {
        return Verdict::Unavailable(format!("non-loopback answer {answer}"));
    }

    // 127.255.255.0/24 is the widely-followed "operational error" convention.
    if o[1] == 255 && o[2] == 255 {
        let why = match o[3] {
            252 => "list refuses queries from public resolvers",
            253 => "list refuses queries from public resolvers (check your DNS)",
            254 => "list refuses queries from public resolvers",
            _ => "list reported an operational error",
        };
        return Verdict::Unavailable(why.to_string());
    }

    // Spamhaus PBL codes. These zones share the 127.0.0.10/.11 answer, and the
    // meaning is policy rather than abuse.
    let is_spamhaus = zone.ends_with("spamhaus.org");
    if is_spamhaus && (o[3] == 10 || o[3] == 11) {
        return Verdict::BenignPolicy(
            "policy listing (dynamic/consumer range; not an abuse report)".to_string(),
        );
    }

    Verdict::Listed(answer.to_string())
}

/// Build a resolver pointed at the **system's real** nameservers.
///
/// This matters more than it looks: `ResolverConfig::default()` carries an
/// empty `name_servers` list, so a resolver built from it fails every query
/// immediately. That failure mode is silent and looks like "the blocklists are
/// all down", which is exactly the kind of wrong-but-plausible result this
/// whole module is written to avoid. On Windows `builder_tokio` reads the
/// configured servers from the registry.
fn resolver() -> anyhow::Result<TokioResolver> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(4);
    opts.attempts = 1;
    // DNSBL answers are tiny; caching a "listed" verdict would hide a
    // delisting that happened seconds ago.
    opts.cache_size = 0;

    let r = TokioResolver::builder_tokio()
        .map_err(|e| anyhow::anyhow!("system resolver config: {e}"))?
        .with_options(opts)
        .build()
        .map_err(|e| anyhow::anyhow!("resolver build: {e}"))?;
    Ok(r)
}

/// Query every zone for one IP. Runs concurrently; a zone that hangs does not
/// hold up the others.
pub async fn check(ip: &str) -> (DnsblResult, SourceStatus) {
    let t = Timed::new("DNSBL", Provenance::FreeSource);

    let rev = if ip.contains(':') {
        reverse_ipv6(ip)
    } else {
        reverse_ipv4(ip)
    };
    let Some(rev) = rev else {
        return (
            DnsblResult::default(),
            t.fail(format!("cannot reverse {ip}")),
        );
    };

    let resolver = match resolver() {
        Ok(r) => r,
        Err(e) => {
            return (
                DnsblResult::default(),
                t.fail(format!("resolver setup: {e}")),
            )
        }
    };

    let futs = ZONES.iter().map(|(zone, name)| {
        let resolver = resolver.clone();
        let qname = format!("{rev}.{zone}");
        let name = name.to_string();
        let zone = zone.to_string();
        async move {
            let verdict = match resolver.lookup_ip(qname.as_str()).await {
                Ok(lookup) => match lookup.iter().next() {
                    Some(addr) => classify(&addr.to_string(), &zone),
                    None => Verdict::Clean,
                },
                Err(e) => {
                    // NXDOMAIN arrives as an error in hickory, and it is the
                    // "not listed" answer, not a failure. Anything else is a
                    // genuine inability to learn the answer.
                    if e.is_nx_domain() || e.is_no_records_found() {
                        Verdict::Clean
                    } else {
                        Verdict::Unavailable(format!("{e}"))
                    }
                }
            };
            (name, verdict)
        }
    });

    let results = futures::future::join_all(futs).await;

    let mut out = DnsblResult::default();
    for (name, verdict) in results {
        match verdict {
            Verdict::Listed(code) => {
                out.checked += 1;
                out.hits.push(name.clone());
                out.details.push((name, format!("listed ({code})")));
            }
            Verdict::BenignPolicy(why) => {
                out.checked += 1;
                out.policy_listings.push(name.clone());
                out.details.push((name, format!("policy listing: {why}")));
            }
            Verdict::Clean => {
                out.checked += 1;
                out.details.push((name, "clean".into()));
            }
            Verdict::Unavailable(why) => {
                out.unavailable += 1;
                out.details.push((name, format!("unavailable: {why}")));
            }
        }
    }

    let note = if out.checked == 0 {
        format!("no list answered ({} unavailable)", out.unavailable)
    } else {
        let mut parts = vec![format!(
            "{}/{} checked, {} hit",
            out.checked,
            ZONES.len(),
            out.hits.len()
        )];
        if !out.policy_listings.is_empty() {
            parts.push(format!("{} policy", out.policy_listings.len()));
        }
        if out.unavailable > 0 {
            parts.push(format!("{} unavailable", out.unavailable));
        }
        parts.join(", ")
    };

    let status = if out.checked == 0 {
        t.fail(note)
    } else {
        t.ok(note)
    };
    (out, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses_ipv4() {
        assert_eq!(reverse_ipv4("1.2.3.4"), Some("4.3.2.1".into()));
    }

    #[test]
    fn rejects_bad_ipv4() {
        assert_eq!(reverse_ipv4("1.2.3"), None);
        assert_eq!(reverse_ipv4("1.2.3.999"), None);
        assert_eq!(reverse_ipv4("not.an.ip.addr"), None);
    }

    #[test]
    fn reverses_ipv6_into_nibbles() {
        // 2001:db8::1 -> ...0.0.0.0.8.b.d.0.1.0.0.2 reversed nibbles
        let rev = reverse_ipv6("2001:db8::1").unwrap();
        assert!(rev.ends_with("0.8.b.d.0.1.0.0.2"), "got {rev}");
        assert_eq!(rev.split('.').count(), 32);
    }

    #[test]
    fn abuse_listing_is_detected() {
        // 127.0.0.2 is Spamhaus SBL — a real spam-source listing.
        assert!(matches!(
            classify("127.0.0.2", "zen.spamhaus.org"),
            Verdict::Listed(_)
        ));
    }

    #[test]
    fn spamhaus_pbl_is_benign_not_an_abuse_hit() {
        // The case verified live: a China Mobile address where SBL/XBL were
        // clean and only PBL matched. Reporting this as risk would be a false
        // positive on a perfectly ordinary consumer connection.
        assert!(matches!(
            classify("127.0.0.11", "zen.spamhaus.org"),
            Verdict::BenignPolicy(_)
        ));
        assert!(matches!(
            classify("127.0.0.10", "zen.spamhaus.org"),
            Verdict::BenignPolicy(_)
        ));
    }

    #[test]
    fn same_code_from_a_non_spamhaus_zone_is_a_real_listing() {
        // 127.0.0.10 only carries the "policy" meaning inside Spamhaus zones.
        // Treating it as benign everywhere would silently excuse genuine
        // listings from other operators.
        assert!(matches!(
            classify("127.0.0.10", "bl.spamcop.net"),
            Verdict::Listed(_)
        ));
    }

    #[test]
    fn refused_query_is_unavailable_not_clean() {
        // This is the bug this module exists to avoid: 127.255.255.254 looks
        // like a valid 127/8 answer but means "I will not answer you".
        match classify("127.255.255.254", "zen.spamhaus.org") {
            Verdict::Unavailable(why) => assert!(why.contains("public resolvers")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn non_loopback_answer_is_unavailable() {
        assert!(matches!(
            classify("10.0.0.1", "zen.spamhaus.org"),
            Verdict::Unavailable(_)
        ));
    }

    #[test]
    fn hit_ratio_excludes_unavailable_lists() {
        let r = DnsblResult {
            hits: vec!["Spamhaus ZEN".into()],
            checked: 2,
            unavailable: 4,
            ..Default::default()
        };
        // 1 of 2 successfully checked — not 1 of 6.
        assert_eq!(r.hit_ratio(), Some(0.5));
    }

    #[test]
    fn hit_ratio_excludes_policy_listings() {
        let r = DnsblResult {
            hits: vec![],
            policy_listings: vec!["Spamhaus ZEN".into()],
            checked: 6,
            unavailable: 0,
            ..Default::default()
        };
        // A policy listing is in the denominator (we did learn something) but
        // not the numerator, so a mobile IP on PBL alone scores 0 risk.
        assert_eq!(r.hit_ratio(), Some(0.0));
    }

    #[test]
    fn no_checked_lists_yields_none_ratio() {
        let r = DnsblResult::default();
        assert_eq!(r.hit_ratio(), None);
    }
}

//! The aggregator: fan out to every probe and source, merge the results into
//! one `Snapshot`, and decide where the sources disagree.
//!
//! Merge policy, in priority order:
//!   - The **egress IP** comes only from our own consensus probe. No third
//!     party gets to tell us what our address is.
//!   - **Country/city/ASN** take the first source that has a value, but a
//!     disagreement between sources is recorded as a conflict rather than
//!     silently dropped.
//!   - **Boolean type flags** are OR'd pessimistically: if any source says
//!     "proxy", we treat it as a proxy. For a warning system, a false positive
//!     costs a moment of scepticism; a false negative costs the user's account.
//!   - **Risk scores** are kept per-source and handed to the scorer unmerged.

use crate::probe::{dns_leak, egress, env_check, stun};
use crate::score::{tally_checks, tally_sources, Signals};
use crate::source::{dnsbl, ipapi, ipwhois, risk};
use crate::types::{Check, Conflict, Provenance, Snapshot, SourceStatus};
use crate::Config;
use std::time::Instant;

/// Everything the aggregator learned, before it is flattened into a Snapshot.
/// Kept separate so the merge logic can be tested without a network.
#[derive(Default)]
pub struct Collected {
    /// Set only for a single-address lookup, where we are asked about an IP
    /// rather than reporting our own. When present it becomes the snapshot's
    /// subject and the egress-consensus check is reported as not-applicable
    /// rather than faked into looking clean.
    pub subject: Option<String>,
    pub egress: Option<egress::EgressResult>,
    pub ipv6: Option<String>,
    pub stun_mapped: Option<String>,
    pub stun_server: String,
    pub resolver_ip: Option<String>,
    pub resolver_country: Option<String>,
    pub ipapi: Option<ipapi::Profile>,
    pub ipwhois: Option<ipwhois::Profile>,
    /// Not an Option: `DnsblResult` already distinguishes "queried and found
    /// nothing" (checked > 0) from "learned nothing" (checked == 0), so an
    /// extra Option would only add a second way to say the same thing.
    pub dnsbl: dnsbl::DnsblResult,
    pub risk: risk::RiskSignals,
    pub sources: Vec<SourceStatus>,
    pub stun_error: Option<String>,
}

/// Merge collected evidence into a scored snapshot.
pub fn merge(collected: Collected, took_ms: u64) -> Snapshot {
    let ip = collected
        .subject
        .clone()
        .or_else(|| collected.egress.as_ref().and_then(|e| e.ip.clone()))
        .unwrap_or_default();

    let mut snap = Snapshot::new(ip.clone());
    snap.ip_version = if ip.contains(':') { 6 } else { 4 };
    if let Some(ref e) = collected.egress {
        snap.domestic_ip = e.domestic_ip.clone();
        snap.international_ip = e.international_ip.clone();
        snap.domestic_agree = e.domestic_agree;
        snap.domestic_responded = e.domestic_responded;
        snap.international_agree = e.international_agree;
        snap.international_responded = e.international_responded;
    }

    // --- Identity fields: first source with a value wins, but note conflicts.
    let mut conflicts: Vec<Conflict> = Vec::new();

    let ia = collected.ipapi.as_ref();
    let iw = collected.ipwhois.as_ref();

    snap.country = ia
        .and_then(|p| p.country.clone())
        .or_else(|| iw.and_then(|p| p.country.clone()))
        .unwrap_or_default();
    snap.country_code = ia
        .and_then(|p| p.country_code.clone())
        .or_else(|| iw.and_then(|p| p.country_code.clone()))
        .unwrap_or_default();
    snap.city = ia
        .and_then(|p| p.city.clone())
        .or_else(|| iw.and_then(|p| p.city.clone()))
        .unwrap_or_default();
    snap.region = ia
        .and_then(|p| p.region.clone())
        .or_else(|| iw.and_then(|p| p.region.clone()))
        .unwrap_or_default();
    snap.isp = ia
        .and_then(|p| p.isp.clone())
        .or_else(|| iw.and_then(|p| p.isp.clone()))
        .unwrap_or_default();
    snap.org = ia
        .and_then(|p| p.org.clone())
        .or_else(|| iw.and_then(|p| p.org.clone()))
        .unwrap_or_default();
    snap.asn = ia
        .and_then(|p| p.asn.clone())
        .or_else(|| iw.and_then(|p| p.asn.clone()))
        .unwrap_or_default();
    snap.timezone = ia
        .and_then(|p| p.timezone.clone())
        .or_else(|| iw.and_then(|p| p.timezone.clone()))
        .unwrap_or_default();

    // A country mismatch between two free providers is worth surfacing: it
    // usually means the address sits in a disputed or recently reassigned range.
    if let (Some(a), Some(b)) = (
        ia.and_then(|p| p.country_code.clone()),
        iw.and_then(|p| p.country_code.clone()),
    ) {
        if !a.is_empty() && !b.is_empty() && !a.eq_ignore_ascii_case(&b) {
            conflicts.push(Conflict {
                field: "country".into(),
                a: format!("ip-api {a}"),
                b: format!("ipwho.is {b}"),
                delta: 0.0,
            });
        }
    }

    // --- Type flags, OR'd pessimistically.
    snap.is_proxy = or_flags(ia.and_then(|p| p.is_proxy), None);
    snap.is_hosting = or_flags(ia.and_then(|p| p.is_hosting), None);
    snap.is_mobile = ia.and_then(|p| p.is_mobile);
    // ip-api has no dedicated VPN/Tor field; if it says proxy we cannot tell
    // which, and we must not invent a distinction it did not make.
    snap.is_vpn = None;
    snap.is_tor = None;
    if snap.is_proxy == Some(true) {
        // Leaving vpn/tor as unknown rather than false is deliberate: unknown
        // is honest, false would be a claim we cannot support.
    }

    snap.ip_type = ia
        .and_then(|p| p.ip_type())
        .or_else(|| {
            // ipwho.is does not classify; infer from ASN-ish org keywords only
            // when it is unambiguous, otherwise leave unknown rather than guess.
            let org = iw.and_then(|p| p.org.clone()).unwrap_or_default();
            let lower = org.to_lowercase();
            if lower.contains("hosting")
                || lower.contains("datacenter")
                || lower.contains("cloud")
                || lower.contains("vps")
            {
                Some("hosting")
            } else {
                None
            }
        })
        .unwrap_or("unknown")
        .to_string();

    // --- Blacklists.
    snap.blacklist_hits = collected.dnsbl.hits.clone();
    snap.blacklist_policy = collected.dnsbl.policy_listings.clone();
    snap.blacklist_checked = collected.dnsbl.checked;

    // --- Leak / coherence checks.
    let mut checks: Vec<Check> = Vec::new();
    let single_lookup = collected.subject.is_some();

    if single_lookup {
        // We were asked about a specific address, so our own egress consensus
        // says nothing about it. Report not-applicable rather than clean.
        checks.push(Check::unknown(
            "egress",
            "出口一致性",
            "查询指定地址，未测试本机出口",
        ));
    } else if let Some(ref e) = collected.egress {
        if e.responded == 0 {
            checks.push(Check::unknown(
                "egress",
                "出口一致性",
                "所有出口探测端点均不可达",
            ));
        } else if e.dissenting.is_empty() {
            checks.push(Check::ok(
                "egress",
                "出口一致性",
                format!("{}/{} 端点一致", e.agree, e.responded),
            ));
        } else {
            checks.push(Check::bad(
                "egress",
                "出口一致性",
                format!(
                    "{} 个端点返回了不同地址: {}",
                    e.dissenting.len(),
                    e.dissenting.join(", ")
                ),
            ));
        }
    } else {
        checks.push(Check::unknown("egress", "出口一致性", "未执行探测"));
    }

    // IPv6 leaking past an IPv4 path is the single most common surprise.
    if single_lookup {
        checks.push(Check::unknown(
            "ipv6",
            "IPv6",
            "查询指定地址，未测试本机 IPv6",
        ));
    } else {
        let (v6_agree, v6_detail) = env_check::compare_ipv6(
            collected.ipv6.as_deref(),
            collected.egress.as_ref().is_some_and(|e| e.ip.is_some()),
        );
        checks.push(Check {
            key: "ipv6".into(),
            label: "IPv6".into(),
            agrees: v6_agree,
            detail: v6_detail,
        });
    }

    // STUN compares the UDP path against the HTTPS path. For a single-address
    // lookup there is no local UDP path to compare, so it is skipped.
    let stun_subject = if single_lookup {
        None
    } else {
        collected.egress.as_ref().and_then(|e| e.ip.clone())
    };
    match (&collected.stun_mapped, stun_subject) {
        (Some(sm), Some(eip)) => {
            if sm == &eip {
                checks.push(Check::ok(
                    "stun",
                    "UDP 路径",
                    format!("STUN 与 HTTPS 出口一致 ({sm})"),
                ));
            } else {
                checks.push(Check::bad(
                    "stun",
                    "UDP 路径",
                    format!("STUN 看到 {sm}，HTTPS 出口是 {eip} — UDP 未走代理"),
                ));
            }
        }
        (Some(sm), None) => checks.push(Check::unknown(
            "stun",
            "UDP 路径",
            format!("STUN 返回 {sm}，但 HTTPS 出口未知"),
        )),
        (None, _) => {
            let detail = collected
                .stun_error
                .clone()
                .unwrap_or_else(|| "未执行 STUN 探测".into());
            checks.push(Check::unknown("stun", "UDP 路径", detail));
        }
    }

    // DNS: does resolution leave through the same place the traffic does?
    let (dns_agree, dns_detail) = dns_leak::evaluate(
        collected.resolver_ip.as_deref(),
        collected.resolver_country.as_deref(),
        Some(snap.country_code.as_str()).filter(|s| !s.is_empty()),
    );
    checks.push(Check {
        key: "dns".into(),
        label: "DNS 出口".into(),
        agrees: dns_agree,
        detail: dns_detail,
    });

    // Timezone offset: local machine vs what the IP claims.
    let ip_offset = ia
        .and_then(|p| p.utc_offset_minutes)
        .or_else(|| iw.and_then(|p| p.utc_offset_minutes));
    let (tz_agree, tz_detail) = env_check::compare_timezone(ip_offset);
    checks.push(Check {
        key: "timezone".into(),
        label: "时区".into(),
        agrees: tz_agree,
        detail: tz_detail,
    });

    // Locale region vs egress country.
    let (loc_agree, loc_detail) = env_check::compare_locale(
        Some(snap.country_code.as_str()).filter(|s| !s.is_empty()),
    );
    checks.push(Check {
        key: "locale".into(),
        label: "语言区域".into(),
        agrees: loc_agree,
        detail: loc_detail,
    });

    snap.checks = checks;

    // --- Scoring inputs.
    // For a single-address lookup there is no egress consensus to speak of, so
    // we report (1,1) — meaning "the subject is unambiguous" — rather than
    // (0,0), which would read as a total failure to observe anything.
    let (egress_agree, egress_total) = if single_lookup {
        (1, 1)
    } else {
        collected
            .egress
            .as_ref()
            .map(|e| (e.agree, e.responded))
            .unwrap_or((0, 0))
    };
    let (checks_ok, checks_testable) = tally_checks(&snap.checks);
    let (sources_ok, sources_total) = tally_sources(&collected.sources);

    let blacklist_ratio = collected.dnsbl.hit_ratio();

    let signals = Signals {
        ip_type: snap.ip_type.clone(),
        is_proxy: snap.is_proxy,
        is_vpn: snap.is_vpn,
        is_tor: snap.is_tor,
        is_hosting: snap.is_hosting,
        is_mobile: snap.is_mobile,
        abuse_confidence: collected.risk.abuse_confidence,
        scamalytics: collected.risk.scamalytics,
        ipqs: collected.risk.ipqs,
        blacklist_ratio,
        blacklist_hits: snap.blacklist_hits.len() as u32,
        egress_agree,
        egress_total,
        checks_ok,
        checks_testable,
        sources_ok,
        sources_total,
    };

    snap.scores = signals.scores();
    snap.composite = snap.scores.composite();

    // Risk-source conflicts join the country conflicts from earlier.
    conflicts.extend(signals.conflicts());
    snap.conflicts = conflicts;

    snap.sources = collected.sources;
    snap.took_ms = took_ms;
    snap.fetched_at = chrono::Utc::now().timestamp_millis();

    snap
}

/// OR two optional booleans pessimistically: a single `true` wins, and
/// `None` never overrides a `Some`.
fn or_flags(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        (Some(false), None) | (None, Some(false)) => Some(false),
        (None, None) => None,
    }
}

/// Run the full pipeline. Concurrency is deliberate: the slowest source
/// determines wall-clock time, and sources that miss their window degrade.
pub async fn refresh(client: &reqwest::Client, cfg: &Config) -> Snapshot {
    let start = Instant::now();

    // Stage 1: find our address. Everything else depends on knowing it, because
    // querying reputation for the wrong IP is worse than not querying at all.
    let egress_res = if cfg.enable_sources {
        egress::fetch().await
    } else {
        egress::EgressResult::default()
    };

    let target = egress_res.ip.clone();
    let mut collected = Collected {
        egress: Some(egress_res),
        ..Default::default()
    };

    // Stage 2: everything that needs the address, plus the address-independent
    // local probes, all at once.
    let (ipv6, stun_res, resolver, ipapi_res, ipwhois_res, dnsbl_res, risk_res) = tokio::join!(
        async {
            if cfg.enable_sources {
                egress::fetch_ipv6().await
            } else {
                None
            }
        },
        async {
            if cfg.enable_stun {
                stun::query_any().await
            } else {
                stun::StunResult {
                    mapped: None,
                    server: String::new(),
                    error: Some("STUN 探测已禁用".into()),
                }
            }
        },
        async {
            if cfg.enable_sources {
                dns_leak::resolver_egress().await
            } else {
                None
            }
        },
        async {
            match target.as_deref() {
                Some(_) if cfg.enable_sources => ipapi::fetch(client, target.as_deref()).await,
                _ => (
                    None,
                    crate::source::Timed::new("ip-api", Provenance::FreeSource)
                        .fail("no egress IP to query"),
                ),
            }
        },
        async {
            match target.as_deref() {
                Some(_) if cfg.enable_sources => {
                    ipwhois::fetch(client, target.as_deref()).await
                }
                _ => (
                    None,
                    crate::source::Timed::new("ipwho.is", Provenance::FreeSource)
                        .fail("no egress IP to query"),
                ),
            }
        },
        async {
            match target.as_deref() {
                Some(ip) if cfg.enable_dnsbl => dnsbl::check(ip).await,
                _ => (
                    dnsbl::DnsblResult::default(),
                    crate::source::Timed::new("DNSBL", Provenance::FreeSource)
                        .fail("disabled or no IP"),
                ),
            }
        },
        async {
            match target.as_deref() {
                Some(ip) if cfg.enable_sources => risk::fetch_all(client, cfg, ip).await,
                _ => (risk::RiskSignals::default(), Vec::new()),
            }
        },
    );

    collected.ipv6 = ipv6;
    collected.stun_server = stun_res.server.clone();
    collected.stun_mapped = stun_res.mapped.clone();
    collected.stun_error = stun_res.error.clone();
    collected.resolver_ip = resolver.clone();

    // To judge a DNS leak we need the resolver's *country*, which means a
    // second lookup of the resolver's own address. The result is a hint, not a
    // requirement: if it fails, `dns_leak::evaluate` degrades the check to
    // "unknown" rather than claiming a leak it cannot demonstrate.
    if let Some(ref rip) = resolver {
        let (resolver_profile, _status) = ipapi::fetch(client, Some(rip)).await;
        collected.resolver_country = resolver_profile.and_then(|p| p.country_code);
    }

    collected.ipapi = ipapi_res.0;
    collected.ipwhois = ipwhois_res.0;
    collected.dnsbl = dnsbl_res.0;
    collected.risk = risk_res.0;

    collected.sources.push(ipapi_res.1);
    collected.sources.push(ipwhois_res.1);
    collected.sources.push(dnsbl_res.1);
    collected.sources.extend(risk_res.1);

    merge(collected, start.elapsed().as_millis() as u64)
}

/// Look up a specific address rather than this machine's egress.
///
/// Egress probing is skipped entirely here: the point of specifying an address
/// is to ask "what is this IP", and our own egress answer would be both
/// irrelevant and misleading. The direct-observation checks (STUN, IPv6) are
/// also skipped, because they describe *this machine*, not the address asked
/// about — reporting them would conflate two different subjects.
pub async fn refresh_for(client: &reqwest::Client, cfg: &Config, ip: &str) -> Snapshot {
    let start = Instant::now();

    let (ipapi_res, ipwhois_res, dnsbl_res, risk_res) = tokio::join!(
        async {
            if cfg.enable_sources {
                ipapi::fetch(client, Some(ip)).await
            } else {
                (
                    None,
                    crate::source::Timed::new("ip-api", Provenance::FreeSource)
                        .fail("sources disabled"),
                )
            }
        },
        async {
            if cfg.enable_sources {
                ipwhois::fetch(client, Some(ip)).await
            } else {
                (
                    None,
                    crate::source::Timed::new("ipwho.is", Provenance::FreeSource)
                        .fail("sources disabled"),
                )
            }
        },
        async {
            if cfg.enable_dnsbl {
                dnsbl::check(ip).await
            } else {
                (
                    dnsbl::DnsblResult::default(),
                    crate::source::Timed::new("DNSBL", Provenance::FreeSource).fail("disabled"),
                )
            }
        },
        async {
            if cfg.enable_sources {
                risk::fetch_all(client, cfg, ip).await
            } else {
                (risk::RiskSignals::default(), Vec::new())
            }
        },
    );

    let mut collected = Collected {
        // The queried address is the subject of the report. `egress` stays
        // None, which is what makes the merge treat the local-path checks as
        // not-applicable instead of pretending they passed.
        subject: Some(ip.to_string()),
        ipapi: ipapi_res.0,
        ipwhois: ipwhois_res.0,
        dnsbl: dnsbl_res.0,
        risk: risk_res.0,
        ..Default::default()
    };

    collected.sources.push(ipapi_res.1);
    collected.sources.push(ipwhois_res.1);
    collected.sources.push(dnsbl_res.1);
    collected.sources.extend(risk_res.1);

    merge(collected, start.elapsed().as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pessimistic_or_prefers_true() {
        assert_eq!(or_flags(Some(true), Some(false)), Some(true));
        assert_eq!(or_flags(Some(false), Some(false)), Some(false));
        assert_eq!(or_flags(None, Some(true)), Some(true));
        assert_eq!(or_flags(None, None), None);
        // false must survive alongside None so we keep the knowledge.
        assert_eq!(or_flags(Some(false), None), Some(false));
    }

    #[test]
    fn country_mismatch_between_sources_is_recorded() {
        let mut c = Collected::default();
        c.ipapi = Some(ipapi::Profile {
            country_code: Some("US".into()),
            ..Default::default()
        });
        c.ipwhois = Some(ipwhois::Profile {
            country_code: Some("CA".into()),
            ..Default::default()
        });
        let snap = merge(c, 0);
        assert!(
            snap.conflicts.iter().any(|x| x.field == "country"),
            "expected a country conflict, got {:?}",
            snap.conflicts
        );
    }

    #[test]
    fn agreeing_sources_produce_no_country_conflict() {
        let mut c = Collected::default();
        c.ipapi = Some(ipapi::Profile {
            country_code: Some("US".into()),
            ..Default::default()
        });
        c.ipwhois = Some(ipwhois::Profile {
            country_code: Some("US".into()),
            ..Default::default()
        });
        let snap = merge(c, 0);
        assert!(!snap.conflicts.iter().any(|x| x.field == "country"));
    }

    #[test]
    fn stun_mismatch_is_flagged_as_leak() {
        let mut c = Collected::default();
        c.egress = Some(egress::EgressResult {
            ip: Some("1.1.1.1".into()),
            agree: 3,
            responded: 3,
            ..Default::default()
        });
        c.stun_mapped = Some("9.9.9.9".into());
        let snap = merge(c, 0);
        let stun_check = snap.checks.iter().find(|c| c.key == "stun").unwrap();
        assert_eq!(stun_check.agrees, Some(false));
        assert!(stun_check.detail.contains("9.9.9.9"));
    }

    #[test]
    fn stun_match_is_clean() {
        let mut c = Collected::default();
        c.egress = Some(egress::EgressResult {
            ip: Some("1.1.1.1".into()),
            agree: 3,
            responded: 3,
            ..Default::default()
        });
        c.stun_mapped = Some("1.1.1.1".into());
        let snap = merge(c, 0);
        let stun_check = snap.checks.iter().find(|c| c.key == "stun").unwrap();
        assert_eq!(stun_check.agrees, Some(true));
    }

    #[test]
    fn dissenting_egress_endpoint_breaks_unanimity() {
        let mut c = Collected::default();
        c.egress = Some(egress::EgressResult {
            ip: Some("1.1.1.1".into()),
            agree: 2,
            responded: 3,
            dissenting: vec!["2.2.2.2".into()],
            ..Default::default()
        });
        let snap = merge(c, 0);
        let e = snap.checks.iter().find(|c| c.key == "egress").unwrap();
        assert_eq!(e.agrees, Some(false));
        assert!(e.detail.contains("2.2.2.2"));
    }

    #[test]
    fn snapshot_has_all_expected_checks() {
        let snap = merge(Collected::default(), 0);
        let keys: Vec<&str> = snap.checks.iter().map(|c| c.key.as_str()).collect();
        for expected in ["egress", "ipv6", "stun", "dns", "timezone", "locale"] {
            assert!(keys.contains(&expected), "missing check {expected} in {keys:?}");
        }
    }

    #[test]
    fn hosting_source_makes_ip_type_hosting() {
        let mut c = Collected::default();
        c.ipapi = Some(ipapi::Profile {
            is_hosting: Some(true),
            is_mobile: Some(false),
            is_proxy: Some(false),
            ..Default::default()
        });
        let snap = merge(c, 0);
        assert_eq!(snap.ip_type, "hosting");
        assert!(snap.scores.purity < 50, "purity {}", snap.scores.purity);
    }
}

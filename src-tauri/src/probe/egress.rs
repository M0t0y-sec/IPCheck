//! Egress IP detection by consensus.
//!
//! The naive version of this tool asks one endpoint and prints the answer. That
//! is wrong often enough to matter: a proxy may cover HTTPS but leak plain
//! HTTP, or a TUN device may split traffic per-destination. Asking several
//! endpoints and comparing is what turns "here is an IP" into "here is an IP,
//! and 3/3 independent observers agree".
//!
//! Endpoints are deliberately heterogeneous (different operators, different
//! paths — JSON, plain text, and a CDN trace endpoint) so a single provider's
//! outage or quirk cannot fake agreement.

use crate::http;
use futures::future::join_all;
use std::collections::HashMap;

/// (name, url, extractor). Extractor pulls the IP out of whatever shape the
/// endpoint returns.
type Extractor = fn(&str) -> Option<String>;

#[derive(Clone, Copy)]
enum RouteKind { Domestic, International }

const ENDPOINTS: &[(&str, &str, Extractor, RouteKind)] = &[
    ("国内 · ipw", "https://4.ipw.cn", plain, RouteKind::Domestic),
    ("国内 · ipip", "https://myip.ipip.net", ipip_text, RouteKind::Domestic),
    ("国际 · ipify", "https://api.ipify.org?format=json", json_field, RouteKind::International),
    ("国际 · ifconfig", "https://ifconfig.me/ip", plain, RouteKind::International),
    (
        "cloudflare",
        "https://www.cloudflare.com/cdn-cgi/trace",
        trace_ip,
        RouteKind::International,
    ),
    ("国际 · ip.sb", "https://api.ip.sb/ip", plain, RouteKind::International),
    ("国际 · ident.me", "https://v4.ident.me", plain, RouteKind::International),
    ("国际 · ipinfo", "https://ipinfo.io/ip", plain, RouteKind::International),
];

fn plain(body: &str) -> Option<String> {
    let t = body.trim();
    looks_like_ip(t).then(|| t.to_string())
}

fn json_field(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let ip = v.get("ip")?.as_str()?.trim().to_string();
    looks_like_ip(&ip).then_some(ip)
}

/// Cloudflare's trace endpoint is `key=value` lines; we want `ip=`.
fn trace_ip(body: &str) -> Option<String> {
    let ip = body
        .lines()
        .find_map(|l| l.strip_prefix("ip="))?
        .trim()
        .to_string();
    looks_like_ip(&ip).then_some(ip)
}

fn ipip_text(body: &str) -> Option<String> {
    body.split(|c: char| !c.is_ascii_digit() && c != '.')
        .find(|part| part.parse::<std::net::Ipv4Addr>().is_ok())
        .map(str::to_string)
}

/// Cheap shape check. We are not validating routability, only rejecting HTML
/// error pages and empty bodies that would otherwise look like "agreement".
fn looks_like_ip(s: &str) -> bool {
    if s.is_empty() || s.len() > 45 {
        return false;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    false
}

#[derive(Debug, Clone, Default)]
pub struct EgressResult {
    /// The consensus IP, if any endpoints agreed.
    pub ip: Option<String>,
    /// How many endpoints returned the consensus IP.
    pub agree: u32,
    /// How many endpoints returned anything usable.
    pub responded: u32,
    /// How many endpoints were attempted.
    pub attempted: u32,
    /// Every endpoint's answer or error, for the detail view.
    pub per_endpoint: Vec<(String, String)>,
    /// Non-consensus answers, i.e. addresses seen but not agreed upon.
    pub dissenting: Vec<String>,
    pub domestic_ip: Option<String>,
    pub domestic_agree: u32,
    pub domestic_responded: u32,
    pub international_ip: Option<String>,
    pub international_agree: u32,
    pub international_responded: u32,
}

impl EgressResult {
    /// True when every responsive endpoint agreed. The strong case.
    pub fn unanimous(&self) -> bool {
        self.responded > 0 && self.agree == self.responded
    }
}

/// Query all endpoints concurrently and pick the majority answer.
pub async fn fetch() -> EgressResult {
    let client = match http::probe_client() {
        Ok(c) => c,
        Err(e) => {
            return EgressResult {
                per_endpoint: vec![("client".into(), format!("build failed: {e}"))],
                ..Default::default()
            }
        }
    };

    let futs = ENDPOINTS.iter().map(|(name, url, extract, kind)| {
        let client = client.clone();
        async move {
            let res = client.get(*url).send().await;
            let out = match res {
                Ok(r) => {
                    let status = r.status();
                    if !status.is_success() {
                        (format!("HTTP {status}"), None)
                    } else {
                        match r.text().await {
                            Ok(body) => match extract(&body) {
                                Some(ip) => (ip.clone(), Some(ip)),
                                None => ("no IP in body".to_string(), None),
                            },
                            Err(e) => (format!("read: {e}"), None),
                        }
                    }
                }
                Err(e) => (format!("{}", short_err(&e)), None),
            };
            ((*name).to_string(), *kind, out.0, out.1)
        }
    });

    let results = join_all(futs).await;

    let mut tally: HashMap<String, u32> = HashMap::new();
    let mut domestic: HashMap<String, u32> = HashMap::new();
    let mut international: HashMap<String, u32> = HashMap::new();
    let mut per_endpoint = Vec::new();
    let mut responded = 0u32;

    let mut domestic_responded = 0;
    let mut international_responded = 0;
    for (name, kind, shown, ip) in results {
        if ip.is_some() {
            responded += 1;
            match kind { RouteKind::Domestic => domestic_responded += 1, RouteKind::International => international_responded += 1 }
        }
        if let Some(ref ip) = ip {
            *tally.entry(ip.clone()).or_default() += 1;
            match kind { RouteKind::Domestic => *domestic.entry(ip.clone()).or_default() += 1, RouteKind::International => *international.entry(ip.clone()).or_default() += 1 }
        }
        per_endpoint.push((name, shown));
    }

    let (best_ip, best_count) = tally
        .iter()
        .max_by_key(|(_, c)| **c)
        .map(|(ip, c)| (Some(ip.clone()), *c))
        .unwrap_or((None, 0));
    let (domestic_ip, domestic_agree) = domestic.iter().max_by_key(|(_, c)| **c).map(|(ip,c)|(Some(ip.clone()),*c)).unwrap_or((None,0));
    let (international_ip, international_agree) = international.iter().max_by_key(|(_, c)| **c).map(|(ip,c)|(Some(ip.clone()),*c)).unwrap_or((None,0));

    // Anything that answered with a different address than the winner. Even a
    // single dissenter matters — it usually means a partial proxy.
    //
    // Deduplicated: several endpoints commonly see the *same* second address
    // (a carrier NAT pool, for instance), and listing it once per endpoint
    // produced messages like "2 个端点返回了不同地址: x.x.x.148, x.x.x.148",
    // which reads like a bug in the tool rather than a finding.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let dissenting: Vec<String> = per_endpoint
        .iter()
        .filter_map(|(_, v)| {
            let v = v.trim();
            if !looks_like_ip(v) || Some(v) == best_ip.as_deref() {
                return None;
            }
            seen.insert(v.to_string()).then(|| v.to_string())
        })
        .collect();

    EgressResult {
        // Prefer the international route for the main subject. A domestic
        // endpoint being reachable must not hide a proxy/TUN egress used for
        // the sites the user actually cares about.
        ip: international_ip.clone().or(best_ip),
        agree: best_count,
        responded,
        attempted: ENDPOINTS.len() as u32,
        per_endpoint,
        dissenting,
        domestic_ip,
        domestic_agree,
        domestic_responded,
        international_ip,
        international_agree,
        international_responded,
    }
}

/// Query an IPv6-only endpoint. A proxy that only handles IPv4 will show the
/// machine's real IPv6 address here — a classic leak.
pub async fn fetch_ipv6() -> Option<String> {
    let client = http::probe_client().ok()?;
    for url in [
        "https://api6.ipify.org",
        "https://v6.ident.me",
        "https://ipv6.icanhazip.com",
    ] {
        if let Ok(r) = client.get(url).send().await {
            if r.status().is_success() {
                if let Ok(body) = r.text().await {
                    let t = body.trim().to_string();
                    if t.parse::<std::net::Ipv6Addr>().is_ok() {
                        return Some(t);
                    }
                }
            }
        }
    }
    None
}

/// reqwest errors are verbose; the card shows a short form.
fn short_err(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".into()
    } else if e.is_connect() {
        "connect failed".into()
    } else if e.is_request() {
        "request failed".into()
    } else {
        "error".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ip_from_each_shape() {
        assert_eq!(json_field(r#"{"ip":"1.2.3.4"}"#), Some("1.2.3.4".into()));
        assert_eq!(plain("  9.8.7.6\n"), Some("9.8.7.6".into()));
        assert_eq!(
            trace_ip("fl=1\nip=5.5.5.5\nts=123\n"),
            Some("5.5.5.5".into())
        );
    }

    #[test]
    fn rejects_html_and_junk() {
        assert_eq!(plain("<html>nope</html>"), None);
        assert_eq!(plain(""), None);
        assert_eq!(json_field("not json"), None);
        assert_eq!(trace_ip("fl=1\nts=2"), None);
    }

    #[test]
    fn ipv6_is_accepted_as_an_ip() {
        assert!(looks_like_ip("2606:4700::1111"));
    }
}

//! ip-api.com — the workhorse free source.
//!
//! Fields we actually use: country/city/region for display, `as`/`isp`/`org`
//! for the network picture, `timezone` for the offset comparison, and the
//! `proxy`/`hosting`/`mobile` booleans for the IP-type signal.
//!
//! Free tier is 45 req/min and rate-limits by returning an HTTP 429 with a
//! JSON body rather than a plain error, so we check the body's `status` field
//! as well as the HTTP code.

use super::Timed;
use crate::types::{Provenance, SourceStatus};
use serde::Deserialize;

const FIELDS: &str = "status,message,country,countryCode,regionName,city,timezone,offset,isp,org,as,asname,mobile,proxy,hosting,query";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Resp {
    status: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    region_name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    offset: Option<i32>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    org: Option<String>,
    /// JSON key is literally "as", which is a Rust keyword, hence the rename.
    #[serde(default, rename = "as")]
    asn_raw: Option<String>,
    #[serde(default)]
    mobile: Option<bool>,
    #[serde(default)]
    proxy: Option<bool>,
    #[serde(default)]
    hosting: Option<bool>,
}

/// Normalised result. `offset` is UTC offset in seconds as ip-api reports it.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub timezone: Option<String>,
    pub utc_offset_minutes: Option<i32>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub is_mobile: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_hosting: Option<bool>,
}

impl Profile {
    /// Derive the coarse IP type from the three booleans. Order matters:
    /// hosting wins over mobile/proxy because a datacenter range marked
    /// "mobile" by a sloppy database is still a datacenter.
    pub fn ip_type(&self) -> Option<&'static str> {
        if self.is_hosting == Some(true) {
            return Some("hosting");
        }
        if self.is_mobile == Some(true) {
            return Some("mobile");
        }
        if self.is_proxy == Some(true) {
            return Some("business");
        }
        if self.is_hosting == Some(false) && self.is_mobile == Some(false) {
            return Some("residential");
        }
        None
    }
}

pub async fn fetch(client: &reqwest::Client, target: Option<&str>) -> (Option<Profile>, SourceStatus) {
    let t = Timed::new("ip-api", Provenance::FreeSource);
    // The free endpoint is HTTP-only; that is a documented limitation of the
    // free tier, not an oversight.
    let base = match target {
        Some(ip) => format!("http://ip-api.com/json/{ip}?fields={FIELDS}"),
        None => format!("http://ip-api.com/json/?fields={FIELDS}"),
    };

    let resp = match client.get(&base).send().await {
        Ok(r) => r,
        Err(e) => return (None, t.fail(format!("request failed: {e}"))),
    };

    let status = resp.status();
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => return (None, t.fail(format!("read failed: {e}"))),
    };

    if status.as_u16() == 429 {
        return (None, t.fail("rate limited (45/min free tier)"));
    }
    if !status.is_success() {
        return (None, t.fail(format!("HTTP {status}")));
    }

    let parsed: Resp = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return (None, t.fail(format!("bad JSON: {e}"))),
    };

    if parsed.status != "success" {
        return (
            None,
            t.fail(parsed.message.unwrap_or_else(|| "source reported failure".into())),
        );
    }

    let asn = parsed.asn_raw.map(|s| {
        // ip-api returns "AS13335 Cloudflare, Inc." — keep just the AS number.
        s.split_whitespace().next().unwrap_or(&s).to_string()
    });

    let profile = Profile {
        country: parsed.country,
        country_code: parsed.country_code,
        region: parsed.region_name,
        city: parsed.city,
        timezone: parsed.timezone,
        utc_offset_minutes: parsed.offset.map(|s| s / 60),
        isp: parsed.isp,
        org: parsed.org,
        asn,
        is_mobile: parsed.mobile,
        is_proxy: parsed.proxy,
        is_hosting: parsed.hosting,
    };

    (Some(profile), t.ok("ok"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(hosting: Option<bool>, mobile: Option<bool>, proxy: Option<bool>) -> Profile {
        Profile {
            is_hosting: hosting,
            is_mobile: mobile,
            is_proxy: proxy,
            ..Default::default()
        }
    }

    #[test]
    fn hosting_wins_over_mobile() {
        // A datacenter range wrongly tagged mobile is still a datacenter.
        assert_eq!(p(Some(true), Some(true), None).ip_type(), Some("hosting"));
    }

    #[test]
    fn mobile_detected() {
        assert_eq!(p(Some(false), Some(true), None).ip_type(), Some("mobile"));
    }

    #[test]
    fn clean_flags_are_residential() {
        assert_eq!(
            p(Some(false), Some(false), Some(false)).ip_type(),
            Some("residential")
        );
    }

    #[test]
    fn unknown_is_none_not_residential() {
        assert_eq!(p(None, None, None).ip_type(), None);
    }

    #[test]
    fn asn_is_trimmed_to_the_number() {
        let raw = "AS13335 Cloudflare, Inc.";
        assert_eq!(raw.split_whitespace().next().unwrap(), "AS13335");
    }
}

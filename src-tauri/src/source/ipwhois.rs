//! ipwho.is — free fallback for the basic profile.
//!
//! Exists because ip-api is HTTP-only and occasionally rate-limits; having a
//! second free provider with a different operator means the basic picture
//! degrades gracefully instead of vanishing. Also gives us a cross-check on
//! country/city, which feeds the conflict detector.
//!
//! The endpoint returns `success: false` with a `message` for bad input, and
//! it silently returns an empty body under some conditions (observed while
//! building this), so an empty body is treated as a normal failure rather than
//! a parse error.

use super::Timed;
use crate::types::{Provenance, SourceStatus};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Resp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    timezone: Option<Timezone>,
    #[serde(default)]
    connection: Option<Connection>,
    #[serde(default)]
    flag: Option<Flag>,
}

#[derive(Debug, Deserialize)]
struct Timezone {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    utc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Connection {
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Flag {
    #[serde(default)]
    emoji: Option<String>,
}

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
    pub flag_emoji: Option<String>,
}

/// ipwho.is reports the offset as a string like "+10:00" or "-05:30".
pub fn parse_utc_offset(s: &str) -> Option<i32> {
    let s = s.trim();
    let (sign, rest) = match s.strip_prefix('-') {
        Some(r) => (-1, r),
        None => (1, s.strip_prefix('+').unwrap_or(s)),
    };
    let (h, m) = rest.split_once(':')?;
    let hours: i32 = h.trim().parse().ok()?;
    let mins: i32 = m.trim().parse().ok()?;
    if hours > 14 || mins > 59 {
        return None;
    }
    Some(sign * (hours * 60 + mins))
}

pub async fn fetch(
    client: &reqwest::Client,
    target: Option<&str>,
) -> (Option<Profile>, SourceStatus) {
    let t = Timed::new("ipwho.is", Provenance::FreeSource);
    let url = match target {
        Some(ip) => format!("https://ipwho.is/{ip}"),
        None => "https://ipwho.is/".to_string(),
    };

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return (None, t.fail(format!("request failed: {e}"))),
    };
    if !resp.status().is_success() {
        let code = resp.status();
        return (None, t.fail(format!("HTTP {code}")));
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => return (None, t.fail(format!("read failed: {e}"))),
    };
    if body.trim().is_empty() {
        return (None, t.fail("empty response"));
    }

    let parsed: Resp = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return (None, t.fail(format!("bad JSON: {e}"))),
    };
    if parsed.success == Some(false) {
        return (
            None,
            t.fail(parsed.message.unwrap_or_else(|| "source reported failure".into())),
        );
    }

    let (timezone, offset) = match parsed.timezone {
        Some(tz) => (
            tz.id,
            tz.utc.as_deref().and_then(parse_utc_offset),
        ),
        None => (None, None),
    };

    let (isp, org, asn) = match parsed.connection {
        Some(c) => (
            c.isp,
            c.org,
            c.asn.map(|a| format!("AS{a}")),
        ),
        None => (None, None, None),
    };

    let profile = Profile {
        country: parsed.country,
        country_code: parsed.country_code,
        region: parsed.region,
        city: parsed.city,
        timezone,
        utc_offset_minutes: offset,
        isp,
        org,
        asn,
        flag_emoji: parsed.flag.and_then(|f| f.emoji),
    };

    (Some(profile), t.ok("ok"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_positive_offset() {
        assert_eq!(parse_utc_offset("+10:00"), Some(600));
    }

    #[test]
    fn parses_negative_offset() {
        assert_eq!(parse_utc_offset("-05:00"), Some(-300));
    }

    #[test]
    fn parses_half_hour_offset() {
        assert_eq!(parse_utc_offset("+05:30"), Some(330));
    }

    #[test]
    fn parses_offset_without_explicit_sign() {
        assert_eq!(parse_utc_offset("08:00"), Some(480));
    }

    #[test]
    fn rejects_absurd_offsets() {
        assert_eq!(parse_utc_offset("+99:00"), None);
        assert_eq!(parse_utc_offset("+05:99"), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_utc_offset("UTC"), None);
        assert_eq!(parse_utc_offset(""), None);
    }
}

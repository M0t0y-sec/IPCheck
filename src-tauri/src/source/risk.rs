//! Keyed risk sources: AbuseIPDB, Scamalytics, IPQS.
//!
//! Every one of these is optional. With no key configured the module returns
//! `None` and a note explaining the degradation, and the scorer simply runs
//! with the signals it has (blocklists alone still give a usable risk figure).
//! This is the "免费为主 + 预留 key 位" contract: adding a key sharpens the
//! verdict, it never gates it.
//!
//! Note on what these scores mean: they are *vendor opinions*, not measurements.
//! That is why the scorer keeps them separate and flags disagreement rather
//! than blending them into one authoritative-looking number.

use super::Timed;
use crate::types::{Provenance, SourceStatus};

#[derive(Debug, Clone, Default)]
pub struct RiskSignals {
    /// AbuseIPDB confidence of abuse, 0..=100.
    pub abuse_confidence: Option<f32>,
    pub abuse_reports: Option<u32>,
    /// Scamalytics fraud score, 0..=100.
    pub scamalytics: Option<f32>,
    /// IPQS fraud score, 0..=100.
    pub ipqs: Option<f32>,
}

/// AbuseIPDB: `GET /api/v2/check?ipAddress=...` with a `Key` header.
pub async fn abuseipdb(
    client: &reqwest::Client,
    key: &str,
    ip: &str,
) -> (Option<f32>, Option<u32>, SourceStatus) {
    let t = Timed::new("AbuseIPDB", Provenance::KeyedSource);
    if key.is_empty() {
        return (None, None, t.unconfigured("no API key (optional)"));
    }

    let resp = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
        .header("Key", key)
        .header("Accept", "application/json")
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => return (None, None, t.fail(format!("request: {e}"))),
    };
    let status = resp.status();
    if status.as_u16() == 429 {
        return (None, None, t.fail("rate limited (free tier 1000/day)"));
    }
    if status.as_u16() == 401 {
        return (None, None, t.fail("invalid API key"));
    }
    if !status.is_success() {
        return (None, None, t.fail(format!("HTTP {status}")));
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => return (None, None, t.fail(format!("read: {e}"))),
    };
    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return (None, None, t.fail(format!("bad JSON: {e}"))),
    };

    let data = &v["data"];
    let score = data["abuseConfidenceScore"].as_f64().map(|f| f as f32);
    let reports = data["totalReports"].as_u64().map(|u| u as u32);

    match score {
        Some(s) => (Some(s), reports, t.ok(format!("confidence {s:.0}, {} reports", reports.unwrap_or(0)))),
        None => (None, None, t.fail("response missing score")),
    }
}

/// Scamalytics requires a key and account id; without a documented public JSON
/// contract for the free key path we only wire the shape and fail soft.
pub async fn scamalytics(
    client: &reqwest::Client,
    key: &str,
    ip: &str,
) -> (Option<f32>, SourceStatus) {
    let t = Timed::new("Scamalytics", Provenance::KeyedSource);
    if key.is_empty() {
        return (None, t.unconfigured("no API key (optional)"));
    }

    // The key is passed as the username half of basic auth on the documented
    // endpoint. If the account is not entitled, the API answers 403 and we
    // degrade rather than guess.
    let resp = client
        .get("https://api11.scamalytics.com/v3/")
        .query(&[
            ("key", key),
            ("ip", ip),
            ("url", "ip-address-checker"),
        ])
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => return (None, t.fail(format!("request: {e}"))),
    };
    let status = resp.status();
    if !status.is_success() {
        return (None, t.fail(format!("HTTP {status}")));
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => return (None, t.fail(format!("read: {e}"))),
    };
    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return (None, t.fail(format!("bad JSON: {e}"))),
    };

    // Score lives in different places depending on response shape.
    let score = v["score"]
        .as_str()
        .and_then(|s| s.parse::<f32>().ok())
        .or_else(|| v["score"].as_f64().map(|f| f as f32))
        .or_else(|| v["scamalytics_score"].as_f64().map(|f| f as f32));

    match score {
        Some(s) => (Some(s), t.ok(format!("fraud score {s:.0}"))),
        None => (None, t.fail("response missing score")),
    }
}

/// IPQS: `GET /json/ip/{ip}?key=...`
pub async fn ipqs(client: &reqwest::Client, key: &str, ip: &str) -> (Option<f32>, SourceStatus) {
    let t = Timed::new("IPQS", Provenance::KeyedSource);
    if key.is_empty() {
        return (None, t.unconfigured("no API key (optional)"));
    }

    let url = format!("https://ipqualityscore.com/api/json/ip/{key}/{ip}");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return (None, t.fail(format!("request: {e}"))),
    };
    let status = resp.status();
    if status.as_u16() == 429 {
        return (None, t.fail("quota exceeded"));
    }
    if !status.is_success() {
        return (None, t.fail(format!("HTTP {status}")));
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => return (None, t.fail(format!("read: {e}"))),
    };
    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return (None, t.fail(format!("bad JSON: {e}"))),
    };

    if v["success"].as_bool() == Some(false) {
        let msg = v["message"].as_str().unwrap_or("source reported failure");
        return (None, t.fail(msg.to_string()));
    }

    match v["fraud_score"].as_f64().map(|f| f as f32) {
        Some(s) => (Some(s), t.ok(format!("fraud score {s:.0}"))),
        None => (None, t.fail("response missing fraud_score")),
    }
}

/// Run whichever keyed sources are configured, concurrently.
pub async fn fetch_all(
    client: &reqwest::Client,
    cfg: &crate::Config,
    ip: &str,
) -> (RiskSignals, Vec<SourceStatus>) {
    let (a, s, i) = tokio::join!(
        abuseipdb(client, &cfg.abuseipdb_key, ip),
        scamalytics(client, &cfg.scamalytics_key, ip),
        ipqs(client, &cfg.ipqs_key, ip),
    );

    (
        RiskSignals {
            abuse_confidence: a.0,
            abuse_reports: a.1,
            scamalytics: s.0,
            ipqs: i.0,
        },
        vec![a.2, s.1, i.1],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_keys_degrade_without_erroring() {
        let client = crate::http::client().unwrap();
        let cfg = crate::Config::default(); // all keys empty
        let (signals, statuses) = fetch_all(&client, &cfg, "1.1.1.1").await;

        assert!(signals.abuse_confidence.is_none());
        assert!(signals.scamalytics.is_none());
        assert!(signals.ipqs.is_none());
        assert_eq!(statuses.len(), 3);
        // Every status must be a soft failure carrying an explanatory note,
        // never a hard error that would abort the refresh.
        for s in &statuses {
            assert!(!s.ok, "{} should not be ok without a key", s.name);
            assert!(
                s.note.contains("no API key"),
                "{} note was {:?}",
                s.name,
                s.note
            );
        }
    }
}

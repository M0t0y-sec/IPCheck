//! Shared data types exchanged between the probe/source layers, the scoring
//! engine, and the UI. Serialized straight to the frontend, so field names are
//! camelCase and every score carries its own confidence.

use serde::{Deserialize, Serialize};

/// Where a fact came from. Kept per-field so the UI can show provenance and the
/// score can down-weight low-trust inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Provenance {
    /// Observed directly from this machine (STUN, egress endpoints, DNS).
    Local,
    /// Free third-party source, no key required.
    FreeSource,
    /// Keyed/commercial source.
    KeyedSource,
    /// Derived by our own scoring layer.
    Derived,
}

/// The four sub-scores plus the composite. Each is 0..=100 where higher is
/// better for "purity"/"trust"/"consistency", but `risk` is inverted at the UI
/// layer (higher risk = worse). Keeping them separate avoids the classic
/// mistake of averaging a cleanliness signal with a fraud signal.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scores {
    /// Residential/clean ASN, not datacenter, not in proxy/VPN/Tor lists.
    pub purity: u8,
    /// Fraud/abuse reputation. Higher = more dangerous.
    pub risk: u8,
    /// How much we believe the picture: source agreement, egress consistency.
    pub confidence: u8,
    /// Environment coherence: timezone/locale/IPv6/DNS all pointing one way.
    pub consistency: u8,
}

impl Scores {
    /// Composite is deliberately NOT a flat mean. Risk drags purity down more
    /// than purity lifts risk, because a high-risk datacenter IP is the case
    /// that actually bites people.
    pub fn composite(&self) -> u8 {
        let base = (self.purity as f32 * 0.35)
            + (self.confidence as f32 * 0.20)
            + (self.consistency as f32 * 0.15)
            + ((100 - self.risk) as f32 * 0.30);
        base.round().clamp(0.0, 100.0) as u8
    }
}

/// One detected-or-cleared leak vector. `agrees == false` means we found a
/// mismatch, which is the thing users actually care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub key: String,
    pub label: String,
    /// true = consistent/no-leak, false = mismatch found, None = could not test.
    pub agrees: Option<bool>,
    /// Human-readable detail, e.g. the leaked address or the two differing values.
    pub detail: String,
}

impl Check {
    pub fn ok(key: &str, label: &str, detail: impl Into<String>) -> Self {
        Self { key: key.into(), label: label.into(), agrees: Some(true), detail: detail.into() }
    }
    pub fn bad(key: &str, label: &str, detail: impl Into<String>) -> Self {
        Self { key: key.into(), label: label.into(), agrees: Some(false), detail: detail.into() }
    }
    pub fn unknown(key: &str, label: &str, detail: impl Into<String>) -> Self {
        Self { key: key.into(), label: label.into(), agrees: None, detail: detail.into() }
    }
}

/// A single third-party source that contributed to this snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    pub name: String,
    pub ok: bool,
    /// Why it failed, or a note on degradation (missing key, rate limited).
    pub note: String,
    pub provenance: Provenance,
    pub took_ms: u64,
    /// False when the source was skipped by *our own configuration* — e.g. a
    /// keyed source with no key set. This is distinct from `ok == false`:
    /// nothing went wrong, we simply chose not to ask. Unconfigured sources are
    /// shown to the user (so they know the key is available) but are excluded
    /// from the confidence denominator, because their absence is not a failure
    /// of the evidence we did gather.
    #[serde(default = "default_true")]
    pub configured: bool,
}

fn default_true() -> bool {
    true
}

/// A conflict between two sources big enough that we refuse to silently
/// average it away. Surfacing this is often more useful than any single score:
/// it means the line is behaving inconsistently.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    pub field: String,
    pub a: String,
    pub b: String,
    pub delta: f32,
}

/// The full picture for one point in time. This is what crosses the IPC
/// boundary and what gets cached.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub ip: String,
    /// Separate route observations. `ip` remains the preferred international
    /// consensus address for backwards compatibility.
    #[serde(default)]
    pub domestic_ip: Option<String>,
    #[serde(default)]
    pub international_ip: Option<String>,
    #[serde(default)]
    pub domestic_agree: u32,
    #[serde(default)]
    pub domestic_responded: u32,
    #[serde(default)]
    pub international_agree: u32,
    #[serde(default)]
    pub international_responded: u32,
    pub ip_version: u8,
    pub country_code: String,
    pub country: String,
    pub city: String,
    pub region: String,
    pub asn: String,
    pub org: String,
    pub isp: String,
    /// residential | mobile | business | hosting | unknown
    pub ip_type: String,
    pub is_proxy: Option<bool>,
    pub is_vpn: Option<bool>,
    pub is_tor: Option<bool>,
    pub is_hosting: Option<bool>,
    pub is_mobile: Option<bool>,
    pub timezone: String,
    pub flag_emoji: String,
    /// Blacklists that flagged this IP as an abuse source.
    pub blacklist_hits: Vec<String>,
    /// Lists that matched only under a consumer-range policy (e.g. Spamhaus
    /// PBL). Kept separate from `blacklist_hits` because these are normal for
    /// residential/mobile addresses and must not read as a risk finding.
    #[serde(default)]
    pub blacklist_policy: Vec<String>,
    pub blacklist_checked: u32,

    pub scores: Scores,
    pub composite: u8,

    pub checks: Vec<Check>,
    pub sources: Vec<SourceStatus>,
    pub conflicts: Vec<Conflict>,

    /// Unix millis.
    pub fetched_at: i64,
    pub took_ms: u64,
}

impl Snapshot {
    pub fn new(ip: impl Into<String>) -> Self {
        Self {
            ip: ip.into(),
            domestic_ip: None,
            international_ip: None,
            domestic_agree: 0,
            domestic_responded: 0,
            international_agree: 0,
            international_responded: 0,
            ip_version: 4,
            country_code: String::new(),
            country: String::new(),
            city: String::new(),
            region: String::new(),
            asn: String::new(),
            org: String::new(),
            isp: String::new(),
            ip_type: "unknown".into(),
            is_proxy: None,
            is_vpn: None,
            is_tor: None,
            is_hosting: None,
            is_mobile: None,
            timezone: String::new(),
            flag_emoji: String::new(),
            blacklist_hits: Vec::new(),
            blacklist_policy: Vec::new(),
            blacklist_checked: 0,
            scores: Scores::default(),
            composite: 0,
            checks: Vec::new(),
            sources: Vec::new(),
            conflicts: Vec::new(),
            fetched_at: chrono::Utc::now().timestamp_millis(),
            took_ms: 0,
        }
    }
}

/// What the UI receives on every update. `changed` lets the card skip re-render
/// work when nothing meaningful moved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Update {
    pub snapshot: Snapshot,
    /// True when the egress IP itself changed since the previous snapshot.
    pub ip_changed: bool,
    /// True when risk crossed a colour band since the previous snapshot.
    pub risk_band_changed: bool,
    /// Set when we are showing a cached value because refresh failed.
    pub stale: bool,
    pub error: Option<String>,
}

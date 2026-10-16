//! Scoring engine.
//!
//! Design note: we deliberately do NOT average sources together. A datacenter
//! IP that one provider calls "clean" and another calls "fraud score 90" is not
//! a 45 — it is a conflict, and the honest answer is a lower confidence plus a
//! visible flag. Averaging is how naive checkers end up confidently wrong.

use crate::types::{Check, Conflict, Scores, SourceStatus};

/// Normalised inputs the scorer works from, gathered by the aggregator.
#[derive(Debug, Default, Clone)]
pub struct Signals {
    /// residential | mobile | business | hosting | unknown
    pub ip_type: String,
    pub is_proxy: Option<bool>,
    pub is_vpn: Option<bool>,
    pub is_tor: Option<bool>,
    pub is_hosting: Option<bool>,
    pub is_mobile: Option<bool>,

    /// AbuseIPDB confidence 0..=100 (higher = worse).
    pub abuse_confidence: Option<f32>,
    /// Scamalytics fraud score 0..=100 (higher = worse).
    pub scamalytics: Option<f32>,
    /// IPQS fraud score 0..=100 (higher = worse).
    pub ipqs: Option<f32>,
    /// Fraction of queried blacklists that hit, 0..=1.
    pub blacklist_ratio: Option<f32>,
    pub blacklist_hits: u32,

    /// How many independent egress endpoints agreed on the same IP.
    pub egress_agree: u32,
    pub egress_total: u32,

    /// Environment checks that came back clean vs total testable.
    pub checks_ok: u32,
    pub checks_testable: u32,

    /// Sources that returned usable data vs attempted.
    pub sources_ok: u32,
    pub sources_total: u32,
}

fn band(v: f32) -> u8 {
    v.round().clamp(0.0, 100.0) as u8
}

impl Signals {
    /// Purity: is this a "what it says on the tin" residential/mobile line?
    pub fn purity(&self) -> u8 {
        let mut s: f32 = match self.ip_type.as_str() {
            "residential" => 92.0,
            "mobile" => 88.0,
            "business" => 68.0,
            "hosting" => 34.0,
            _ => 60.0,
        };
        if self.is_tor == Some(true) {
            s -= 55.0;
        }
        if self.is_proxy == Some(true) {
            s -= 35.0;
        }
        if self.is_vpn == Some(true) {
            s -= 28.0;
        }
        if self.is_hosting == Some(true) && self.ip_type != "hosting" {
            s -= 22.0;
        }
        band(s)
    }

    /// Risk: trust the worst credible signal, discounted by how many sources
    /// agree. One lone alarmist source should not tank the score on its own.
    pub fn risk(&self) -> u8 {
        let mut vals: Vec<f32> = Vec::new();
        if let Some(v) = self.abuse_confidence {
            vals.push(v);
        }
        if let Some(v) = self.scamalytics {
            vals.push(v);
        }
        if let Some(v) = self.ipqs {
            vals.push(v);
        }
        if let Some(r) = self.blacklist_ratio {
            // A single blocklist hit is a strong negative, not a weak one.
            vals.push((r * 100.0).min(100.0) * 1.1);
        }
        if vals.is_empty() {
            return 0;
        }
        let worst = vals.iter().copied().fold(0.0f32, f32::max);
        let mean = vals.iter().sum::<f32>() / vals.len() as f32;
        // 70% worst-case + 30% mean: leans pessimistic without being hostage to
        // a single outlier provider.
        let mut s = worst * 0.7 + mean * 0.3;
        if self.is_tor == Some(true) {
            s = s.max(70.0);
        }
        if self.is_proxy == Some(true) || self.is_vpn == Some(true) {
            s = s.max(35.0);
        }
        band(s)
    }

    /// Confidence: how much of the intended evidence we actually got.
    ///
    /// Egress agreement is a *gate*, not a term. If our own endpoints cannot
    /// agree on what our address is, then every downstream fact is about an
    /// address we are not sure we have — so confidence must collapse even when
    /// plenty of sources answered. Modelling this as a weighted sum would let
    /// source availability outvote the disagreement, which is exactly backwards.
    pub fn confidence(&self) -> u8 {
        let egress = if self.egress_total > 0 {
            self.egress_agree as f32 / self.egress_total as f32
        } else {
            // No egress probe ran: we cannot be more than half sure about
            // anything, however many sources answered.
            0.5
        };
        let sources = if self.sources_total > 0 {
            self.sources_ok as f32 / self.sources_total as f32
        } else {
            0.0
        };
        band(100.0 * egress * sources)
    }

    /// Consistency: does the local environment cohere with the claimed IP?
    pub fn consistency(&self) -> u8 {
        if self.checks_testable == 0 {
            return 50;
        }
        band(self.checks_ok as f32 / self.checks_testable as f32 * 100.0)
    }

    pub fn scores(&self) -> Scores {
        Scores {
            purity: self.purity(),
            risk: self.risk(),
            confidence: self.confidence(),
            consistency: self.consistency(),
        }
    }

    /// Detect sources that disagree enough that averaging would be a lie.
    pub fn conflicts(&self) -> Vec<Conflict> {
        let mut out = Vec::new();
        let named: Vec<(&str, f32)> = [
            ("AbuseIPDB", self.abuse_confidence),
            ("Scamalytics", self.scamalytics),
            ("IPQS", self.ipqs),
        ]
        .into_iter()
        .filter_map(|(n, v)| v.map(|v| (n, v)))
        .collect();

        for i in 0..named.len() {
            for j in (i + 1)..named.len() {
                let (an, av) = named[i];
                let (bn, bv) = named[j];
                let delta = (av - bv).abs();
                if delta >= 40.0 {
                    out.push(Conflict {
                        field: "risk".into(),
                        a: format!("{an} {av:.0}"),
                        b: format!("{bn} {bv:.0}"),
                        delta,
                    });
                }
            }
        }
        out
    }
}

/// Recompute the consistency/confidence inputs from the check list, so the
/// scorer never has to know how checks are produced.
pub fn tally_checks(checks: &[Check]) -> (u32, u32) {
    let mut ok = 0;
    let mut testable = 0;
    for c in checks {
        match c.agrees {
            Some(true) => {
                ok += 1;
                testable += 1;
            }
            Some(false) => testable += 1,
            None => {}
        }
    }
    (ok, testable)
}

/// Count sources for the confidence denominator.
///
/// Only sources we actually *asked* count. A keyed source with no key
/// configured is skipped by our own choice, so folding it in as a failure would
/// mean "you didn't buy an API key" silently reads as "we couldn't verify your
/// IP" — a real bug that dragged confidence to 33 on a fully unanimous egress
/// result during development.
pub fn tally_sources(sources: &[SourceStatus]) -> (u32, u32) {
    let considered: Vec<&SourceStatus> = sources.iter().filter(|s| s.configured).collect();
    let ok = considered.iter().filter(|s| s.ok).count() as u32;
    (ok, considered.len() as u32)
}

/// Colour band for the UI. Kept here so Rust and the frontend cannot drift.
pub fn risk_band(risk: u8) -> &'static str {
    match risk {
        0..=19 => "green",
        20..=39 => "blue",
        40..=59 => "yellow",
        60..=79 => "orange",
        _ => "red",
    }
}

pub fn quality_band(composite: u8) -> &'static str {
    match composite {
        80..=100 => "green",
        60..=79 => "blue",
        40..=59 => "yellow",
        20..=39 => "orange",
        _ => "red",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residential_clean_scores_high() {
        let s = Signals {
            ip_type: "residential".into(),
            is_proxy: Some(false),
            is_vpn: Some(false),
            is_tor: Some(false),
            is_hosting: Some(false),
            abuse_confidence: Some(0.0),
            blacklist_ratio: Some(0.0),
            egress_agree: 3,
            egress_total: 3,
            checks_ok: 4,
            checks_testable: 4,
            sources_ok: 3,
            sources_total: 3,
            ..Default::default()
        };
        let sc = s.scores();
        assert!(sc.purity >= 90, "purity {}", sc.purity);
        assert!(sc.risk <= 5, "risk {}", sc.risk);
        assert!(sc.composite() >= 85, "composite {}", sc.composite());
    }

    #[test]
    fn datacenter_tor_scores_low() {
        let s = Signals {
            ip_type: "hosting".into(),
            is_tor: Some(true),
            is_proxy: Some(true),
            is_vpn: Some(true),
            is_hosting: Some(true),
            abuse_confidence: Some(80.0),
            scamalytics: Some(75.0),
            blacklist_ratio: Some(0.3),
            egress_agree: 2,
            egress_total: 3,
            checks_ok: 1,
            checks_testable: 4,
            sources_ok: 2,
            sources_total: 3,
            ..Default::default()
        };
        let sc = s.scores();
        assert!(sc.purity <= 15, "purity {}", sc.purity);
        assert!(sc.risk >= 70, "risk {}", sc.risk);
        assert!(sc.composite() <= 45, "composite {}", sc.composite());
    }

    #[test]
    fn egress_disagreement_tanks_confidence() {
        let s = Signals {
            egress_agree: 1,
            egress_total: 3,
            sources_ok: 3,
            sources_total: 3,
            ..Default::default()
        };
        assert!(s.confidence() < 50, "confidence {}", s.confidence());
    }

    #[test]
    fn unanimous_egress_with_all_sources_ok_is_high_confidence() {
        let s = Signals {
            egress_agree: 5,
            egress_total: 5,
            sources_ok: 3,
            sources_total: 3,
            ..Default::default()
        };
        assert!(s.confidence() >= 95, "confidence {}", s.confidence());
    }

    #[test]
    fn unconfigured_sources_do_not_count_against_confidence() {
        use crate::types::Provenance;
        let mk = |ok: bool, configured: bool| SourceStatus {
            name: "x".into(),
            ok,
            note: String::new(),
            provenance: Provenance::KeyedSource,
            took_ms: 0,
            configured,
        };
        // Two sources ran and succeeded; three were never asked because no key
        // was set. Confidence must reflect the two, not the five.
        let sources = vec![
            mk(true, true),
            mk(true, true),
            mk(false, false),
            mk(false, false),
            mk(false, false),
        ];
        let (ok, total) = tally_sources(&sources);
        assert_eq!((ok, total), (2, 2));
    }

    #[test]
    fn configured_failures_still_count_against_confidence() {
        use crate::types::Provenance;
        let mk = |ok: bool, configured: bool| SourceStatus {
            name: "x".into(),
            ok,
            note: String::new(),
            provenance: Provenance::FreeSource,
            took_ms: 0,
            configured,
        };
        // A source that ran and failed is real missing evidence and must count.
        let sources = vec![mk(true, true), mk(false, true)];
        let (ok, total) = tally_sources(&sources);
        assert_eq!((ok, total), (1, 2));
    }

    #[test]
    fn conflicting_risk_sources_are_flagged_not_averaged() {
        let s = Signals {
            abuse_confidence: Some(5.0),
            scamalytics: Some(90.0),
            ..Default::default()
        };
        let c = s.conflicts();
        assert_eq!(c.len(), 1);
        assert!(c[0].delta >= 40.0);
    }

    #[test]
    fn no_risk_data_is_zero_not_unknown() {
        // Absence of evidence must not be reported as evidence of cleanliness
        // in the *confidence* score; risk itself defaults to 0 but confidence
        // drops via the source tally.
        let s = Signals::default();
        assert_eq!(s.risk(), 0);
        assert!(s.confidence() < 50);
    }
}

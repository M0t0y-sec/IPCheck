//! Third-party intelligence sources.
//!
//! Each source is an independent adapter returning a *partial* profile. The
//! aggregator merges them and records which fields came from where, so the UI
//! can show provenance and the scorer can drop a source that starts lying.
//!
//! Contract every source follows: fail soft. A source that times out, rate
//! limits, or returns a shape we do not recognise must return `ok = false`
//! with a note, never an error that aborts the refresh. The card is a
//! background utility; one vendor being down is not a reason to show nothing.

pub mod dnsbl;
pub mod ipapi;
pub mod ipwhois;
pub mod risk;

use crate::types::{Provenance, SourceStatus};
use std::time::Instant;

/// Timing helper so every source reports how long it took, consistently.
pub struct Timed {
    name: String,
    provenance: Provenance,
    start: Instant,
}

impl Timed {
    pub fn new(name: &str, provenance: Provenance) -> Self {
        Self {
            name: name.to_string(),
            provenance,
            start: Instant::now(),
        }
    }

    pub fn ok(self, note: impl Into<String>) -> SourceStatus {
        SourceStatus {
            name: self.name,
            ok: true,
            note: note.into(),
            provenance: self.provenance,
            took_ms: self.start.elapsed().as_millis() as u64,
            configured: true,
        }
    }

    /// The source ran and failed. Counts against confidence.
    pub fn fail(self, note: impl Into<String>) -> SourceStatus {
        SourceStatus {
            name: self.name,
            ok: false,
            note: note.into(),
            provenance: self.provenance,
            took_ms: self.start.elapsed().as_millis() as u64,
            configured: true,
        }
    }

    /// The source was never asked, because we were not configured to ask.
    /// Shown in the UI, but excluded from the confidence denominator.
    pub fn unconfigured(self, note: impl Into<String>) -> SourceStatus {
        SourceStatus {
            name: self.name,
            ok: false,
            note: note.into(),
            provenance: self.provenance,
            took_ms: self.start.elapsed().as_millis() as u64,
            configured: false,
        }
    }
}

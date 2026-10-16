//! Layered TTL cache and per-source rate limiting.
//!
//! Two problems this solves, both caused by the same reality — free tiers are
//! small:
//!
//! 1. **Repeated queries.** The card refreshes periodically, but IP reputation
//!    does not change on that cadence. Basic geolocation is cached for minutes,
//!    blocklist answers for longer, and an unchanged egress IP reuses everything
//!    it can.
//!
//! 2. **Bursts.** A refresh fans out to six or more endpoints at once. Without a
//!    limiter, a user who restarts the app several times burns a day's free
//!    quota in a minute.
//!
//! Deliberately in-memory: persisting reputation data to disk would leave a
//! record of which addresses the user looked up, which is itself something this
//! category of tool should not create.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Time-to-live per source class. Chosen so that a normal 5-minute refresh
/// cycle hits the network roughly once per class per cycle, not six times.
#[derive(Debug, Clone, Copy)]
pub struct Ttl {
    pub basic: Duration,
    pub risk: Duration,
    pub blacklist: Duration,
}

impl Default for Ttl {
    fn default() -> Self {
        Self {
            basic: Duration::from_secs(300),
            risk: Duration::from_secs(1800),
            blacklist: Duration::from_secs(3600),
        }
    }
}

struct Entry<T> {
    value: T,
    stored: Instant,
}

/// A tiny TTL map. Not a general-purpose cache; no eviction policy beyond the
/// key set being small (one entry per source per IP we have looked at).
pub struct TtlCache<T> {
    ttl: Duration,
    map: Mutex<HashMap<String, Entry<T>>>,
    /// Cache is dropped wholesale above this many keys, which in practice only
    /// happens if the user is switching exits rapidly.
    max_keys: usize,
}

impl<T: Clone> TtlCache<T> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            map: Mutex::new(HashMap::new()),
            max_keys: 64,
        }
    }

    pub async fn get(&self, key: &str) -> Option<T> {
        let map = self.map.lock().await;
        let e = map.get(key)?;
        if e.stored.elapsed() < self.ttl {
            Some(e.value.clone())
        } else {
            None
        }
    }

    pub async fn put(&self, key: impl Into<String>, value: T) {
        let mut map = self.map.lock().await;
        if map.len() >= self.max_keys {
            map.clear();
        }
        map.insert(
            key.into(),
            Entry {
                value,
                stored: Instant::now(),
            },
        );
    }

    /// Drop everything. Called when the egress IP changes, because a cached
    /// reputation for the previous address is worse than no cache at all.
    pub async fn clear(&self) {
        self.map.lock().await.clear();
    }
}

/// Token bucket, one per source.
pub struct RateLimiter {
    capacity: f64,
    tokens: Mutex<f64>,
    refill_per_sec: f64,
    last: Mutex<Instant>,
}

impl RateLimiter {
    /// `capacity` = largest burst allowed. `per_minute` = sustained rate.
    pub fn new(capacity: u32, per_minute: u32) -> Self {
        Self {
            capacity: capacity as f64,
            tokens: Mutex::new(capacity as f64),
            refill_per_sec: per_minute as f64 / 60.0,
            last: Mutex::new(Instant::now()),
        }
    }

    /// Non-blocking acquire: returns false when the caller should skip this
    /// source for now rather than queue behind it. Skipping is correct here —
    /// the refresh has a deadline and a stale-but-present source beats a late one.
    pub async fn try_acquire(&self) -> bool {
        let mut last = self.last.lock().await;
        let mut tokens = self.tokens.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *last = now;
        *tokens = (*tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// All limiters, sized to the documented free tiers of each source.
pub struct Limiters {
    pub ipapi: RateLimiter,
    pub ipwhois: RateLimiter,
    pub dnsbl: RateLimiter,
    pub abuseipdb: RateLimiter,
    pub scamalytics: RateLimiter,
    pub ipqs: RateLimiter,
}

impl Default for Limiters {
    fn default() -> Self {
        Self {
            // ip-api free tier: 45/min. Burst of 5 is plenty for one refresh.
            ipapi: RateLimiter::new(5, 40),
            ipwhois: RateLimiter::new(5, 60),
            dnsbl: RateLimiter::new(8, 60),
            // AbuseIPDB free tier: 1000/day ≈ 0.7/min sustained.
            abuseipdb: RateLimiter::new(4, 1),
            scamalytics: RateLimiter::new(2, 5),
            ipqs: RateLimiter::new(2, 5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_returns_values_within_ttl() {
        let c: TtlCache<u32> = TtlCache::new(Duration::from_secs(60));
        c.put("a", 1).await;
        assert_eq!(c.get("a").await, Some(1));
        assert_eq!(c.get("missing").await, None);
    }

    #[tokio::test]
    async fn cache_expires_entries() {
        let c: TtlCache<u32> = TtlCache::new(Duration::from_millis(1));
        c.put("a", 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(c.get("a").await, None);
    }

    #[tokio::test]
    async fn clear_drops_everything() {
        let c: TtlCache<u32> = TtlCache::new(Duration::from_secs(60));
        c.put("a", 1).await;
        c.clear().await;
        assert_eq!(c.get("a").await, None);
    }

    #[tokio::test]
    async fn limiter_allows_burst_then_refuses() {
        let l = RateLimiter::new(2, 60);
        assert!(l.try_acquire().await);
        assert!(l.try_acquire().await);
        // Burst exhausted; refill is 1/sec so an immediate third must fail.
        assert!(!l.try_acquire().await);
    }

    #[tokio::test]
    async fn limiter_refills_over_time() {
        let l = RateLimiter::new(1, 600); // 10/sec refill
        assert!(l.try_acquire().await);
        assert!(!l.try_acquire().await);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(l.try_acquire().await);
    }

    #[tokio::test]
    async fn cache_clears_when_oversized() {
        let c: TtlCache<u32> = TtlCache::new(Duration::from_secs(60));
        for i in 0..70 {
            c.put(format!("k{i}"), i).await;
        }
        // The first key should have been evicted by the wholesale clear.
        assert_eq!(c.get("k0").await, None);
        assert_eq!(c.get("k69").await, Some(69));
    }
}

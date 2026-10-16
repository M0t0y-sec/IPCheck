//! Shared HTTP client construction. One builder so timeouts and the UA string
//! cannot drift between sources.

use std::time::Duration;

pub const UA: &str = concat!("IPCheck/", env!("CARGO_PKG_VERSION"));

/// Short timeout: the card is a background utility, and a slow source must not
/// stall the whole refresh. Sources that miss the window degrade, they don't
/// block.
pub fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(5))
        .build()?)
}

/// Client used for the multi-endpoint egress agreement test. Shorter timeout
/// still — we want N endpoints answering quickly, and a straggler is more
/// informative as a failure than as a late success.
pub fn probe_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(6))
        .connect_timeout(Duration::from_secs(4))
        .build()?)
}

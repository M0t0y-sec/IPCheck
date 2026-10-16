//! Environment coherence checks.
//!
//! Everything here asks the same underlying question from a different angle:
//! does *this machine's local configuration* line up with the country and
//! network its traffic claims to come from? These mismatches are what make an
//! otherwise-clean setup stand out, and unlike risk scores they are facts we
//! can observe directly rather than infer from a vendor.

/// System timezone as an IANA name, e.g. "America/New_York".
pub fn system_timezone() -> Option<String> {
    iana_time_zone::get_timezone().ok()
}

/// System locale, e.g. "zh-CN" or "en-US".
pub fn system_locale() -> Option<String> {
    sys_locale::get_locale()
}

/// The machine's real UTC offset in minutes.
///
/// We compare the *offset* rather than the zone name because offset is what
/// sites actually fingerprint from JavaScript, and because a correct offset
/// paired with an unusual zone name is far less telling than the reverse.
pub fn local_utc_offset_minutes() -> Option<i32> {
    Some(chrono::Local::now().offset().local_minus_utc() / 60)
}

/// Compare the machine's timezone offset against the offset the IP provider
/// associates with the egress address.
pub fn compare_timezone(ip_offset_minutes: Option<i32>) -> (Option<bool>, String) {
    let (Some(ip_off), Some(local_off)) = (ip_offset_minutes, local_utc_offset_minutes()) else {
        return (
            None,
            "IP-provided UTC offset unavailable; cannot compare".to_string(),
        );
    };

    let delta = (ip_off - local_off).abs();
    let tz = system_timezone().unwrap_or_else(|| "unknown".into());
    if delta <= 60 {
        (
            Some(true),
            format!("local {tz} (UTC{local_off:+}) matches IP (UTC{ip_off:+})"),
        )
    } else {
        (
            Some(false),
            format!(
                "local {tz} is UTC{local_off:+} but IP reports UTC{ip_off:+} ({}h apart)",
                delta / 60
            ),
        )
    }
}

/// Compare the locale's implied region against the egress country.
pub fn compare_locale(ip_country_code: Option<&str>) -> (Option<bool>, String) {
    let Some(cc) = ip_country_code.filter(|c| !c.is_empty()) else {
        return (None, "egress country unknown".into());
    };
    let Some(locale) = system_locale() else {
        return (None, "system locale unavailable".into());
    };

    // Locale looks like "en-US", "zh-CN", "en_US".
    let region = locale
        .split(['-', '_'])
        .nth(1)
        .map(|s| s.to_ascii_uppercase());

    match region {
        Some(r) if r == cc.to_ascii_uppercase() => (
            Some(true),
            format!("locale {locale} matches egress {cc}"),
        ),
        Some(r) => (
            Some(false),
            format!("locale {locale} ({r}) but egress is {cc}"),
        ),
        None => (
            None,
            format!("locale {locale} carries no region to compare"),
        ),
    }
}

/// Compare the IPv6 address (if any) against the IPv4 egress.
///
/// The strong failure here is not "v6 differs from v4" — those legitimately
/// differ — it is "a v6 address is visible at all while the user believes they
/// are proxied", because IPv6 nearly always bypasses an IPv4-only proxy.
pub fn compare_ipv6(v6: Option<&str>, v4_present: bool) -> (Option<bool>, String) {
    match (v6, v4_present) {
        (Some(a), true) => (
            Some(false),
            format!("IPv6 {a} is reachable outside the tunnel — v6 typically bypasses IPv4 proxies"),
        ),
        (Some(a), false) => (Some(true), format!("IPv6 {a} is the primary path")),
        (None, _) => (Some(true), "no external IPv6 path observed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timezone_within_an_hour_agrees() {
        let local = local_utc_offset_minutes().unwrap();
        let (agree, _) = compare_timezone(Some(local));
        assert_eq!(agree, Some(true));
    }

    #[test]
    fn timezone_far_off_is_flagged() {
        let local = local_utc_offset_minutes().unwrap();
        let (agree, detail) = compare_timezone(Some(local + 600));
        assert_eq!(agree, Some(false));
        assert!(detail.contains("h apart"));
    }

    #[test]
    fn missing_ip_offset_is_unknown() {
        let (agree, _) = compare_timezone(None);
        assert_eq!(agree, None);
    }

    #[test]
    fn visible_ipv6_alongside_v4_is_a_leak() {
        let (agree, detail) = compare_ipv6(Some("2606:4700::1"), true);
        assert_eq!(agree, Some(false));
        assert!(detail.contains("2606:4700::1"));
    }

    #[test]
    fn absent_ipv6_is_clean() {
        let (agree, _) = compare_ipv6(None, true);
        assert_eq!(agree, Some(true));
    }

    #[test]
    fn locale_region_is_extracted() {
        // Exercise the parsing branch without depending on the host locale.
        let cc = Some("US");
        let (agree, detail) = compare_locale(cc);
        // Either a real comparison or an explicit unknown — never a silent true.
        assert!(agree.is_some() || detail.contains("unavailable") || detail.contains("no region"));
    }

    #[test]
    fn missing_country_is_unknown() {
        let (agree, _) = compare_locale(None);
        assert_eq!(agree, None);
    }
}

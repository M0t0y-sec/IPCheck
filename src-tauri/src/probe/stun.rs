//! Hand-rolled STUN Binding request over UDP.
//!
//! Why this exists: HTTPS-based egress checks only tell you where TCP/443 goes.
//! A proxy configured for web traffic frequently leaves UDP entirely unproxied,
//! so WebRTC, QUIC and games still talk directly from the real address. STUN is
//! the cheapest way to observe the NAT-mapped address on the UDP path, and
//! comparing it against the HTTPS egress answer is one of the sharpest leak
//! signals available without extra privileges.
//!
//! Implemented directly rather than pulled from a crate because a Binding
//! request is ~20 bytes of header plus a 12-byte transaction ID, and RFC 5389
//! §15.2 is short. Fewer dependencies in a tool that handles network identity.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Well-known public STUN servers. Mixed operators so one outage doesn't
/// silently disable the leak check.
pub const SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:443",
];

#[derive(Debug, Clone)]
pub struct StunResult {
    /// The reflexive (public) address as the STUN server saw it.
    pub mapped: Option<String>,
    pub server: String,
    pub error: Option<String>,
}

/// Build a 20-byte Binding Request. Transaction ID is derived from the clock;
/// it only needs to be unique enough to match the reply, not unpredictable,
/// since we are not defending against off-path spoofing here.
fn build_request() -> ([u8; 20], [u8; 12]) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut txid = [0u8; 12];
    txid[..8].copy_from_slice(&nanos.to_le_bytes()[..8]);
    // Mix in the process id so two refreshes in the same nanosecond differ.
    txid[8..12].copy_from_slice(&std::process::id().to_le_bytes());

    let mut buf = [0u8; 20];
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // no attributes
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(&txid);
    (buf, txid)
}

/// Parse the attributes of a Binding Success response and return the mapped
/// address. Prefers XOR-MAPPED-ADDRESS (RFC 5389) over the legacy
/// MAPPED-ADDRESS (RFC 3489).
fn parse_response(buf: &[u8], txid: &[u8; 12]) -> Option<String> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_SUCCESS {
        return None;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    // Reject replies to a different transaction.
    if &buf[8..20] != txid {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());

    let mut legacy: Option<String> = None;
    let mut pos = 20;
    while pos + 4 <= end {
        let atype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let alen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let vstart = pos + 4;
        let vend = vstart + alen;
        if vend > end {
            break;
        }
        let val = &buf[vstart..vend];

        if atype == ATTR_XOR_MAPPED_ADDRESS {
            if let Some(ip) = decode_address(val, true, txid) {
                return Some(ip);
            }
        } else if atype == ATTR_MAPPED_ADDRESS {
            legacy = decode_address(val, false, txid);
        }
        // Attributes are 4-byte aligned.
        pos = vend + ((4 - (alen % 4)) % 4);
    }
    legacy
}

/// Decode a MAPPED-ADDRESS style value: 1 byte reserved, 1 byte family,
/// 2 bytes port, then 4 (IPv4) or 16 (IPv6) bytes of address — XORed with the
/// magic cookie (and transaction ID, for IPv6) when `xor` is set.
fn decode_address(val: &[u8], xor: bool, txid: &[u8; 12]) -> Option<String> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    match family {
        0x01 => {
            if val.len() < 8 {
                return None;
            }
            let mut octets = [val[4], val[5], val[6], val[7]];
            if xor {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    octets[i] ^= cookie[i];
                }
            }
            Some(std::net::Ipv4Addr::from(octets).to_string())
        }
        0x02 => {
            if val.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&val[4..20]);
            if xor {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    octets[i] ^= cookie[i];
                }
                for i in 0..12 {
                    octets[4 + i] ^= txid[i];
                }
            }
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

/// Send a Binding request to one server and read the reply.
pub async fn query_one(server: &str, per_try: Duration) -> StunResult {
    let mut out = StunResult {
        mapped: None,
        server: server.to_string(),
        error: None,
    };

    let addr: SocketAddr = match tokio::net::lookup_host(server).await {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => {
                out.error = Some("no address".into());
                return out;
            }
        },
        Err(e) => {
            out.error = Some(format!("resolve: {e}"));
            return out;
        }
    };

    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            out.error = Some(format!("bind: {e}"));
            return out;
        }
    };
    if let Err(e) = sock.connect(addr).await {
        out.error = Some(format!("connect: {e}"));
        return out;
    }

    let (req, txid) = build_request();
    if let Err(e) = sock.send(&req).await {
        out.error = Some(format!("send: {e}"));
        return out;
    }

    let mut buf = [0u8; 512];
    match tokio::time::timeout(per_try, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => match parse_response(&buf[..n], &txid) {
            Some(ip) => out.mapped = Some(ip),
            None => out.error = Some("unparseable reply".into()),
        },
        Ok(Err(e)) => out.error = Some(format!("recv: {e}")),
        Err(_) => out.error = Some("timeout".into()),
    }
    out
}

/// Try each server in turn; first answer wins.
pub async fn query_any() -> StunResult {
    let per_try = Duration::from_millis(2500);
    let mut last = StunResult {
        mapped: None,
        server: String::new(),
        error: Some("no server attempted".into()),
    };
    for s in SERVERS {
        let r = query_one(s, per_try).await;
        if r.mapped.is_some() {
            return r;
        }
        last = r;
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_correct_header() {
        let (req, txid) = build_request();
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &txid);
    }

    /// Build an attribute: 2-byte type, 2-byte length, the value, then zero
    /// padding to the next 4-byte boundary (RFC 5389 §15).
    fn attribute(atype: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + value.len() + 3);
        out.extend_from_slice(&atype.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    /// An XOR-MAPPED-ADDRESS value for an IPv4 address: 0, family, port, addr.
    fn xor_mapped_value(ip: [u8; 4]) -> Vec<u8> {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let mut xored = ip;
        for i in 0..4 {
            xored[i] ^= cookie[i];
        }
        let mut v = vec![0u8, 0x01, 0x1f, 0x90]; // reserved, family=IPv4, port
        v.extend_from_slice(&xored);
        v
    }

    fn response(txid: [u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut resp = vec![0u8; 20];
        resp[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        resp[2..4].copy_from_slice(&(attrs.len() as u16).to_be_bytes());
        resp[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp[8..20].copy_from_slice(&txid);
        resp.extend_from_slice(attrs);
        resp
    }

    #[test]
    fn decodes_xor_mapped_ipv4() {
        let txid = [7u8; 12];
        let attrs = attribute(ATTR_XOR_MAPPED_ADDRESS, &xor_mapped_value([1, 2, 3, 4]));
        let resp = response(txid, &attrs);
        assert_eq!(parse_response(&resp, &txid), Some("1.2.3.4".into()));
    }

    #[test]
    fn rejects_reply_with_wrong_transaction_id() {
        let txid = [7u8; 12];
        let mut resp = vec![0u8; 20];
        resp[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        resp[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp[8..20].copy_from_slice(&[9u8; 12]); // different
        assert_eq!(parse_response(&resp, &txid), None);
    }

    #[test]
    fn rejects_non_success_message() {
        let txid = [1u8; 12];
        let mut resp = vec![0u8; 20];
        resp[0..2].copy_from_slice(&0x0111u16.to_be_bytes()); // error response
        resp[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp[8..20].copy_from_slice(&txid);
        assert_eq!(parse_response(&resp, &txid), None);
    }

    #[test]
    fn decodes_legacy_mapped_address() {
        // RFC 3489 style: the address is NOT xor'd.
        let txid = [0u8; 12];
        let mut value = vec![0u8, 0x01, 0x1f, 0x90]; // reserved, IPv4, port
        value.extend_from_slice(&[8, 8, 8, 8]);
        let attrs = attribute(ATTR_MAPPED_ADDRESS, &value);
        let resp = response(txid, &attrs);
        assert_eq!(parse_response(&resp, &txid), Some("8.8.8.8".into()));
    }

    #[test]
    fn xor_attribute_wins_over_legacy_when_both_present() {
        // Real servers sometimes include both; RFC 5389 says prefer XOR.
        let txid = [3u8; 12];
        let mut value = vec![0u8, 0x01, 0x1f, 0x90];
        value.extend_from_slice(&[9, 9, 9, 9]);
        let mut attrs = attribute(ATTR_MAPPED_ADDRESS, &value);
        attrs.extend_from_slice(&attribute(
            ATTR_XOR_MAPPED_ADDRESS,
            &xor_mapped_value([1, 2, 3, 4]),
        ));
        let resp = response(txid, &attrs);
        assert_eq!(parse_response(&resp, &txid), Some("1.2.3.4".into()));
    }

    #[test]
    fn skips_unknown_attributes_and_still_finds_the_address() {
        // A real reply carries SOFTWARE, FINGERPRINT, etc. before/after the
        // mapped address; the parser must walk past them.
        let txid = [5u8; 12];
        let mut attrs = attribute(0x8022, b"test-server"); // SOFTWARE
        attrs.extend_from_slice(&attribute(
            ATTR_XOR_MAPPED_ADDRESS,
            &xor_mapped_value([5, 6, 7, 8]),
        ));
        attrs.extend_from_slice(&attribute(0x8028, &[0xde, 0xad, 0xbe, 0xef]));
        let resp = response(txid, &attrs);
        assert_eq!(parse_response(&resp, &txid), Some("5.6.7.8".into()));
    }
}

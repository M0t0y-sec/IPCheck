//! Active probing from this machine. Nothing here trusts a third party for the
//! question "what is my IP" — that is answered by asking several independent
//! endpoints and watching for disagreement, which is the signal that something
//! is routing inconsistently.

pub mod dns_leak;
pub mod egress;
pub mod env_check;
pub mod stun;

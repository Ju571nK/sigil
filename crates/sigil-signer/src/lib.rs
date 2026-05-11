//! Operator CLI for signing Sigil policy bundles.
//!
//! Wraps a YAML policy in a `SignedPolicyResponse` (Plan A `signed_envelope.rs`)
//! using a private ed25519 key. The host-side agent's `verify_envelope`
//! 5-check chain accepts the result as long as the matching pubkey is in
//! its `policy-signing-pubkeys.pem` keystore.

pub mod cli;
pub mod inspect;
pub mod keygen;
pub mod sign;
pub mod verify;

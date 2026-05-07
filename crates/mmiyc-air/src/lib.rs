//! Algebraic Intermediate Representations for Match-Me-If-You-Can.
//!
//! Each module here is one predicate the registration server may want
//! to enforce.  The predicates are the operationally-useful ones we
//! identify in the paper:
//!
//! * [`age`]      — range proof: prove the user's age (derived from a
//!                  hidden DOB) lies in a public range, e.g. \[18, 120\].
//! * [`country`]  — set membership: prove the user's country code is
//!                  a member of a public set (e.g. EU member states),
//!                  via Merkle inclusion.
//! * [`postcode`] — set membership over UK outward-code prefixes.
//! * [`email`]    — set membership over allowed mail providers.
//! * [`income`]   — range proof on declared income, by bracket.
//!
//! Each module exposes a `Public<T>` (the public inputs the verifier
//! sees), a `Witness<T>` (the secret values the prover knows), and
//! `prove` / `verify` functions that wrap the underlying STARK-STIR
//! machinery from `deep_ali`.
//!
//! The MVP for the project includes [`age`] and [`country`] only;
//! the remaining modules are currently `pub mod stub;` placeholders
//! to lock in the public surface.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

pub mod age;
pub mod country;
pub mod postcode;
pub mod email;
pub mod income;

/// Errors common to all AIRs.
///
/// Per-AIR specific failure modes are reported via this enum so the
/// HTTP layer can distinguish "user gave a bad witness" from "the
/// proof failed STARK verification" from "the public inputs do not
/// match the registered policy" cleanly.
#[derive(Debug, thiserror::Error)]
pub enum AirError {
    /// The witness violates the AIR's constraints (e.g. the claimed
    /// age is outside the public range).  Happens before any STARK
    /// machinery runs.
    #[error("witness rejected by predicate: {0}")]
    Witness(String),

    /// The proof bytes did not deserialise.
    #[error("proof deserialisation failed: {0}")]
    Deserialise(String),

    /// The STARK proof failed verification.
    #[error("STARK verification failed: {0}")]
    Verify(String),

    /// The public inputs supplied with the proof do not match the
    /// policy the verifier was instantiated with.
    #[error("public inputs did not match policy: {0}")]
    Policy(String),
}

/// A small marker trait every AIR module's public inputs implement.
///
/// Used by the server to obtain a content-addressed identifier for a
/// concrete policy instance (e.g. the SHA3 of the public inputs of
/// the "age ≥ 18" AIR), useful both for caching verifier state and
/// for stable references in audit logs.
pub trait PolicyId {
    /// Stable 32-byte identifier for this public-input set.
    fn policy_id(&self) -> [u8; 32];
}

#[cfg(test)]
mod tests {
    /// Sanity test that re-exports compile.
    #[test]
    fn module_paths_resolve() {
        let _ = super::age::Public::default;
        let _ = super::country::Public::default;
    }
}

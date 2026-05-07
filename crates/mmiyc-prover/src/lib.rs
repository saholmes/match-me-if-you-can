//! Proof-generation wrapper for Match-Me-If-You-Can.
//!
//! Top-level entry points that take an attribute witness + the
//! relevant public input and return serialised STARK proof bytes
//! ready for storage by the server.  Currently a thin shim around
//! the per-attribute `prove` functions in [`mmiyc_air`]; the
//! abstraction layer exists so that as more attributes land, the
//! server only depends on this crate's stable API rather than
//! reaching directly into individual AIR modules.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

use mmiyc_air::AirError;

/// Prove an age-range claim.
pub fn prove_age(
    public: &mmiyc_air::age::Public,
    witness: &mmiyc_air::age::Witness,
) -> Result<Vec<u8>, AirError> {
    witness.prove(public)
}

/// Prove a country set-membership claim.
pub fn prove_country(
    public: &mmiyc_air::country::Public,
    witness: &mmiyc_air::country::Witness,
    set_leaves: &[[u8; 32]],
) -> Result<Vec<u8>, AirError> {
    witness.prove(public, set_leaves)
}

/// Convenience: prove the full registration bundle in one call.
///
/// Returns one proof per attribute, in attribute-name order.  The
/// caller is responsible for serialising the bundle alongside the
/// matching public-input record.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    /// Optional age-range proof.
    pub age: Option<Vec<u8>>,
    /// Optional country-set-membership proof.
    pub country: Option<Vec<u8>>,
}

//! Native verifier for Match-Me-If-You-Can proofs.
//!
//! Wraps the per-AIR `verify` functions behind a single entry
//! point keyed by [`mmiyc_air::PolicyId`], so the server can
//! dispatch incoming `(public_inputs, proof)` pairs without
//! knowing which AIR they belong to until inspection time.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

use mmiyc_air::AirError;

/// Verify an age-range proof.
pub fn verify_age(
    public: &mmiyc_air::age::Public,
    proof: &[u8],
) -> Result<(), AirError> {
    mmiyc_air::age::verify(public, proof)
}

/// Verify a country set-membership proof.
pub fn verify_country(
    public: &mmiyc_air::country::Public,
    proof: &[u8],
) -> Result<(), AirError> {
    mmiyc_air::country::verify(public, proof)
}

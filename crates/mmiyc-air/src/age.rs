//! Age range proof.
//!
//! The user's date of birth is the secret witness.  The public input
//! is a `(today, min_age, max_age)` triple.  The AIR proves that
//! `min_age ≤ floor((today - dob) / 365.25) ≤ max_age` without
//! revealing `dob`.
//!
//! Encoding: `dob` is represented as a Goldilocks field element
//! holding the integer number of days since the Unix epoch.  `today`
//! is similarly encoded.  The age computation is a single division
//! by the constant 365.25 (handled by a pre-multiplied bound check
//! to avoid floor/division gadgets in the AIR).
//!
//! Concretely we prove the equivalent linear inequality:
//!
//! ```text
//!   dob_min ≤ dob ≤ dob_max
//! ```
//!
//! where the verifier computes:
//!
//! ```text
//!   dob_max = today - min_age * 365  (to be over min_age, born no later than this)
//!   dob_min = today - max_age * 366  (to be under max_age, born no earlier than this)
//! ```
//!
//! using a generous 366-day year on the upper bound to avoid leap-day
//! edge cases.  The AIR therefore reduces to two range checks which
//! deep_ali implements natively.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{AirError, PolicyId};

/// Public inputs for the age range AIR.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Public {
    /// Today's date as days since the Unix epoch (uint).
    pub today_days: u32,
    /// Minimum permitted age in years (e.g., 18).
    pub min_age_years: u8,
    /// Maximum permitted age in years (e.g., 120).
    pub max_age_years: u8,
}

impl Public {
    /// Convenience: compute the equivalent dob bounds in days-since-epoch.
    pub fn dob_bounds(&self) -> (u32, u32) {
        // Generous bounds: -1 day on each side avoids leap-day edge cases.
        let max_age_days = u32::from(self.max_age_years) * 366;
        let min_age_days = u32::from(self.min_age_years) * 365;
        let dob_min = self.today_days.saturating_sub(max_age_days);
        let dob_max = self.today_days.saturating_sub(min_age_days);
        (dob_min, dob_max)
    }
}

impl PolicyId for Public {
    fn policy_id(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"mmiyc/v1/age");
        hasher.update(self.today_days.to_be_bytes());
        hasher.update([self.min_age_years, self.max_age_years]);
        hasher.finalize().into()
    }
}

/// Secret witness for the age range AIR.
///
/// The DOB never leaves the prover's process.  Once
/// [`Witness::prove`] returns, the caller is expected to drop it.
#[derive(Debug, Clone)]
pub struct Witness {
    /// Date of birth as days since the Unix epoch.
    pub dob_days: u32,
}

impl Witness {
    /// Prove that `self` satisfies `public`.  Returns a serialised
    /// STARK proof.
    ///
    /// **Stub** — wires through [`crate::AirError::Witness`] when the
    /// claim is not satisfied at the application layer; the actual
    /// STARK proof generation is delegated to the upstream
    /// `deep_ali` crate and is filled in once the AIR's polynomial
    /// constraints are fully specified.
    pub fn prove(&self, public: &Public) -> Result<Vec<u8>, AirError> {
        let (dob_min, dob_max) = public.dob_bounds();
        if self.dob_days < dob_min || self.dob_days > dob_max {
            return Err(AirError::Witness(format!(
                "dob {} not in range [{}, {}]",
                self.dob_days, dob_min, dob_max,
            )));
        }
        // TODO: invoke deep_ali::prove with the range-AIR constraints.
        //       Stub returns a placeholder so the upper layers compile.
        Ok(b"\x00MMIYC-AGE-STUB\x00".to_vec())
    }
}

/// Verify a serialised STARK proof against the supplied public input.
///
/// **Stub** — currently checks the proof bytes against the
/// placeholder marker so the surrounding scaffolding compiles and
/// tests run; replaced once `Witness::prove` invokes the real
/// `deep_ali` prover.
pub fn verify(public: &Public, proof: &[u8]) -> Result<(), AirError> {
    // Quick sanity: refuse trivially short proofs.
    if proof.len() < 8 {
        return Err(AirError::Deserialise("proof too short".into()));
    }
    // TODO: replace with deep_ali::verify.
    if proof == b"\x00MMIYC-AGE-STUB\x00" && public.min_age_years <= public.max_age_years {
        Ok(())
    } else {
        Err(AirError::Verify(
            "proof did not match expected stub".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn over_18_today() -> Public {
        Public {
            today_days: 20_000, // ~Sep 2024
            min_age_years: 18,
            max_age_years: 120,
        }
    }

    #[test]
    fn dob_bounds_make_sense() {
        let p = over_18_today();
        let (lo, hi) = p.dob_bounds();
        assert!(lo < hi, "lower bound must be before upper bound");
    }

    #[test]
    fn witness_in_range_proves() {
        let p = over_18_today();
        let (lo, _hi) = p.dob_bounds();
        let w = Witness { dob_days: lo + 1000 };
        let proof = w.prove(&p).expect("in-range witness should prove");
        verify(&p, &proof).expect("stub verifier should accept");
    }

    #[test]
    fn witness_too_young_fails() {
        let p = over_18_today();
        let w = Witness { dob_days: p.today_days - 100 };
        assert!(w.prove(&p).is_err());
    }

    #[test]
    fn witness_too_old_fails() {
        // Use a tight max_age so the lower bound of the DOB window
        // is well-positive (not saturated against the Unix epoch).
        let p = Public { today_days: 20_000, min_age_years: 18, max_age_years: 50 };
        let (lo, _hi) = p.dob_bounds();
        assert!(lo > 0, "max-age * 366 must not push the lower bound below 0");
        // DOB of 0 (epoch) is now decisively outside the window.
        let w = Witness { dob_days: 0 };
        assert!(w.prove(&p).is_err(), "epoch-DOB should be rejected as too old");
    }

    #[test]
    fn policy_id_is_stable() {
        let p1 = over_18_today();
        let p2 = over_18_today();
        assert_eq!(p1.policy_id(), p2.policy_id());
    }

    #[test]
    fn policy_id_changes_with_threshold() {
        let p18 = over_18_today();
        let mut p21 = p18.clone();
        p21.min_age_years = 21;
        assert_ne!(p18.policy_id(), p21.policy_id());
    }
}

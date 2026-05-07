//! Income-bracket range proof.
//!
//! Mirrors the [`crate::age`] range-proof pattern: prove the user's
//! declared annual income lies in a public bracket
//! `[bracket_min, bracket_max]` (in minor currency units, e.g.
//! pence) without revealing the exact amount.  The brackets are
//! operator-defined (e.g. £0–25k, £25–50k, £50–100k, £100k+) and
//! selected at registration time; the policy is bound through
//! `public_inputs_hash` so a proof issued under one bracket does
//! not verify under another.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{AirError, PolicyId};

/// Public inputs for the income range AIR.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Public {
    /// Inclusive lower bound (currency minor units, e.g. pence).
    pub bracket_min: u64,
    /// Inclusive upper bound, or `u64::MAX` for the open-top bracket.
    pub bracket_max: u64,
    /// 3-letter ISO currency code.
    pub currency: [u8; 3],
}

impl Public {
    /// Convenience: a default GBP £25k–£1M bracket — wide enough for
    /// the demo's prefill and "minimum income" gates without being
    /// trivially open-ended.  Operators would replace this per
    /// deployment.
    pub fn default_demo_bracket() -> Self {
        Self {
            bracket_min: 2_500_000,    // £25,000.00 in pence
            bracket_max: 100_000_000,  // £1,000,000.00 in pence
            currency:    *b"GBP",
        }
    }
}

impl PolicyId for Public {
    fn policy_id(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"mmiyc/v1/income/policy");
        hasher.update(self.bracket_min.to_be_bytes());
        hasher.update(self.bracket_max.to_be_bytes());
        hasher.update(self.currency);
        hasher.finalize().into()
    }
}

/// Secret witness for the income range AIR.
///
/// The exact income figure never leaves the prover's process.
#[derive(Debug, Clone)]
pub struct Witness {
    /// Income in currency minor units (pence for GBP).
    pub income_pence: u64,
}

impl Witness {
    /// Application-layer policy check.  Returns `Err` when the
    /// witness lies outside the declared bracket so the prover can
    /// reject before burning STARK CPU on a bad input.
    pub fn check(&self, public: &Public) -> Result<(), AirError> {
        if public.bracket_min > public.bracket_max {
            return Err(AirError::Policy(
                "bracket_min > bracket_max".into(),
            ));
        }
        if self.income_pence < public.bracket_min
            || self.income_pence > public.bracket_max
        {
            return Err(AirError::Witness(format!(
                "income {} not in bracket [{}, {}]",
                self.income_pence, public.bracket_min, public.bracket_max,
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_bracket_passes_check() {
        let p = Public::default_demo_bracket();
        let w = Witness { income_pence: 4_500_000 }; // £45k
        w.check(&p).expect("in-bracket witness must pass");
    }

    #[test]
    fn below_bracket_fails() {
        let p = Public::default_demo_bracket();
        let w = Witness { income_pence: 1_000_000 }; // £10k
        assert!(w.check(&p).is_err());
    }

    #[test]
    fn above_bracket_fails() {
        let p = Public::default_demo_bracket();
        let w = Witness { income_pence: 200_000_000 }; // £2M
        assert!(w.check(&p).is_err());
    }

    #[test]
    fn policy_id_is_stable_and_bracket_sensitive() {
        let p1 = Public::default_demo_bracket();
        let p2 = Public::default_demo_bracket();
        assert_eq!(p1.policy_id(), p2.policy_id());
        let mut p3 = p1.clone();
        p3.bracket_min += 100;
        assert_ne!(p1.policy_id(), p3.policy_id());
    }
}

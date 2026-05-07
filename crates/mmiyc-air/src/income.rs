//! Income-bracket range proof — **stub**.
//!
//! Mirrors the [`crate::age`] range-proof pattern: prove the user's
//! declared annual income lies in a public bracket
//! `[bracket_min, bracket_max]` without revealing the exact amount.
//! The brackets are operator-defined (e.g. £0–25k, £25–50k,
//! £50–100k, £100k+) and selected at registration time.  Phase-2.

use serde::{Deserialize, Serialize};

use crate::PolicyId;

/// Public inputs — placeholder.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Public {
    /// Inclusive lower bound (currency units, e.g. pence).
    pub bracket_min: u64,
    /// Inclusive upper bound, or `u64::MAX` for the open-top bracket.
    pub bracket_max: u64,
    /// 3-letter ISO currency code.
    pub currency: [u8; 3],
}

impl PolicyId for Public {
    fn policy_id(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(b"mmiyc/v1/income/policy");
        hasher.update(self.bracket_min.to_be_bytes());
        hasher.update(self.bracket_max.to_be_bytes());
        hasher.update(self.currency);
        hasher.finalize().into()
    }
}

//! Postcode-prefix set membership proof — **stub**.
//!
//! Mirrors the [`crate::country`] pattern with a Merkle commitment
//! over the canonical UK outward-code first-two-character prefixes
//! (`SW`, `EH`, `M`, `B`, etc., normalised to a fixed-width form).
//! Phase-2 in the project plan.

use serde::{Deserialize, Serialize};

use crate::PolicyId;

/// Public inputs — placeholder.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Public {
    /// Future home of the Merkle root over permitted postcode prefixes.
    pub set_root: [u8; 32],
}

impl PolicyId for Public {
    fn policy_id(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(b"mmiyc/v1/postcode/policy");
        hasher.update(self.set_root);
        hasher.finalize().into()
    }
}

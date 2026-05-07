//! Email-domain set membership proof — **stub**.
//!
//! The witness is the user's email address; the AIR proves the
//! domain part lies in a public set (e.g. allow-list of mail
//! providers, or block-list of disposable-mail providers).  The
//! local part can be additionally hashed and stored separately if
//! the operator needs to support per-account login by email; see
//! the paper §[design] for the trade-off.  Phase-2.

use serde::{Deserialize, Serialize};

use crate::PolicyId;

/// Public inputs — placeholder.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Public {
    /// Merkle root of permitted (or disallowed) mail domains.
    pub set_root: [u8; 32],
    /// Whether the set is interpreted as allow-list (true) or block-list (false).
    pub is_allowlist: bool,
}

impl PolicyId for Public {
    fn policy_id(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(b"mmiyc/v1/email/policy");
        hasher.update(self.set_root);
        hasher.update([self.is_allowlist as u8]);
        hasher.finalize().into()
    }
}

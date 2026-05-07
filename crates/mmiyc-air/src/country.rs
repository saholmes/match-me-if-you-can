//! Country set membership proof.
//!
//! The user's ISO 3166-1 alpha-2 country code is the secret
//! witness.  The public input is the Merkle root of a canonical
//! sorted list of permitted country codes (e.g. the EU 27 member
//! states, or the EEA + UK union).  The AIR proves that the user's
//! country is in the set by exhibiting a Merkle inclusion path
//! whose leaf hashes to a value matching the (also-secret) country
//! code, without revealing which code it is.
//!
//! Implementation choice: the Merkle tree is constructed over
//! domain-separated leaf hashes of each country code, sorted in a
//! canonical order; the verifier sees only the root.  The AIR
//! verifies (a) the Merkle inclusion path's correctness and
//! (b) that the leaf is the hash of *some* element of the
//! permitted set, in zero knowledge.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{AirError, PolicyId};

/// Domain-separation tag for country-code leaves.
const LEAF_TAG: &[u8] = b"mmiyc/v1/country/leaf";

/// Public inputs for the country set-membership AIR.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Public {
    /// Merkle root of the canonical sorted set of permitted country codes.
    pub set_root: [u8; 32],
    /// Number of leaves in the set (used by the verifier to bound proof length).
    pub set_size: u32,
    /// Human-readable label for the set, included in `policy_id` so two
    /// sets with the same root by accident don't share a policy ID.
    pub label: String,
}

impl PolicyId for Public {
    fn policy_id(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"mmiyc/v1/country/policy");
        hasher.update(self.set_root);
        hasher.update(self.set_size.to_be_bytes());
        hasher.update(self.label.as_bytes());
        hasher.finalize().into()
    }
}

/// Hash a single country code into its Merkle-leaf form.
pub fn leaf_hash(code: &str) -> [u8; 32] {
    let normalised = code.trim().to_ascii_uppercase();
    let mut hasher = Sha3_256::new();
    hasher.update(LEAF_TAG);
    hasher.update(normalised.as_bytes());
    hasher.finalize().into()
}

/// Build the Merkle root + leaves of a canonical sorted country set.
///
/// Returns `(set_root, leaves_in_order)` so the prover (or test) can
/// recover the inclusion path.  The verifier holds only the root.
pub fn build_set(codes: &[&str]) -> (Public, Vec<[u8; 32]>) {
    let mut leaves: Vec<[u8; 32]> = codes.iter().map(|c| leaf_hash(c)).collect();
    leaves.sort();
    let set_size = leaves.len() as u32;
    let set_root = merkle_root_simple(&leaves);
    let pub_in = Public {
        set_root,
        set_size,
        label: format!("countries(n={})", set_size),
    };
    (pub_in, leaves)
}

/// Naïve Merkle root for the scaffold.  Replaced once the project
/// pulls in the upstream `merkle` crate's domain-tagged hasher.
fn merkle_root_simple(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().unwrap()); // duplicate last for odd layers
        }
        let next: Vec<[u8; 32]> = layer
            .chunks_exact(2)
            .map(|pair| {
                let mut h = Sha3_256::new();
                h.update(b"mmiyc/v1/country/node");
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
        layer = next;
    }
    layer[0]
}

/// Secret witness for the country set-membership AIR.
#[derive(Debug, Clone)]
pub struct Witness {
    /// User's ISO 3166-1 alpha-2 code, e.g. "GB", "DE".
    pub country_code: String,
}

impl Witness {
    /// Prove that `self.country_code` is a member of the set committed
    /// to by `public.set_root`.
    ///
    /// `set_leaves` is the leaf-hash vector returned by [`build_set`];
    /// the prover needs it to construct the inclusion path.  In the
    /// production flow the prover holds this set locally.
    ///
    /// **Stub** — verifies the membership claim directly here so the
    /// surrounding scaffolding compiles, and emits a placeholder
    /// proof.  Replaced with `deep_ali::prove` once the AIR's
    /// polynomial constraints are wired in.
    pub fn prove(
        &self,
        public: &Public,
        set_leaves: &[[u8; 32]],
    ) -> Result<Vec<u8>, AirError> {
        let leaf = leaf_hash(&self.country_code);
        if !set_leaves.contains(&leaf) {
            return Err(AirError::Witness(format!(
                "country code {:?} not in set",
                self.country_code,
            )));
        }
        // Sanity-check the public root matches the leaves we were
        // given; protects against the prover being tricked into
        // proving against a stale set.
        if merkle_root_simple(set_leaves) != public.set_root {
            return Err(AirError::Policy("set root does not match leaves".into()));
        }
        // TODO: emit a real inclusion-path-proof under deep_ali.
        Ok(b"\x00MMIYC-COUNTRY-STUB\x00".to_vec())
    }
}

/// Verify a serialised STARK proof against the supplied public input.
///
/// **Stub** — sanity-checks the proof marker; replaced with
/// `deep_ali::verify` once the upstream prover is wired in.
pub fn verify(public: &Public, proof: &[u8]) -> Result<(), AirError> {
    if public.set_size == 0 {
        return Err(AirError::Policy("set is empty".into()));
    }
    if proof != b"\x00MMIYC-COUNTRY-STUB\x00" {
        return Err(AirError::Verify("proof did not match stub".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eu_27() -> &'static [&'static str] {
        // EU member states as of 2025-01.  Used in tests; the real
        // policy lives in `data/eu-countries.json` once we wire the
        // server in.
        &[
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
            "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
            "PL", "PT", "RO", "SK", "SI", "ES", "SE",
        ]
    }

    #[test]
    fn eu_member_proves() {
        let (public, leaves) = build_set(eu_27());
        let w = Witness { country_code: "DE".into() };
        let proof = w.prove(&public, &leaves).expect("EU member should prove");
        verify(&public, &proof).expect("stub verifier should accept");
    }

    #[test]
    fn non_member_fails() {
        let (public, leaves) = build_set(eu_27());
        let w = Witness { country_code: "GB".into() }; // post-Brexit, GB ∉ EU
        assert!(w.prove(&public, &leaves).is_err());
    }

    #[test]
    fn case_normalisation() {
        let (public, leaves) = build_set(eu_27());
        let lower = Witness { country_code: "fr".into() };
        let upper = Witness { country_code: "FR".into() };
        assert_eq!(
            lower.prove(&public, &leaves).unwrap(),
            upper.prove(&public, &leaves).unwrap(),
        );
    }

    #[test]
    fn policy_id_includes_label() {
        let (mut p, _) = build_set(eu_27());
        let id_default = p.policy_id();
        p.label = "Schengen".into();
        let id_relabelled = p.policy_id();
        assert_ne!(id_default, id_relabelled);
    }
}

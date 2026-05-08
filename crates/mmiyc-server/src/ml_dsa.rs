//! Native ML-DSA-44 (FIPS 204) signature primitive.
//!
//! Wraps the RustCrypto [`ml-dsa`] crate to provide a uniform
//! `keygen / sign / verify` surface for the post-quantum
//! designated-verifier gate.  This is the *native reference*
//! implementation — the in-circuit AIR that proves
//! `ML-DSA.Verify(pk, m, σ) = 1` is a separate, multi-session
//! project tracked in `docs/ml_dsa_air_plan.md`.
//!
//! We pick parameter set **ML-DSA-44** (FIPS 204 §4 Table 1):
//! - NIST security category 2 (≈ 128-bit classical, "level 1" in
//!   the original NIST PQC bake-off naming),
//! - public key  1\,312 B, signing key  2\,560 B, signature  2\,420 B,
//! - q = 8\,380\,417, n = 256, k = 4, l = 4, η = 2, τ = 39, β = 78,
//!   γ_1 = 2^17, γ_2 = (q−1)/88, ω = 80.
//!
//! The corresponding STARK is itself NIST PQ category 3 (level 3,
//! ~192-bit classical) by the SHA3-512 + STIR calibration of
//! `deep_ali`.  We deliberately pin the *signature* to the smaller
//! parameter set: in the gate's threat model the STARK PoK supplies
//! the soundness, the ML-DSA signature only needs to be unforgeable
//! against an adversary that does not hold sk.  Level-1 ML-DSA gives
//! a comfortable margin and minimises the AIR's circuit footprint
//! (1\,312 B pk vs 1\,952 B for level-3).

use anyhow::{anyhow, Result};
use ml_dsa::{
    signature::{Keypair as _, SignatureEncoding as _, Signer, Verifier},
    KeyGen, MlDsa44, SigningKey,
};
// rand_core 0.10 (which ml-dsa pins) dropped its built-in OsRng.
// Use getrandom 0.4's SysRng instead, wrapped in UnwrapErr to
// expose a non-fallible CryptoRng — the pattern shown in
// ml-dsa's own crate-level usage doc.
use getrandom::{rand_core::UnwrapErr, SysRng};

/// ML-DSA-44 signing key (the `key_gen` output IS the keypair —
/// `SigningKey<P>` implements `signature::Keypair` and exposes
/// `verifying_key()`).
pub struct Keypair(SigningKey<MlDsa44>);

impl Keypair {
    /// Generate a fresh keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = UnwrapErr(SysRng);
        Self(MlDsa44::key_gen(&mut rng))
    }

    /// Encoded verifying key (FIPS 204 §3.5 EncodePublic), 1\,312 B.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let encoded = self.0.verifying_key().encode();
        let slice: &[u8] = encoded.as_ref();
        slice.to_vec()
    }

    /// Sign `message` under this keypair.  Returns the FIPS 204
    /// §3.5 EncodeSignature output, 2\,420 B.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: ml_dsa::Signature<MlDsa44> = self.0.sign(message);
        let bytes = sig.to_bytes();
        let slice: &[u8] = bytes.as_ref();
        slice.to_vec()
    }
}

/// Verify `signature` on `message` under the supplied encoded
/// verifying key.  Returns `Ok(())` on success, `Err` otherwise.
pub fn verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use ml_dsa::{EncodedVerifyingKey, Signature, VerifyingKey};

    let pk_arr: &EncodedVerifyingKey<MlDsa44> = public_key_bytes
        .try_into()
        .map_err(|_| anyhow!("ml-dsa-44 pk length mismatch: got {} bytes",
                             public_key_bytes.len()))?;
    let vk = VerifyingKey::<MlDsa44>::decode(pk_arr);

    // `Signature<P>` implements `TryFrom<&[u8]>` directly.
    let sig = Signature::<MlDsa44>::try_from(signature)
        .map_err(|e| anyhow!("ml-dsa-44 sig failed to decode: {e}"))?;

    vk.verify(message, &sig)
        .map_err(|e| anyhow!("ml-dsa-44 verify rejected: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_sign_verify() {
        let kp = Keypair::generate();
        let pk = kp.public_key_bytes();
        let msg = b"mmiyc/v1/ml-dsa-roundtrip-test";
        let sig = kp.sign(msg);
        // FIPS 204 §4 Table 1 sizes, sanity check.
        assert_eq!(pk.len(), 1312, "ml-dsa-44 pk should be 1312 B");
        assert_eq!(sig.len(), 2420, "ml-dsa-44 sig should be 2420 B");
        verify(&pk, msg, &sig).expect("verify must accept own signature");
    }

    #[test]
    fn verify_rejects_signature_under_wrong_message() {
        let kp = Keypair::generate();
        let pk = kp.public_key_bytes();
        let sig = kp.sign(b"original message");
        assert!(verify(&pk, b"different message", &sig).is_err());
    }

    #[test]
    fn verify_rejects_signature_under_wrong_pk() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let msg = b"shared message";
        let sig = kp1.sign(msg);
        // Verifying kp1's signature under kp2's pk must fail.
        let pk2 = kp2.public_key_bytes();
        assert!(verify(&pk2, msg, &sig).is_err());
    }

    #[test]
    fn verify_rejects_truncated_signature() {
        let kp = Keypair::generate();
        let pk = kp.public_key_bytes();
        let mut sig = kp.sign(b"x");
        sig.pop();
        assert!(verify(&pk, b"x", &sig).is_err());
    }
}

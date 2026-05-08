//! Native ML-DSA (FIPS 204) signature primitive — multi-level.
//!
//! Wraps the RustCrypto [`ml-dsa`] crate to provide a uniform
//! `keygen / sign / verify` surface for the post-quantum
//! designated-verifier gate.  Level-aware: the active scheme is
//! selected by the `mldsa-44` / `mldsa-65` / `mldsa-87` Cargo
//! feature on `deep_ali` (workspace dep).
//!
//! | Feature   | Scheme     | NIST L | pk B | sig B |
//! |-----------|------------|--------|------|-------|
//! | mldsa-44  | ML-DSA-44  | 1      | 1312 | 2420 |
//! | mldsa-65  | ML-DSA-65  | 3      | 1952 | 3293 |
//! | mldsa-87  | ML-DSA-87  | 5      | 2592 | 4627 |
//!
//! Wire-format byte counts auto-derive from
//! `deep_ali::ml_dsa::params::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES}`.

use anyhow::{anyhow, Result};
use ml_dsa::{
    signature::{Keypair as _, SignatureEncoding as _, Signer, Verifier},
    KeyGen, SigningKey,
};

#[cfg(feature = "mldsa-44")]
use ml_dsa::MlDsa44 as ActiveScheme;
#[cfg(feature = "mldsa-65")]
use ml_dsa::MlDsa65 as ActiveScheme;
#[cfg(feature = "mldsa-87")]
use ml_dsa::MlDsa87 as ActiveScheme;
// rand_core 0.10 (which ml-dsa pins) dropped its built-in OsRng.
// Use getrandom 0.4's SysRng instead, wrapped in UnwrapErr to
// expose a non-fallible CryptoRng — the pattern shown in
// ml-dsa's own crate-level usage doc.
use getrandom::{rand_core::UnwrapErr, SysRng};

/// ML-DSA signing key for the active level (mldsa-44/65/87 feature).
/// `SigningKey<P>` implements `signature::Keypair` and exposes
/// `verifying_key()`.
pub struct Keypair(SigningKey<ActiveScheme>);

impl Keypair {
    /// Generate a fresh keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = UnwrapErr(SysRng);
        Self(<ActiveScheme as KeyGen>::key_gen(&mut rng))
    }

    /// Encoded verifying key (FIPS 204 §3.5 EncodePublic).  Length:
    /// 1312 B (ML-DSA-44) / 1952 B (ML-DSA-65) / 2592 B (ML-DSA-87).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let encoded = self.0.verifying_key().encode();
        let slice: &[u8] = encoded.as_ref();
        slice.to_vec()
    }

    /// Sign `message` under this keypair.  Returns the FIPS 204
    /// §3.5 EncodeSignature output.  Length: 2420 / 3293 / 4627 B.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: ml_dsa::Signature<ActiveScheme> = self.0.sign(message);
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

    let pk_arr: &EncodedVerifyingKey<ActiveScheme> = public_key_bytes
        .try_into()
        .map_err(|_| anyhow!("ml-dsa pk length mismatch: got {} bytes",
                             public_key_bytes.len()))?;
    let vk = VerifyingKey::<ActiveScheme>::decode(pk_arr);

    // `Signature<P>` implements `TryFrom<&[u8]>` directly.
    let sig = Signature::<ActiveScheme>::try_from(signature)
        .map_err(|e| anyhow!("ml-dsa sig failed to decode: {e}"))?;

    vk.verify(message, &sig)
        .map_err(|e| anyhow!("ml-dsa verify rejected: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 204 §4 Table 1 sizes per active param set.
    #[cfg(feature = "mldsa-44")]
    const EXPECTED_PK_BYTES: usize = 1312;
    #[cfg(feature = "mldsa-65")]
    const EXPECTED_PK_BYTES: usize = 1952;
    #[cfg(feature = "mldsa-87")]
    const EXPECTED_PK_BYTES: usize = 2592;

    #[cfg(feature = "mldsa-44")]
    const EXPECTED_SIG_BYTES: usize = 2420;
    #[cfg(feature = "mldsa-65")]
    const EXPECTED_SIG_BYTES: usize = 3293;
    #[cfg(feature = "mldsa-87")]
    const EXPECTED_SIG_BYTES: usize = 4627;

    #[test]
    fn round_trip_sign_verify() {
        let kp = Keypair::generate();
        let pk = kp.public_key_bytes();
        let msg = b"mmiyc/v1/ml-dsa-roundtrip-test";
        let sig = kp.sign(msg);
        assert_eq!(pk.len(), EXPECTED_PK_BYTES,
            "ml-dsa pk size must match active param set");
        assert_eq!(sig.len(), EXPECTED_SIG_BYTES,
            "ml-dsa sig size must match active param set");
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

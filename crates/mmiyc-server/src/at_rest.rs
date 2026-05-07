//! At-rest encryption of the income proof bytes.
//!
//! The DB column `users_proofs.income_proof` previously stored raw
//! STARK proof bytes — verifiable by anyone with a copy.  Under the
//! designated-verifier upgrade we wrap each row with hybrid
//! encryption keyed on the operator's RSA-2048 public key, so an
//! attacker who exfiltrates the DB without `sk_rsa` recovers only
//! ciphertext.  They cannot even feed the row to a STARK verifier
//! to learn its truth value — this is the strongest form of the
//! "exfiltrated proof can't be verified" claim.
//!
//! Wire format (single self-framed blob written to the BLOB column):
//!
//! ```text
//!   ┌──────┬──────────────────────────────────────┬───────────┬───────────────────────────┐
//!   │ ver  │ wrapped AES-256 key (RSA-OAEP/SHA-256)│ GCM nonce │ AES-256-GCM ciphertext    │
//!   │ 1 B  │ 256 B (= |n|/8 for RSA-2048)          │ 12 B      │ plaintext_len + 16 (tag)  │
//!   └──────┴──────────────────────────────────────┴───────────┴───────────────────────────┘
//! ```
//!
//! - `ver = 0x01` is the current format.  Reserved for in-place
//!   schema bumps; rejecting an unknown version surfaces the issue
//!   immediately rather than silently misinterpreting bytes.
//! - The AES-GCM tag is appended to the ciphertext by the
//!   `aes-gcm` crate's `encrypt`/`decrypt` API; we don't separate it.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Result};
use rand::{rngs::OsRng, RngCore};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

const VERSION: u8 = 0x01;
const WRAPPED_KEY_LEN: usize = 256;   // RSA-2048 modulus byte size
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 1 + WRAPPED_KEY_LEN + NONCE_LEN;

/// Encrypt `plaintext` so only the holder of `sk_rsa` for `pk_rsa`
/// can decrypt.  Pulls a fresh 256-bit AES key + 96-bit GCM nonce
/// from `OsRng` per call.
pub fn encrypt_for(pk: &RsaPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut aes_key = [0u8; 32];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut aes_key);
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new((&aes_key).into());
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow!("aes-gcm encrypt: {e}"))?;

    let wrapped_key = pk.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &aes_key)
        .map_err(|e| anyhow!("rsa-oaep encrypt: {e}"))?;
    if wrapped_key.len() != WRAPPED_KEY_LEN {
        bail!("rsa-oaep produced {} bytes, expected {}",
              wrapped_key.len(), WRAPPED_KEY_LEN);
    }

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&wrapped_key);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reverse of [`encrypt_for`].  Returns the recovered plaintext —
/// here the original STARK proof bytes ready for `verify_*`.
pub fn decrypt_with(sk: &RsaPrivateKey, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < HEADER_LEN {
        bail!("ciphertext too short ({} bytes)", blob.len());
    }
    let version = blob[0];
    if version != VERSION {
        bail!("unsupported at-rest version: 0x{:02x}", version);
    }
    let wrapped_key = &blob[1..1 + WRAPPED_KEY_LEN];
    let nonce_bytes = &blob[1 + WRAPPED_KEY_LEN..HEADER_LEN];
    let ciphertext  = &blob[HEADER_LEN..];

    let aes_key = sk.decrypt(Oaep::new::<Sha256>(), wrapped_key)
        .map_err(|e| anyhow!("rsa-oaep decrypt: {e}"))?;
    if aes_key.len() != 32 {
        bail!("unwrapped aes key wrong length: {}", aes_key.len());
    }
    let cipher = Aes256Gcm::new(aes_key.as_slice().into());
    cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| anyhow!("aes-gcm decrypt: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small_payload() {
        let sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let pk = sk.to_public_key();
        let pt = b"hello world";
        let blob = encrypt_for(&pk, pt).expect("encrypt");
        let recovered = decrypt_with(&sk, &blob).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn unsupported_version_byte_is_rejected() {
        let sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let pk = sk.to_public_key();
        let mut blob = encrypt_for(&pk, b"x").expect("encrypt");
        blob[0] ^= 0xFF;
        assert!(decrypt_with(&sk, &blob).is_err());
    }

    #[test]
    fn ciphertext_tampering_rejected_by_aead() {
        let sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let pk = sk.to_public_key();
        let mut blob = encrypt_for(&pk, b"some proof bytes").expect("encrypt");
        let n = blob.len();
        blob[n - 1] ^= 0x01; // flip a bit in the GCM tag
        assert!(decrypt_with(&sk, &blob).is_err());
    }
}

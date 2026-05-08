//! Real STARK verifier for Match-Me-If-You-Can proofs.
//!
//! Mirror of [`mmiyc_prover`]: today only the age-range path runs
//! a real `deep_ali` verification; country / postcode / e-mail /
//! income remain at the stub layer pending dual-hash wiring.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

pub mod ml_dsa_pok;

use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use deep_ali::{
    fri::{deep_fri_verify, DeepFriParams, DeepFriProof},
    rsa2048::emsa_pkcs1_v1_5_encode_sha256,
    sextic_ext::SexticExt,
};
use mmiyc_air::{age, country, income, AirError, PolicyId};
use sha2::Sha256;
use sha3::Sha3_256;

type Ext = SexticExt;

/// Pipeline calibration constants — must match `mmiyc-prover`.
const BLOWUP: usize = 32;
const NUM_QUERIES: usize = 54;
const SEED_Z: u64 = 0xDEEF_BAAD;
const N_TRACE_AGE: usize = 32;
const N_TRACE_MERKLE: usize = 512;

fn make_schedule(n0: usize) -> Vec<usize> {
    vec![2usize; n0.trailing_zeros() as usize]
}

/// Verify an age-range proof against the supplied public input.
pub fn verify_age(
    public: &age::Public,
    proof: &[u8],
) -> Result<(), AirError> {
    if public.min_age_years > public.max_age_years {
        return Err(AirError::Policy("min_age_years > max_age_years".into()));
    }
    let n_trace = N_TRACE_AGE;
    let n0 = n_trace * BLOWUP;

    let proof = DeepFriProof::<Ext>::deserialize_with_mode(
        proof, Compress::Yes, Validate::Yes,
    ).map_err(|e| AirError::Deserialise(format!("{e:?}")))?;

    let pi_hash = public.policy_id();
    let params = DeepFriParams {
        schedule: make_schedule(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: false,
        s0: NUM_QUERIES,
        public_inputs_hash: Some(pi_hash),
    };

    if deep_fri_verify::<Ext>(&params, &proof) {
        Ok(())
    } else {
        Err(AirError::Verify("STARK verification rejected the proof".into()))
    }
}

/// Verify a country set-membership proof.
///
/// Mirrors [`mmiyc_prover::prove_country`]: real `deep_fri_verify`
/// against `AirType::MerklePath` at $n_\mathrm{trace} = 512$, with
/// the policy bound through `public_inputs_hash`.  See the prover's
/// doc-comment for the cryptographic boundary on what this
/// currently attests.
pub fn verify_country(
    public: &country::Public,
    proof: &[u8],
) -> Result<(), AirError> {
    if public.set_size == 0 {
        return Err(AirError::Policy("set is empty".into()));
    }
    let n_trace = N_TRACE_MERKLE;
    let n0 = n_trace * BLOWUP;

    let proof = DeepFriProof::<Ext>::deserialize_with_mode(
        proof, Compress::Yes, Validate::Yes,
    ).map_err(|e| AirError::Deserialise(format!("{e:?}")))?;

    let pi_hash = public.policy_id();
    let params = DeepFriParams {
        schedule: make_schedule(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: false,
        s0: NUM_QUERIES,
        public_inputs_hash: Some(pi_hash),
    };

    if deep_fri_verify::<Ext>(&params, &proof) {
        Ok(())
    } else {
        Err(AirError::Verify("STARK verification rejected the proof".into()))
    }
}

/// Verify an income-bracket proof against the supplied public input.
///
/// Same 32-row AgeRange32 STARK shell as [`verify_age`]; the policy
/// is what makes the proofs distinguishable.
pub fn verify_income(
    public: &income::Public,
    proof: &[u8],
) -> Result<(), AirError> {
    if public.bracket_min > public.bracket_max {
        return Err(AirError::Policy("bracket_min > bracket_max".into()));
    }
    let n_trace = N_TRACE_AGE;
    let n0 = n_trace * BLOWUP;

    let proof = DeepFriProof::<Ext>::deserialize_with_mode(
        proof, Compress::Yes, Validate::Yes,
    ).map_err(|e| AirError::Deserialise(format!("{e:?}")))?;

    let pi_hash = public.policy_id();
    let params = DeepFriParams {
        schedule: make_schedule(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: false,
        s0: NUM_QUERIES,
        public_inputs_hash: Some(pi_hash),
    };

    if deep_fri_verify::<Ext>(&params, &proof) {
        Ok(())
    } else {
        Err(AirError::Verify("STARK verification rejected the proof".into()))
    }
}

// ─── RSA-2048 designated-verifier proof of knowledge ────────────────

const RSA2048_K: usize = 256;
const N_TRACE_RSA_POK: usize = 32;

fn make_schedule_rsa_pok(n0: usize) -> Vec<usize> {
    assert!(n0.is_power_of_two());
    let log_n0 = n0.trailing_zeros() as usize;
    let log_arity = 3usize;
    let full_folds = log_n0 / log_arity;
    let remainder_log = log_n0 % log_arity;
    let mut s = vec![8usize; full_folds];
    if remainder_log > 0 {
        s.push(1usize << remainder_log);
    }
    s
}

fn rsa_pok_pi_hash(n_be: &[u8], em: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    let mut h = Sha3_256::new();
    h.update(b"mmiyc/v1/income-rsa-pok");
    h.update(&(n_be.len() as u64).to_be_bytes());
    h.update(n_be);
    h.update(&(em.len() as u64).to_be_bytes());
    h.update(em);
    h.finalize().into()
}

fn emsa_pkcs1_v1_5_encode_msg(message: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    let mut digest = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());
    emsa_pkcs1_v1_5_encode_sha256(&digest, RSA2048_K)
        .expect("RSA-2048-SHA256 EM always fits in k=256")
}

/// Verify an RSA-2048 PoK proof under public modulus `n_be` for the
/// given `message`.  Reconstructs the EMSA-PKCS1-v1_5(SHA256) encoding
/// from `message` and checks the FRI proof under the matching
/// `public_inputs_hash` binding.  See `mmiyc_prover::prove_rsa_pok`
/// for the threat model.
pub fn verify_rsa_pok(
    n_be: &[u8],
    message: &[u8],
    proof: &[u8],
) -> Result<(), AirError> {
    if n_be.is_empty() {
        return Err(AirError::Policy("rsa_pok: empty modulus".into()));
    }
    let n_trace = N_TRACE_RSA_POK;
    let n0 = n_trace * BLOWUP;

    let proof = DeepFriProof::<Ext>::deserialize_with_mode(
        proof, Compress::Yes, Validate::Yes,
    ).map_err(|e| AirError::Deserialise(format!("{e:?}")))?;

    let em = emsa_pkcs1_v1_5_encode_msg(message);
    let pi_hash = rsa_pok_pi_hash(n_be, &em);

    let params = DeepFriParams {
        schedule: make_schedule_rsa_pok(n0),
        r: NUM_QUERIES,
        seed_z: SEED_Z,
        coeff_commit_final: true,
        d_final: 1,
        stir: true,
        s0: NUM_QUERIES,
        public_inputs_hash: Some(pi_hash),
    };

    if deep_fri_verify::<Ext>(&params, &proof) {
        Ok(())
    } else {
        Err(AirError::Verify("RSA-PoK STARK verification rejected the proof".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realistic_age_policy() -> age::Public {
        age::Public {
            today_days: 20_000,
            min_age_years: 18,
            max_age_years: 120,
        }
    }

    #[test]
    fn round_trip_age_proof() {
        let public = realistic_age_policy();
        let (lo, _hi) = public.dob_bounds();
        let witness = age::Witness { dob_days: lo + 5_000 };
        let proof = mmiyc_prover::prove_age(&public, &witness).expect("prove ok");
        verify_age(&public, &proof).expect("verify should accept own proof");
    }

    #[test]
    fn proof_for_one_policy_does_not_verify_under_another() {
        // Different `min_age_years` ⇒ different policy_id ⇒ different
        // public_inputs_hash ⇒ verifier must reject.
        let p18 = age::Public { today_days: 20_000, min_age_years: 18, max_age_years: 120 };
        let p21 = age::Public { today_days: 20_000, min_age_years: 21, max_age_years: 120 };
        let (lo, _hi) = p18.dob_bounds();
        let witness = age::Witness { dob_days: lo + 5_000 };
        let proof = mmiyc_prover::prove_age(&p18, &witness).expect("prove ok");
        assert!(verify_age(&p21, &proof).is_err(),
                "proof under p18 must not verify under p21");
    }

    #[test]
    fn round_trip_country_proof() {
        let codes = ["AT","BE","BG","DE","FR","IT"];
        let (public, leaves) = country::build_set(&codes);
        let witness = country::Witness { country_code: "DE".into() };
        let proof = mmiyc_prover::prove_country(&public, &witness, &leaves)
            .expect("prove ok");
        verify_country(&public, &proof)
            .expect("verify should accept own proof");
    }

    #[test]
    fn country_proof_for_one_set_does_not_verify_under_another() {
        // Different set roots ⇒ different policy_id ⇒ verifier must reject.
        let (p_eu27, leaves_eu) = country::build_set(&["AT","DE","FR"]);
        let (p_eea,  _leaves_eea) = country::build_set(&["NO","IS","LI"]);
        let witness = country::Witness { country_code: "DE".into() };
        let proof = mmiyc_prover::prove_country(&p_eu27, &witness, &leaves_eu)
            .expect("prove ok");
        assert!(verify_country(&p_eea, &proof).is_err(),
                "proof under EU-3 must not verify under EEA-3");
    }

    fn fresh_rsa_keypair_and_sign(message: &[u8])
        -> (Vec<u8>, Vec<u8>) // (n_be, signature_be)
    {
        use rsa::{
            pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
            traits::PublicKeyParts, RsaPrivateKey,
        };
        use sha2::Sha256;
        // Deterministic seed so the test is reproducible without
        // making the (slow) RSA-2048 keygen flaky on CI.
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0xC0FFEE);
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let n_be = priv_key.to_public_key().n().to_bytes_be();
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let sig = signing_key.sign(message);
        (n_be, sig.to_bytes().to_vec())
    }

    #[test]
    #[ignore = "RSA-2048 keygen is slow; run explicitly with --ignored"]
    fn round_trip_rsa_pok() {
        let message = b"income-verify-binding-2026-05-07";
        let (n_be, sig_be) = fresh_rsa_keypair_and_sign(message);
        let proof = mmiyc_prover::prove_rsa_pok(&n_be, message, &sig_be)
            .expect("prove_rsa_pok must succeed for a valid signature");
        verify_rsa_pok(&n_be, message, &proof)
            .expect("verifier must accept its own prover's proof");
    }

    #[test]
    #[ignore = "RSA-2048 keygen is slow; run explicitly with --ignored"]
    fn rsa_pok_does_not_verify_under_a_different_message() {
        let message = b"income-verify-binding-2026-05-07";
        let (n_be, sig_be) = fresh_rsa_keypair_and_sign(message);
        let proof = mmiyc_prover::prove_rsa_pok(&n_be, message, &sig_be)
            .expect("prove ok");
        // Verifier reconstructs `em` from message; a different message
        // hashes to a different `em`, hence a different
        // public_inputs_hash → STARK rejects.
        let other = b"income-verify-binding-2026-05-08";
        assert!(verify_rsa_pok(&n_be, other, &proof).is_err(),
                "proof under one message must not verify under another");
    }
}

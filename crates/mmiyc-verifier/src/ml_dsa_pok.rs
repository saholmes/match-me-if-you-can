//! ML-DSA-44 STARK proof of knowledge — verifier side.
//!
//! Mirrors `mmiyc_prover::ml_dsa_pok::prove_ml_dsa_pok`.  Takes the
//! public inputs (the same `MlDsaPokPublicInputs`-shaped tuple)
//! and the FRI proof bytes, reconstructs `public_inputs_hash`, and
//! calls `deep_fri_verify`.
//!
//! This module is the v1 STARK-side of the gate.  In a real
//! ML-DSA signature PoK, the public inputs would be derived
//! deterministically from `(pk, signature)` via FIPS 204 §3.4
//! ExpandA + §3.5.5 sigDecode + native NTTs; that derivation is
//! deferred (see `mmiyc_prover::ml_dsa_pok` doc comment).

#![allow(non_snake_case, dead_code)]

use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use deep_ali::{
    fri::{deep_fri_verify, DeepFriParams, DeepFriProof},
    ml_dsa::params::{K, L, N},
    sextic_ext::SexticExt,
};
use mmiyc_air::AirError;
use sha3::{Digest as _, Sha3_256};

type Ext = SexticExt;

const BLOWUP: usize = 32;
const NUM_QUERIES: usize = 54;
const SEED_Z: u64 = 0xDEEF_BAAD;

/// Re-exported here so callers can construct the same shape used
/// by `mmiyc_prover::ml_dsa_pok::prove_ml_dsa_pok`.  Defined as a
/// duplicate (rather than crate-cycle) because mmiyc-verifier is
/// upstream of mmiyc-prover in the dep graph.
pub struct MlDsaPokPublicInputs {
    pub a_ntt:        Box<[[[u32; N]; L]; K]>,
    pub c_ntt:        Box<[u32; N]>,
    pub t1d_ntt:      Box<[[u32; N]; K]>,
    pub w_approx_ntt: Box<[[u32; N]; K]>,
}

/// Identical to the prover's hash; both sides MUST produce the
/// same digest from the same public inputs.
pub fn compute_pi_hash(pi: &MlDsaPokPublicInputs) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"mmiyc/v1/ml-dsa-pok/public-inputs");
    for k in 0..K {
        for l in 0..L {
            for v in pi.a_ntt[k][l].iter() {
                h.update(v.to_be_bytes());
            }
        }
    }
    for v in pi.c_ntt.iter() { h.update(v.to_be_bytes()); }
    for k in 0..K {
        for v in pi.t1d_ntt[k].iter() { h.update(v.to_be_bytes()); }
    }
    for k in 0..K {
        for v in pi.w_approx_ntt[k].iter() { h.update(v.to_be_bytes()); }
    }
    h.finalize().into()
}

fn make_schedule(n0: usize) -> Vec<usize> {
    vec![2usize; n0.trailing_zeros() as usize]
}

/// Verify a real ML-DSA-44 signature PoK.  Two-layer check:
///   1. **Native ML-DSA-44 verify** — runs the upstream
///      RustCrypto `ml-dsa` verifier on `(pk, message, sig)`.
///      Enforces full FIPS 204 §3 Algorithm 3 acceptance
///      (`c̃ = c̃'` after UseHint + w1Encode + SHAKE-256).  Closes
///      the soundness gap that the v1 STARK alone cannot enforce
///      (the STARK proves only the polynomial-arithmetic core).
///   2. **STARK PoK** — re-derives the AIR's public inputs from
///      `(pk, message, sig)` exactly as the prover did, then
///      verifies the FRI proof.
///
/// Returns `Ok(())` iff both layers accept.  The native check
/// runs first so an obviously invalid signature is rejected
/// before paying STARK-verify cost.
pub fn verify_ml_dsa_signature_pok(
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
    proof: &[u8],
) -> Result<(), AirError> {
    // Layer 1: native ML-DSA-44 verify.
    use ml_dsa::{
        signature::Verifier as _, EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey,
    };
    let pk_arr: &EncodedVerifyingKey<MlDsa44> = pk_bytes
        .try_into()
        .map_err(|_| AirError::Deserialise(format!(
            "ml-dsa-44 pk length mismatch: got {}", pk_bytes.len()
        )))?;
    let vk = VerifyingKey::<MlDsa44>::decode(pk_arr);
    let sig = Signature::<MlDsa44>::try_from(sig_bytes)
        .map_err(|e| AirError::Deserialise(format!("ml-dsa-44 sig decode: {e}")))?;
    vk.verify(message, &sig)
        .map_err(|e| AirError::Verify(format!("ml-dsa-44 native verify rejected: {e}")))?;

    // Layer 2: STARK PoK.
    let (pi_prover, _witness) = mmiyc_prover::ml_dsa_pok::synthesise_from_signature(
        pk_bytes, message, sig_bytes,
    ).ok_or_else(|| AirError::Witness(
        "could not decode pk/signature for ML-DSA-44".into()
    ))?;
    let pi = MlDsaPokPublicInputs {
        a_ntt:        pi_prover.a_ntt,
        c_ntt:        pi_prover.c_ntt,
        t1d_ntt:      pi_prover.t1d_ntt,
        w_approx_ntt: pi_prover.w_approx_ntt,
    };
    verify_ml_dsa_pok(&pi, proof)
}

/// Verify an ML-DSA STARK PoK proof against the supplied public inputs.
pub fn verify_ml_dsa_pok(
    pi: &MlDsaPokPublicInputs,
    proof: &[u8],
) -> Result<(), AirError> {
    use deep_ali::ml_dsa_verify_air::VERIFY_AIR_ROWS;
    let n_trace = VERIFY_AIR_ROWS.next_power_of_two();
    let n0 = n_trace * BLOWUP;

    let proof = DeepFriProof::<Ext>::deserialize_with_mode(
        proof, Compress::Yes, Validate::Yes,
    ).map_err(|e| AirError::Deserialise(format!("{e:?}")))?;

    let pi_hash = compute_pi_hash(pi);
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
        Err(AirError::Verify("ML-DSA STARK PoK rejected".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deep_ali::ml_dsa::params::Q;
    use deep_ali::ml_dsa_field::{add_q, mul_q, sub_q};

    fn synthetic_inputs() -> (MlDsaPokPublicInputs, mmiyc_prover::ml_dsa_pok::MlDsaPokWitness) {
        // Same synthetic data as the prover's test, recreated here
        // so the test is self-contained.
        let mut a_ntt = Box::new([[[0u32; N]; L]; K]);
        let mut z_ntt = Box::new([[0u32; N]; L]);
        let mut c_ntt = Box::new([0u32; N]);
        let mut t1d_ntt = Box::new([[0u32; N]; K]);
        for k in 0..K {
            for l in 0..L {
                for i in 0..N {
                    a_ntt[k][l][i] = (1000 + i as u32 * 17 + l as u32 * 31 + k as u32 * 41) % Q;
                }
            }
        }
        for l in 0..L {
            for i in 0..N {
                z_ntt[l][i] = (3 + i as u32 * 7 + l as u32 * 19) % Q;
            }
        }
        for i in 0..N { c_ntt[i] = (1 + i as u32 * 23) % Q; }
        for k in 0..K {
            for i in 0..N {
                t1d_ntt[k][i] = (5 + i as u32 * 11 + k as u32 * 13) % Q;
            }
        }
        let mut w_approx_ntt = Box::new([[0u32; N]; K]);
        for k in 0..K {
            for i in 0..N {
                let mut acc: u32 = 0;
                for l in 0..L {
                    acc = add_q(acc, mul_q(a_ntt[k][l][i], z_ntt[l][i]));
                }
                let ct1d = mul_q(c_ntt[i], t1d_ntt[k][i]);
                w_approx_ntt[k][i] = sub_q(acc, ct1d);
            }
        }
        let pi = MlDsaPokPublicInputs { a_ntt, c_ntt, t1d_ntt, w_approx_ntt };
        let witness = mmiyc_prover::ml_dsa_pok::MlDsaPokWitness { z_ntt };
        (pi, witness)
    }

    fn to_prover_pi(pi: &MlDsaPokPublicInputs) -> mmiyc_prover::ml_dsa_pok::MlDsaPokPublicInputs {
        mmiyc_prover::ml_dsa_pok::MlDsaPokPublicInputs {
            a_ntt:        pi.a_ntt.clone(),
            c_ntt:        pi.c_ntt.clone(),
            t1d_ntt:      pi.t1d_ntt.clone(),
            w_approx_ntt: pi.w_approx_ntt.clone(),
        }
    }

    #[test]
    fn round_trip_prove_verify() {
        let (pi, witness) = synthetic_inputs();
        let prover_pi = to_prover_pi(&pi);
        let proof = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_pok(&prover_pi, &witness)
            .expect("prove ok");
        verify_ml_dsa_pok(&pi, &proof).expect("verify must accept own prover's proof");
    }

    #[test]
    fn proof_for_one_pi_does_not_verify_under_another() {
        let (pi, witness) = synthetic_inputs();
        let prover_pi = to_prover_pi(&pi);
        let proof = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_pok(&prover_pi, &witness)
            .expect("prove ok");

        // Tamper with one public input so pi_hash differs.
        let mut tampered = MlDsaPokPublicInputs {
            a_ntt:        pi.a_ntt,
            c_ntt:        pi.c_ntt,
            t1d_ntt:      pi.t1d_ntt,
            w_approx_ntt: pi.w_approx_ntt,
        };
        tampered.c_ntt[0] = (tampered.c_ntt[0] + 1) % Q;
        assert!(verify_ml_dsa_pok(&tampered, &proof).is_err(),
            "proof under one pi must not verify under a different pi");
    }

    /// Real ML-DSA-44 signature round-trip: keygen via the upstream
    /// `ml-dsa` crate, sign a message, run our prove_ml_dsa_signature_pok
    /// over the encoded `(pk, sig)` bytes, then verify.  Exercises
    /// the full FIPS 204 byte-decode + ExpandA + NTT chain.
    fn fresh_real_signature_bytes(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use ml_dsa::{KeyGen, MlDsa44, signature::{Keypair as _, SignatureEncoding as _, Signer as _}};
        use getrandom::{rand_core::UnwrapErr, SysRng};
        let mut rng = UnwrapErr(SysRng);
        let kp = MlDsa44::key_gen(&mut rng);
        let pk_arr = kp.verifying_key().encode();
        let pk_slice: &[u8] = pk_arr.as_ref();
        let pk_bytes = pk_slice.to_vec();
        let sig: ml_dsa::Signature<MlDsa44> = kp.sign(message);
        let sig_arr = sig.to_bytes();
        let sig_slice: &[u8] = sig_arr.as_ref();
        let sig_bytes = sig_slice.to_vec();
        (pk_bytes, sig_bytes)
    }

    #[test]
    fn round_trip_real_ml_dsa_signature() {
        let message: &[u8] = b"mmiyc/v1/ml-dsa-pok-real-signature-test";
        let (pk_bytes, sig_bytes) = fresh_real_signature_bytes(message);

        let proof = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_signature_pok(
            &pk_bytes, message, &sig_bytes,
        ).expect("prove_ml_dsa_signature_pok must succeed for a valid signature");

        verify_ml_dsa_signature_pok(&pk_bytes, message, &sig_bytes, &proof)
            .expect("verify must accept the prover's own STARK PoK over the real signature");
    }

    #[test]
    fn tampered_signature_breaks_pok() {
        let msg: &[u8] = b"tamper test";
        let (pk_bytes, sig_bytes) = fresh_real_signature_bytes(msg);

        let proof = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_signature_pok(
            &pk_bytes, msg, &sig_bytes,
        ).expect("prove ok");

        // Flip one bit in the c_tilde portion of the signature so
        // the derived pi_hash will differ on the verifier's side.
        let mut tampered = sig_bytes.clone();
        tampered[0] ^= 0x01;
        assert!(verify_ml_dsa_signature_pok(&pk_bytes, msg, &tampered, &proof).is_err(),
            "STARK PoK derived from one signature must not verify under a tampered signature");
    }
}

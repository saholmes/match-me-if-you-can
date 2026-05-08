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
}

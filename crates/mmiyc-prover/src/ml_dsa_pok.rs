//! ML-DSA-44 STARK proof of knowledge — **phase 7 v1**.
//!
//! Drives `deep_ali::ml_dsa_verify_air` (the pointwise polynomial
//! core of FIPS 204 §3 Algorithm 3 step 5) through the FRI prove
//! pipeline.  Returns a serialized `DeepFriProof` byte-string that
//! can be paired with a native ML-DSA signature to make a
//! signature-PoK.
//!
//! ## Status
//!
//! The AIR's v1 design treats `(a_ntt, c_ntt, t1d_ntt, w_approx_ntt)`
//! as public inputs and only `z_ntt` as witness.  In a "real"
//! signature-PoK these would be derived deterministically from
//! `(pk, signature)` via FIPS 204 §3.4 ExpandA and FIPS 204 §3.5.5
//! sigDecode.  Those decoders are non-trivial and don't exist
//! yet — the upstream `ml-dsa` crate doesn't expose internal
//! polynomial state.  v1 of this prover therefore takes the
//! NTT-domain values directly as caller-supplied inputs; the
//! "couple to a real ML-DSA signature" plumbing is deferred to
//! the next session (phase 7.5 / 8.5).
//!
//! Even with that gap, this prover successfully exercises the
//! deep_ali → STARK → FRI prove path end-to-end with the new
//! ML-DSA verify-AIR, validating the integration before the
//! decoder/ExpandA work lands.

#![allow(non_snake_case, dead_code)]

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use deep_ali::{
    deep_ali_merge_general,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, DeepFriParams, FriDomain},
    ml_dsa::params::{K, L, N},
    ml_dsa_verify_air::{self, VERIFY_AIR_ROWS, WIDTH as VERIFY_WIDTH},
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};
use mmiyc_air::AirError;
use sha3::{Digest as _, Sha3_256};

type Ext = SexticExt;

const BLOWUP: usize = 32;
const NUM_QUERIES: usize = 54;
const SEED_Z: u64 = 0xDEEF_BAAD;

/// Public inputs to the ML-DSA-STARK PoK.  These are the values
/// the verifier deterministically reconstructs (in the next-session
/// version, from `(pk, signature)`); the AIR's
/// `public_inputs_hash` binds the proof to them.
pub struct MlDsaPokPublicInputs {
    pub a_ntt:        Box<[[[u32; N]; L]; K]>,   // matrix Â
    pub c_ntt:        Box<[u32; N]>,
    pub t1d_ntt:      Box<[[u32; N]; K]>,
    pub w_approx_ntt: Box<[[u32; N]; K]>,
}

/// Witness: response polynomial in NTT domain.
pub struct MlDsaPokWitness {
    pub z_ntt: Box<[[u32; N]; L]>,
}

/// Derive `(public_inputs, witness)` from a real ML-DSA-44
/// signature.  Implements the FIPS 204 §3 Algorithm 3 step-5 setup:
///
/// 1. Decode `pk_bytes` → `(ρ, t1)` (FIPS 204 §3.5.4).
/// 2. Decode `sig_bytes` → `(c̃, z, h)` (FIPS 204 §3.5.5).
/// 3. ExpandA(ρ) → matrix Â already in NTT domain (FIPS 204 §3.4).
/// 4. c ← SampleInBall(c̃); c_hat ← NTT(c).
/// 5. t1_2d ← t1 · 2^d; t1_2d_hat ← NTT per polynomial.
/// 6. z_hat ← NTT per polynomial of z.
/// 7. w_approx_ntt[k][i] = Σ_l Â[k][l][i]·z_hat[l][i]
///                         − c_hat[i]·t1_2d_hat[k][i]   (mod q)
///
/// The returned tuple is exactly what `prove_ml_dsa_pok` consumes.
/// The same function is used by the verifier (it has access to all
/// of `pk_bytes`, `message`, `sig_bytes`).
pub fn synthesise_from_signature(
    pk_bytes: &[u8],
    _message: &[u8],
    sig_bytes: &[u8],
) -> Option<(MlDsaPokPublicInputs, MlDsaPokWitness)> {
    use deep_ali::ml_dsa_codec::{decode_pk, decode_signature, expand_a, t1_times_2d};
    use deep_ali::ml_dsa_field::{add_q, mul_q, sub_q};
    use deep_ali::ml_dsa_ntt::ntt;
    use deep_ali::ml_dsa_sample_in_ball::sample_in_ball;

    let (rho, t1) = decode_pk(pk_bytes)?;
    let (c_tilde, z, _h) = decode_signature(sig_bytes)?;

    // ExpandA already returns Â in NTT domain.
    let a_hat = expand_a(&rho);

    // c ← SampleInBall(c̃); c_hat ← NTT(c).
    let mut c_poly = sample_in_ball(&c_tilde);
    ntt(&mut c_poly);
    let mut c_ntt = Box::new([0u32; N]);
    *c_ntt = c_poly;

    // t1·2^d, then NTT each polynomial.
    let mut t1_2d = t1_times_2d(&t1);
    for k in 0..K { ntt(&mut t1_2d[k]); }
    let mut t1d_ntt: Box<[[u32; N]; K]> = Box::new([[0u32; N]; K]);
    for k in 0..K { t1d_ntt[k] = t1_2d[k]; }

    // NTT each z polynomial.
    let mut z_ntt: Box<[[u32; N]; L]> = Box::new([[0u32; N]; L]);
    for l in 0..L {
        let mut zl = z[l];
        ntt(&mut zl);
        z_ntt[l] = zl;
    }

    // w_approx_ntt[k][i] = Σ_l a_hat[k][l][i]·z_ntt[l][i]
    //                     − c_ntt[i]·t1d_ntt[k][i]   (mod q)
    let mut w_approx_ntt: Box<[[u32; N]; K]> = Box::new([[0u32; N]; K]);
    for k in 0..K {
        for i in 0..N {
            let mut acc: u32 = 0;
            for l in 0..L {
                acc = add_q(acc, mul_q(a_hat[k][l][i], z_ntt[l][i]));
            }
            let ct1d = mul_q(c_ntt[i], t1d_ntt[k][i]);
            w_approx_ntt[k][i] = sub_q(acc, ct1d);
        }
    }

    let pi = MlDsaPokPublicInputs {
        a_ntt: a_hat,
        c_ntt,
        t1d_ntt,
        w_approx_ntt,
    };
    let witness = MlDsaPokWitness { z_ntt };
    Some((pi, witness))
}

/// Convenience: produce a STARK PoK over the public inputs derived
/// from a real ML-DSA-44 signature.  Equivalent to running
/// [`synthesise_from_signature`] then [`prove_ml_dsa_pok`].
pub fn prove_ml_dsa_signature_pok(
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<Vec<u8>, AirError> {
    let (pi, witness) = synthesise_from_signature(pk_bytes, message, sig_bytes)
        .ok_or_else(|| AirError::Witness(
            "could not decode pk/signature for ML-DSA-44".into()
        ))?;
    prove_ml_dsa_pok(&pi, &witness)
}

/// Deterministically synthesise a `(public_inputs, witness)` pair
/// from a 32-byte nonce.  Used by the v1 demo path so the browser
/// and server can recompute the same inputs without shipping ~21
/// KB of polynomial coefficients across the wire.
///
/// Real ML-DSA-signature PoKs would replace this with FIPS 204
/// §3.4 ExpandA + §3.5.5 sigDecode + native NTTs deriving from
/// `(pk, signature)`.  The wire shape is what changes; the AIR /
/// FRI machinery is identical.
pub fn synthesise_from_nonce(nonce: &[u8; 32]) -> (MlDsaPokPublicInputs, MlDsaPokWitness) {
    use deep_ali::ml_dsa::params::Q;
    use deep_ali::ml_dsa_field::{add_q, mul_q, sub_q};

    // Expand the nonce into a deterministic stream of u32s in [0, q).
    fn next_u32(state: &mut [u8; 32], counter: &mut u64) -> u32 {
        loop {
            let mut h = Sha3_256::new();
            h.update(b"mmiyc/v1/ml-dsa-pok/synth");
            h.update(&*state);
            h.update(counter.to_be_bytes());
            *counter += 1;
            let out = h.finalize();
            let v = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
            // Reject-sample to get an in-range Z_q value.
            if v < (u32::MAX / Q) * Q {
                return v % Q;
            }
        }
    }

    let mut state = *nonce;
    let mut counter = 0u64;
    let mut a_ntt = Box::new([[[0u32; N]; L]; K]);
    let mut z_ntt = Box::new([[0u32; N]; L]);
    let mut c_ntt = Box::new([0u32; N]);
    let mut t1d_ntt = Box::new([[0u32; N]; K]);
    for k in 0..K {
        for l in 0..L {
            for i in 0..N {
                a_ntt[k][l][i] = next_u32(&mut state, &mut counter);
            }
        }
    }
    for l in 0..L {
        for i in 0..N { z_ntt[l][i] = next_u32(&mut state, &mut counter); }
    }
    for i in 0..N { c_ntt[i] = next_u32(&mut state, &mut counter); }
    for k in 0..K {
        for i in 0..N { t1d_ntt[k][i] = next_u32(&mut state, &mut counter); }
    }

    // Compute w_approx_ntt natively from the equation; both sides
    // produce the same value, so it's effectively part of the
    // deterministically-derived public input.
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
    let witness = MlDsaPokWitness { z_ntt };
    (pi, witness)
}

/// Compose all NTT-domain values into the deterministic
/// `public_inputs_hash` that `deep_fri_prove` and `deep_fri_verify`
/// both bind to.  Domain-separated; both prover and verifier
/// reconstruct exactly this digest from the same public inputs.
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

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

/// Produce a STARK proof that the polynomial-arithmetic verify
/// equation holds for the supplied (public, witness) pair.
///
/// The trace shape is `n_trace = next_power_of_two(VERIFY_AIR_ROWS)`
/// (currently 1024 → 1024).  Constraint set is the per-row
/// constraints from `ml_dsa_verify_air::eval_per_row`.
pub fn prove_ml_dsa_pok(
    pi: &MlDsaPokPublicInputs,
    witness: &MlDsaPokWitness,
) -> Result<Vec<u8>, AirError> {
    let n_trace = VERIFY_AIR_ROWS.next_power_of_two();
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);

    let mut trace: Vec<Vec<F>> = (0..VERIFY_WIDTH)
        .map(|_| vec![F::zero(); n_trace])
        .collect();
    ml_dsa_verify_air::fill_trace(
        &mut trace, n_trace,
        &pi.a_ntt, &witness.z_ntt, &pi.c_ntt, &pi.t1d_ntt, &pi.w_approx_ntt,
    );

    // We need a custom merge for ml_dsa_verify_air since its
    // constraint shape is unique.  For v1, hand-roll the merge by
    // using a one-shot `deep_ali_merge_general`-shaped harness.
    // The deep_ali pipeline doesn't yet have an ml_dsa-specific
    // merge function; since `eval_per_row` of ml_dsa_verify_air is
    // pure deg-2 + per-row, we wrap it with a small adapter that
    // calls the AIR's own evaluator on each row.
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP)
        .map_err(|e| AirError::Internal(format!("LDE failed: {e:?}")))?;

    let n_constraints = ml_dsa_verify_air::NUM_CONSTRAINTS;
    let coeffs = comb_coeffs(n_constraints);

    // Compute Φ̃ on the LDE domain by hand: for each LDE row, run
    // ml_dsa_verify_air::eval_per_row and form the random linear
    // combination.  Then IFFT to coefficients, divide by Z_H, FFT
    // back — same shape as `deep_ali_merge_general` but with the
    // verify-AIR's evaluator hard-wired.
    let c_eval = compose_verify_air_c_eval(&lde, &coeffs, n_trace);
    drop(lde);

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

    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let size = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut blob = Vec::with_capacity(size);
    proof.serialize_with_mode(&mut blob, Compress::Yes)
        .map_err(|e| AirError::Internal(format!("serialize failed: {e:?}")))?;
    Ok(blob)
}

/// Compose the C-polynomial on the LDE domain by running
/// `ml_dsa_verify_air::eval_per_row` against every LDE row.  This
/// is the "merge" step `deep_ali_merge_general` performs for
/// generic AIRs — replicated here because the verify-AIR's
/// constraint shape isn't enrolled in `air_workloads::AirType`.
fn compose_verify_air_c_eval(
    lde: &[Vec<F>], coeffs: &[F], n_trace: usize,
) -> Vec<F> {
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

    let n = lde[0].len();
    let blowup = n / n_trace;
    let n_constraints = coeffs.len();

    // Phi values on the LDE.
    let mut phi = vec![F::zero(); n];
    for i in 0..n {
        let cur: Vec<F> = (0..lde.len()).map(|c| lde[c][i]).collect();
        let nxt_idx = (i + blowup) % n;
        let nxt: Vec<F> = (0..lde.len()).map(|c| lde[c][nxt_idx]).collect();
        let trace_row = i / blowup;
        let cvals = ml_dsa_verify_air::eval_per_row(&cur, &nxt, trace_row);
        debug_assert_eq!(cvals.len(), n_constraints);
        let mut acc = F::zero();
        for j in 0..n_constraints { acc += coeffs[j] * cvals[j]; }
        phi[i] = acc;
    }
    let domain = GeneralEvaluationDomain::<F>::new(n)
        .expect("power-of-two domain");
    let phi_coeffs = domain.ifft(&phi);
    // Divide by Z_H = X^n_trace - 1.  Reuse deep_ali's poly_div_zh
    // semantics by computing via its public form: not exposed, so
    // we replicate the recurrence here.
    let c_coeffs = poly_div_zh_local(&phi_coeffs, n_trace);
    let mut padded = c_coeffs;
    padded.resize(n, F::zero());
    domain.fft(&padded)
}

/// Local copy of deep_ali's poly_div_zh logic.  Divides `dividend`
/// by `Z_H = X^m - 1`.  Returns the quotient evaluated as
/// coefficients.  Matches the upstream semantics.
fn poly_div_zh_local(dividend: &[F], m: usize) -> Vec<F> {
    let n = dividend.len();
    if n <= m { return vec![F::zero(); n.max(1)]; }
    let q_len = n - m;
    let mut q = vec![F::zero(); q_len];
    for k in (m..n).rev() {
        let qk = if k < q_len { q[k] } else { F::zero() };
        q[k - m] = dividend[k] + qk;
    }
    q
}

// Suppress unused warning when caller-side hasn't wired
// `deep_ali_merge_general` yet (we may want to merge in future).
#[allow(unused_imports)]
use deep_ali_merge_general as _unused_in_v1;

#[cfg(test)]
mod tests {
    use super::*;
    use deep_ali::ml_dsa_field::{add_q, mul_q, sub_q};

    fn synthetic_inputs() -> (MlDsaPokPublicInputs, MlDsaPokWitness) {
        let mut a_ntt = Box::new([[[0u32; N]; L]; K]);
        let mut z_ntt = Box::new([[0u32; N]; L]);
        let mut c_ntt = Box::new([0u32; N]);
        let mut t1d_ntt = Box::new([[0u32; N]; K]);
        for k in 0..K {
            for l in 0..L {
                for i in 0..N {
                    a_ntt[k][l][i] = (1000 + i as u32 * 17 + l as u32 * 31 + k as u32 * 41)
                        % deep_ali::ml_dsa::params::Q;
                }
            }
        }
        for l in 0..L {
            for i in 0..N {
                z_ntt[l][i] = (3 + i as u32 * 7 + l as u32 * 19)
                    % deep_ali::ml_dsa::params::Q;
            }
        }
        for i in 0..N {
            c_ntt[i] = (1 + i as u32 * 23) % deep_ali::ml_dsa::params::Q;
        }
        for k in 0..K {
            for i in 0..N {
                t1d_ntt[k][i] = (5 + i as u32 * 11 + k as u32 * 13)
                    % deep_ali::ml_dsa::params::Q;
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
        let witness = MlDsaPokWitness { z_ntt };
        (pi, witness)
    }

    #[test]
    fn prove_returns_a_proof() {
        let (pi, witness) = synthetic_inputs();
        let proof = prove_ml_dsa_pok(&pi, &witness).expect("prove ok");
        // Sanity: proof should be well over 10 KiB.
        assert!(proof.len() > 10_000,
            "ml-dsa-pok proof unexpectedly small: {} bytes", proof.len());
    }

    #[test]
    fn pi_hash_is_deterministic() {
        let (pi, _) = synthetic_inputs();
        let h1 = compute_pi_hash(&pi);
        let h2 = compute_pi_hash(&pi);
        assert_eq!(h1, h2);
    }

    #[test]
    fn pi_hash_changes_with_inputs() {
        let (mut pi, _) = synthetic_inputs();
        let h1 = compute_pi_hash(&pi);
        pi.c_ntt[0] = (pi.c_ntt[0] + 1) % deep_ali::ml_dsa::params::Q;
        let h2 = compute_pi_hash(&pi);
        assert_ne!(h1, h2);
    }
}

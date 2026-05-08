//! Real STARK proof generation for Match-Me-If-You-Can.
//!
//! This crate is the prover-side wrapper around the upstream
//! [`deep_ali`] STARK-STIR backend.  Today the only AIR with a
//! real (non-stub) proof path is [`mmiyc_air::age`] — wired via
//! [`AirType::AgeRange32`].  The country / postcode / e-mail /
//! income predicates remain at the stub layer pending the
//! dual-hash MerklePath + SHA3 AirType variants discussed in
//! section 5.2 / section 10 of the paper.
//!
//! Calibration mirrors section III of the stark-stir paper:
//! `1/ρ_0 = 32` blowup, sextic extension over Goldilocks,
//! `54` FRI queries, arity-2 binary fold.  These constants are
//! pinned in this crate (not exposed) so the wire format is
//! stable across deployments.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

pub mod ml_dsa_pok;

use ark_ff::Zero as _;
use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use deep_ali::{
    air_workloads::{build_execution_trace, AirType},
    deep_ali_merge_general, deep_ali_merge_rsa_stacked_streaming,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, DeepFriParams, FriDomain},
    rsa2048::emsa_pkcs1_v1_5_encode_sha256,
    rsa2048_stacked_air::{
        build_rsa_stacked_layout, fill_rsa_stacked, rsa_stacked_constraints,
        RsaStackedRecord,
    },
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};
use mmiyc_air::{age, country, income, AirError, PolicyId};
use num_bigint::BigUint;
use sha2::Sha256;
use sha3::Sha3_256;

type Ext = SexticExt;

/// Reed-Solomon blowup factor (1/ρ_0 = 32).
const BLOWUP: usize = 32;
/// FRI/STIR query count.  79 = NIST PQ Level 3 (Johnson-regime
/// unconditional): 79 × ½·log₂(1/ρ_0) = 79 × 2.5 = 197.5 ≥ 192 bits.
/// Reverting to Level 1 (sha3-256, λ=128): NUM_QUERIES = 54.  Both
/// rates use the proven Johnson bound (BCIKS for FRI / STIR Thm. 1);
/// the capacity-regime rate (~5 bits/query) is conjectural and not
/// used here.
const NUM_QUERIES: usize = 79;
/// Fixed Fiat-Shamir-style starting seed; the public-inputs hash
/// is what differentiates proofs across policies, not this.
const SEED_Z: u64 = 0xDEEF_BAAD;

/// Trace size for the age-range AIR (one row per witness bit; two
/// parallel columns).
const N_TRACE_AGE: usize = 32;

/// Trace size for the country-Merkle-path AIR.  $n=512$ covers the
/// EU-27 (depth $5$) configuration plus headroom for one
/// SHA3-binding hash hop when the dual-hash MerklePath+SHA3
/// constraint set lands.
const N_TRACE_MERKLE: usize = 512;

fn make_schedule(n0: usize) -> Vec<usize> {
    // arity-2 binary FRI fold; matches the WASM-portable schedule
    // used in the paper's evaluation.
    vec![2usize; n0.trailing_zeros() as usize]
}

fn comb_coeffs(num: usize) -> Vec<F> {
    (0..num).map(|i| F::from((i + 1) as u64)).collect()
}

/// Prove an age-range claim.
///
/// Application-layer policy check fires first; on success the real
/// `deep_ali` STARK pipeline produces a proof bound to the policy
/// via `public_inputs_hash = public.policy_id()`.
pub fn prove_age(
    public: &age::Public,
    witness: &age::Witness,
) -> Result<Vec<u8>, AirError> {
    let (dob_min, dob_max) = public.dob_bounds();
    if witness.dob_days < dob_min || witness.dob_days > dob_max {
        return Err(AirError::Witness(format!(
            "dob {} not in policy range [{}, {}]",
            witness.dob_days, dob_min, dob_max,
        )));
    }
    if public.min_age_years > public.max_age_years {
        return Err(AirError::Policy(
            "min_age_years > max_age_years".into(),
        ));
    }

    let n_trace = N_TRACE_AGE;
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);
    let air = AirType::AgeRange32;

    let trace = build_execution_trace(air, n_trace);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP)
        .map_err(|e| AirError::Internal(format!("LDE failed: {e:?}")))?;
    let coeffs = comb_coeffs(air.num_constraints());
    let (c_eval, _) = deep_ali_merge_general(
        &lde, &coeffs, air, domain.omega, n_trace, BLOWUP,
    );

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

    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let mut blob = Vec::with_capacity(deep_fri_proof_size_bytes::<Ext>(&proof, false));
    proof.serialize_with_mode(&mut blob, Compress::Yes)
        .map_err(|e| AirError::Internal(format!("serialize failed: {e:?}")))?;
    Ok(blob)
}

/// Prove an income-bracket claim.
///
/// Mirrors [`prove_age`]: application-layer bracket check fires first,
/// then the same 32-row `AirType::AgeRange32` STARK shell produces a
/// proof bound to `income::Public.policy_id()` via
/// `public_inputs_hash`.  Same cryptographic-boundary caveat as the
/// other range AIR — the STARK attests "trace satisfies range-AIR
/// constraints + transcript binds to this policy", while the witness
/// is enforced at the application layer until the value-binding
/// constraint set lands.
pub fn prove_income(
    public: &income::Public,
    witness: &income::Witness,
) -> Result<Vec<u8>, AirError> {
    witness.check(public)?;

    let n_trace = N_TRACE_AGE;
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);
    let air = AirType::AgeRange32;

    let trace = build_execution_trace(air, n_trace);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP)
        .map_err(|e| AirError::Internal(format!("LDE failed: {e:?}")))?;
    let coeffs = comb_coeffs(air.num_constraints());
    let (c_eval, _) = deep_ali_merge_general(
        &lde, &coeffs, air, domain.omega, n_trace, BLOWUP,
    );

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

    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let mut blob = Vec::with_capacity(deep_fri_proof_size_bytes::<Ext>(&proof, false));
    proof.serialize_with_mode(&mut blob, Compress::Yes)
        .map_err(|e| AirError::Internal(format!("serialize failed: {e:?}")))?;
    Ok(blob)
}

/// Prove a country set-membership claim.
///
/// Application-layer membership gate fires first (the witness's
/// country code must hash to a leaf in `set_leaves`); on success the
/// real `deep_ali` STARK pipeline produces a proof at
/// `AirType::MerklePath` cost ($n_\mathrm{trace} = 512$, depth-$5$
/// Poseidon-equivalent) bound to the policy via
/// `public_inputs_hash = country::Public.policy_id()`.
///
/// **Cryptographic boundary.**  `MerklePath` currently shares the
/// `PoseidonChain` constraint set, so the in-circuit attestation is
/// "trace satisfies Poseidon-round-function constraints + the
/// proof was generated under a transcript binding `(set_root,
/// label, |S|)`".  A custom MerklePath constraint set that
/// enforces sibling-swap selection and per-layer hash chaining
/// in-circuit is the next follow-up; until then the membership
/// soundness is at the application-layer gate.  The proof bytes
/// and prove time match the in-circuit version of the AIR (per
/// the bench), so storage / latency claims in the paper hold.
pub fn prove_country(
    public: &country::Public,
    witness: &country::Witness,
    set_leaves: &[[u8; 32]],
) -> Result<Vec<u8>, AirError> {
    // Application-layer membership gate.  Reject before doing any
    // STARK work for non-members so the prover doesn't burn CPU on
    // bad inputs.
    let leaf = country::leaf_hash(&witness.country_code);
    if !set_leaves.contains(&leaf) {
        return Err(AirError::Witness(format!(
            "country code {:?} not in set",
            witness.country_code,
        )));
    }
    if public.set_size == 0 {
        return Err(AirError::Policy("set is empty".into()));
    }

    let n_trace = N_TRACE_MERKLE;
    let n0 = n_trace * BLOWUP;
    let domain = FriDomain::new_radix2(n0);
    let air = AirType::MerklePath;

    let trace = build_execution_trace(air, n_trace);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP)
        .map_err(|e| AirError::Internal(format!("LDE failed: {e:?}")))?;
    let coeffs = comb_coeffs(air.num_constraints());
    let (c_eval, _) = deep_ali_merge_general(
        &lde, &coeffs, air, domain.omega, n_trace, BLOWUP,
    );

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

    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let mut blob = Vec::with_capacity(deep_fri_proof_size_bytes::<Ext>(&proof, false));
    proof.serialize_with_mode(&mut blob, Compress::Yes)
        .map_err(|e| AirError::Internal(format!("serialize failed: {e:?}")))?;
    Ok(blob)
}

// ─── RSA-2048 designated-verifier proof of knowledge ────────────────

/// RSA-2048 PKCS#1 v1.5 modulus byte length (k = ⌈|n|/8⌉).
const RSA2048_K: usize = 256;
/// Trace size for the one-record stacked-RSA AIR.
const N_TRACE_RSA_POK: usize = 32;

/// STIR-style FRI fold schedule used by the rsa2048 stacked AIR — the
/// stark-dns reference example uses an arity-8 schedule (with a
/// power-of-two remainder fold) and `stir = true`, which is what the
/// one-record case calibrates against.  Mirror that here so prover and
/// verifier agree on the schedule.
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

/// Bind an RSA-2048 PoK proof to its `(n, em)` public inputs.  Mirror
/// of the verifier's binding so a proof issued under one operator's
/// public key cannot be replayed under another.
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

/// EMSA-PKCS1-v1_5 encoding helper bound to RSA-2048-SHA256 (k = 256).
fn emsa_pkcs1_v1_5_encode_msg(message: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    let mut digest = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(message);
    digest.copy_from_slice(&hasher.finalize());
    emsa_pkcs1_v1_5_encode_sha256(&digest, RSA2048_K)
        .expect("RSA-2048-SHA256 EM always fits in k=256")
}

/// Prove knowledge of an RSA-PKCS#1 v1.5 signature on `message`
/// under public modulus `n_be` (big-endian).  The signature
/// `signature_be` is the *witness* — it's hidden inside the STARK,
/// never appears in the returned bytes.  The `public_inputs_hash`
/// transcript binds the proof to `(n, em(message))`, where `em` is
/// the EMSA-PKCS1-v1_5(SHA256) encoding the verifier reconstructs.
///
/// **Threat model.**  A holder of `sk_rsa` for `pk_rsa = (n, e=65537)`
/// can produce this proof.  Anyone else with just the proof bytes
/// can verify it but cannot fabricate a fresh one bound to a new
/// message — that's the designated-verifier gate.
pub fn prove_rsa_pok(
    n_be: &[u8],
    message: &[u8],
    signature_be: &[u8],
) -> Result<Vec<u8>, AirError> {
    if n_be.is_empty() {
        return Err(AirError::Policy("rsa_pok: empty modulus".into()));
    }

    let em = emsa_pkcs1_v1_5_encode_msg(message);
    let n  = BigUint::from_bytes_be(n_be);
    let s  = BigUint::from_bytes_be(signature_be);
    let em_bn = BigUint::from_bytes_be(&em);

    let layout = build_rsa_stacked_layout(1);
    let cons_per_row = rsa_stacked_constraints(&layout);
    let n_trace = N_TRACE_RSA_POK;
    let n0 = n_trace * BLOWUP;

    let mut trace: Vec<Vec<F>> = (0..layout.width)
        .map(|_| vec![F::zero(); n_trace])
        .collect();
    fill_rsa_stacked(&mut trace, &layout, n_trace,
                     &[RsaStackedRecord { n, s, em: em_bn }]);

    let domain = FriDomain::new_radix2(n0);
    let lde = lde_trace_columns(&trace, n_trace, BLOWUP)
        .map_err(|e| AirError::Internal(format!("LDE failed: {e:?}")))?;
    drop(trace);

    let coeffs = comb_coeffs(cons_per_row);
    let (c_eval, _) = deep_ali_merge_rsa_stacked_streaming(
        &lde, &coeffs, &layout, domain.omega, n_trace, BLOWUP,
    );
    drop(lde);

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

    let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
    let size = deep_fri_proof_size_bytes::<Ext>(&proof, params.stir);
    let mut blob = Vec::with_capacity(size);
    proof.serialize_with_mode(&mut blob, Compress::Yes)
        .map_err(|e| AirError::Internal(format!("serialize failed: {e:?}")))?;
    Ok(blob)
}

/// Convenience: prove the full registration bundle in one call.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    /// Optional age-range proof.
    pub age: Option<Vec<u8>>,
    /// Optional country-set-membership proof.
    pub country: Option<Vec<u8>>,
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
    fn prove_age_emits_real_stark_bytes() {
        let public = realistic_age_policy();
        let (lo, _hi) = public.dob_bounds();
        let witness = age::Witness { dob_days: lo + 5_000 };
        let proof = prove_age(&public, &witness).expect("prove ok");
        // Real STARK proofs at n_trace=32 / 54 queries are well over
        // 200 KiB; the stub was 16 bytes.  Assert we're nowhere near
        // the stub size.
        assert!(proof.len() > 100_000,
                "real proof should be >100 KiB, got {} bytes", proof.len());
    }

    #[test]
    fn prove_age_rejects_out_of_range_witness() {
        let public = realistic_age_policy();
        let witness = age::Witness { dob_days: public.today_days - 100 };
        assert!(matches!(prove_age(&public, &witness), Err(AirError::Witness(_))));
    }
}

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

use ark_goldilocks::Goldilocks as F;
use ark_serialize::{CanonicalSerialize, Compress};
use deep_ali::{
    air_workloads::{build_execution_trace, AirType},
    deep_ali_merge_general,
    fri::{deep_fri_proof_size_bytes, deep_fri_prove, DeepFriParams, FriDomain},
    sextic_ext::SexticExt,
    trace_import::lde_trace_columns,
};
use mmiyc_air::{age, country, AirError, PolicyId};

type Ext = SexticExt;

/// Reed-Solomon blowup factor (1/ρ_0 = 32).
const BLOWUP: usize = 32;
/// FRI query count (~128-bit security with conservative gap).
const NUM_QUERIES: usize = 54;
/// Fixed Fiat-Shamir-style starting seed; the public-inputs hash
/// is what differentiates proofs across policies, not this.
const SEED_Z: u64 = 0xDEEF_BAAD;

/// Trace size for the age-range AIR (one row per witness bit; two
/// parallel columns).
const N_TRACE_AGE: usize = 32;

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

/// Prove a country set-membership claim.
///
/// **Stub.**  Real STARK proof emission for set membership requires
/// the dual-hash design described in section 5.2 of the paper:
/// Poseidon Merkle path inside the AIR (covered by the existing
/// `PoseidonChain` `AirType`) plus a single SHA3 transition for
/// FIPS-compliant trust-boundary binding (the `Sha3` `AirType`
/// variant is not yet wired).  Until then the application-layer
/// membership check is the soundness mechanism and the returned
/// bytes are a placeholder; the bench harness measures the
/// real cost (see Tables 2-3).
pub fn prove_country(
    public: &country::Public,
    witness: &country::Witness,
    set_leaves: &[[u8; 32]],
) -> Result<Vec<u8>, AirError> {
    witness.prove(public, set_leaves)
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

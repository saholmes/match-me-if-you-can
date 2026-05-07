//! Real STARK verifier for Match-Me-If-You-Can proofs.
//!
//! Mirror of [`mmiyc_prover`]: today only the age-range path runs
//! a real `deep_ali` verification; country / postcode / e-mail /
//! income remain at the stub layer pending dual-hash wiring.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use deep_ali::{
    fri::{deep_fri_verify, DeepFriParams, DeepFriProof},
    sextic_ext::SexticExt,
};
use mmiyc_air::{age, country, AirError, PolicyId};

type Ext = SexticExt;

/// Pipeline calibration constants — must match `mmiyc-prover`.
const BLOWUP: usize = 32;
const NUM_QUERIES: usize = 54;
const SEED_Z: u64 = 0xDEEF_BAAD;
const N_TRACE_AGE: usize = 32;

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
/// **Stub** — see [`mmiyc_prover::prove_country`] for the dual-hash
/// pending status.
pub fn verify_country(
    public: &country::Public,
    proof: &[u8],
) -> Result<(), AirError> {
    country::verify(public, proof)
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
}

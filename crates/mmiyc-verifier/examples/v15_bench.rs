//! Server-side prove + verify timing for v1, v1.5, v1.7 ML-DSA-STARK.
//!
//! Native release-mode numbers — apples-to-apples for B2B / server
//! verifiers.  Browser WASM verify on the same machine is typically
//! ~1.5–3× slower than native.

fn main() {
    use ml_dsa::{KeyGen, signature::{Keypair as _, SignatureEncoding as _, Signer as _}};
    use getrandom::{rand_core::UnwrapErr, SysRng};

    // Pick the rustcrypto scheme matching the active mmiyc-verifier feature.
    #[cfg(feature = "mldsa-44")]
    use ml_dsa::MlDsa44 as ActiveScheme;
    #[cfg(feature = "mldsa-65")]
    use ml_dsa::MlDsa65 as ActiveScheme;
    #[cfg(feature = "mldsa-87")]
    use ml_dsa::MlDsa87 as ActiveScheme;
    #[cfg(not(any(feature = "mldsa-44", feature = "mldsa-65", feature = "mldsa-87")))]
    use ml_dsa::MlDsa44 as ActiveScheme;

    eprintln!("active scheme: {} ({} bytes pk / {} bytes sig)",
        deep_ali::ml_dsa::params::SCHEME_NAME,
        deep_ali::ml_dsa::params::PUBLIC_KEY_BYTES,
        deep_ali::ml_dsa::params::SIGNATURE_BYTES,
    );
    eprintln!("STARK level: NIST L{} (sha3-{}, NUM_QUERIES = {})",
        deep_ali::stark_level::NIST_LEVEL,
        deep_ali::stark_level::COLLISION_BITS,
        deep_ali::stark_level::NUM_QUERIES_LEVEL,
    );

    let message: &[u8] = b"v15-bench-message";
    let mut rng = UnwrapErr(SysRng);
    let kp = <ActiveScheme as KeyGen>::key_gen(&mut rng);
    let pk_arr = kp.verifying_key().encode();
    let pk_slice: &[u8] = pk_arr.as_ref();
    let pk_bytes = pk_slice.to_vec();
    let sig: ml_dsa::Signature<ActiveScheme> = kp.sign(message);
    let sig_arr = sig.to_bytes();
    let sig_slice: &[u8] = sig_arr.as_ref();
    let sig_bytes = sig_slice.to_vec();

    eprintln!("=== prove (release, 3 runs each) ===");

    let mut proof_v1 = vec![];
    let mut proof_v15 = vec![];
    let mut proof_v17 = vec![];

    for run in 1..=3 {
        let t0 = std::time::Instant::now();
        proof_v1 = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_signature_pok(
            &pk_bytes, message, &sig_bytes,
        ).expect("v1 prove");
        let dt1 = t0.elapsed();

        let t0 = std::time::Instant::now();
        proof_v15 = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_signature_pok_v15(
            &pk_bytes, message, &sig_bytes,
        ).expect("v1.5 prove");
        let dt15 = t0.elapsed();

        let t0 = std::time::Instant::now();
        proof_v17 = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_signature_pok_v17(
            &pk_bytes, message, &sig_bytes,
        ).expect("v1.7 prove");
        let dt17 = t0.elapsed();

        eprintln!("run {}: v1 {:.2?}  v1.5 {:.2?}  v1.7 {:.2?}", run, dt1, dt15, dt17);
    }
    eprintln!("proof sizes: v1 = {} B   v1.5 = {} B   v1.7 = {} B",
        proof_v1.len(), proof_v15.len(), proof_v17.len());

    eprintln!("\n=== verify (release, 10 runs each) ===");

    let mut v1_t = vec![];
    let mut v15_t = vec![];
    let mut v17_t = vec![];
    for _ in 0..10 {
        let t0 = std::time::Instant::now();
        mmiyc_verifier::ml_dsa_pok::verify_ml_dsa_signature_pok(
            &pk_bytes, message, &sig_bytes, &proof_v1,
        ).expect("v1 verify");
        v1_t.push(t0.elapsed());

        let t0 = std::time::Instant::now();
        mmiyc_verifier::ml_dsa_pok::verify_ml_dsa_signature_pok_v15(
            &pk_bytes, message, &sig_bytes, &proof_v15,
        ).expect("v1.5 verify");
        v15_t.push(t0.elapsed());

        let t0 = std::time::Instant::now();
        mmiyc_verifier::ml_dsa_pok::verify_ml_dsa_signature_pok_v17(
            &pk_bytes, message, &sig_bytes, &proof_v17,
        ).expect("v1.7 verify");
        v17_t.push(t0.elapsed());
    }

    fn stats(label: &str, ts: &[std::time::Duration]) {
        let mut ms: Vec<f64> = ts.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
        ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mean = ms.iter().sum::<f64>() / ms.len() as f64;
        let min = ms.first().unwrap();
        let max = ms.last().unwrap();
        let median = ms[ms.len() / 2];
        eprintln!("  {}: mean={:.2}ms median={:.2}ms min={:.2}ms max={:.2}ms",
            label, mean, median, min, max);
    }
    stats("v1   ", &v1_t);
    stats("v1.5 ", &v15_t);
    stats("v1.7 ", &v17_t);
}

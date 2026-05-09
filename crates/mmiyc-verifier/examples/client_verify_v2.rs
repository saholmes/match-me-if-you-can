//! Demo client: read a `/verify/income/ml_dsa_v2` JSON response from
//! disk and run the full client-side trust path:
//!   1. native ML-DSA-N verify (Layer-1 sanity check)
//!   2. native v2 STARK PoK verify (Layer-1-free soundness gate)
//!
//! Pairs with `scripts/run-demo.sh`.  Reads the JSON path from argv[1]
//! (default `/tmp/mmiyc-v2-resp.json`).

fn main() -> anyhow::Result<()> {
    use std::time::Instant;

    let path = std::env::args().nth(1)
        .unwrap_or_else(|| "/tmp/mmiyc-v2-resp.json".into());
    eprintln!("[client] reading verify response: {path}");
    let bytes = std::fs::read(&path)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;

    if v["verified"] != serde_json::json!(true) {
        anyhow::bail!("server reported verified=false on income proof");
    }
    let pk_hex  = v["ml_dsa_pk_hex"].as_str().ok_or_else(|| anyhow::anyhow!("ml_dsa_pk_hex"))?;
    let msg_hex = v["signed_message_hex"].as_str().ok_or_else(|| anyhow::anyhow!("signed_message_hex"))?;
    let sig_hex = v["sig_hex"].as_str().ok_or_else(|| anyhow::anyhow!("sig_hex"))?;
    let pok_hex = v["proof_pok_hex"].as_str().ok_or_else(|| anyhow::anyhow!("proof_pok_hex"))?;

    let pk  = hex::decode(pk_hex)?;
    let msg = hex::decode(msg_hex)?;
    let sig = hex::decode(sig_hex)?;
    let pok = hex::decode(pok_hex)?;
    eprintln!(
        "[client] active scheme: {} (NIST L{}, sha3-{}, r={})",
        deep_ali::ml_dsa::params::SCHEME_NAME,
        deep_ali::stark_level::NIST_LEVEL,
        deep_ali::stark_level::COLLISION_BITS,
        deep_ali::stark_level::NUM_QUERIES_LEVEL,
    );
    eprintln!(
        "[client] pk={} B  msg={} B  sig={} B  pok={:.2} MiB",
        pk.len(), msg.len(), sig.len(),
        pok.len() as f64 / (1024.0 * 1024.0),
    );
    assert_eq!(pk.len(),  deep_ali::ml_dsa::params::PUBLIC_KEY_BYTES);
    assert_eq!(sig.len(), deep_ali::ml_dsa::params::SIGNATURE_BYTES);

    eprintln!("[client] step 1/2: native ML-DSA verify (Layer-1 sanity)…");
    let t0 = Instant::now();
    {
        use ml_dsa::{
            EncodedSignature, EncodedVerifyingKey, VerifyingKey,
            signature::Verifier as _,
        };
        // Active scheme matches the workspace `mldsa-N` Cargo feature.
        #[cfg(feature = "mldsa-44")] type Active = ml_dsa::MlDsa44;
        #[cfg(feature = "mldsa-65")] type Active = ml_dsa::MlDsa65;
        #[cfg(feature = "mldsa-87")] type Active = ml_dsa::MlDsa87;
        #[cfg(not(any(feature = "mldsa-44", feature = "mldsa-65", feature = "mldsa-87")))]
        type Active = ml_dsa::MlDsa65;

        let pk_arr  = EncodedVerifyingKey::<Active>::try_from(&pk[..])
            .map_err(|e| anyhow::anyhow!("encode pk: {e:?}"))?;
        let sig_arr = EncodedSignature::<Active>::try_from(&sig[..])
            .map_err(|e| anyhow::anyhow!("encode sig: {e:?}"))?;
        let vk  = VerifyingKey::<Active>::decode(&pk_arr);
        let sig = ml_dsa::Signature::<Active>::decode(&sig_arr)
            .ok_or_else(|| anyhow::anyhow!("decode sig"))?;
        vk.verify(&msg, &sig)
            .map_err(|e| anyhow::anyhow!("native ML-DSA verify failed: {e:?}"))?;
    }
    eprintln!("[client] native ML-DSA verify OK in {:.1} ms", t0.elapsed().as_secs_f64() * 1000.0);

    eprintln!("[client] step 2/2: native v2 STARK PoK verify (Layer-1-free)…");
    let t0 = Instant::now();
    mmiyc_verifier::ml_dsa_pok::verify_ml_dsa_signature_pok_v2(&pk, &msg, &sig, &pok)
        .map_err(|e| anyhow::anyhow!("v2 STARK verify error: {e:?}"))?;
    let dt = t0.elapsed();
    eprintln!("[client] v2 STARK PoK verify OK in {:.1} ms", dt.as_secs_f64() * 1000.0);
    println!("DEMO OK");
    Ok(())
}

//! Browser-side STARK prover bindings.
//!
//! The browser loads `mmiyc_wasm_bg.wasm` + `mmiyc_wasm.js` (post-
//! processed by `wasm-bindgen`) and calls [`prove_age_in_browser`]
//! to generate a real STARK proof on the client.  The function
//! returns a JS object with `{prove_ms, proof_bytes_hex, byte_len}`.
//!
//! This is the Phase-2 client-side prover discussed in §6.2 of
//! the paper.  Same constraint set as `mmiyc_prover::prove_age`,
//! same `public_inputs_hash` policy binding — the only difference
//! is where the prove() call runs.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

use mmiyc_air::{age, country, income, PolicyId};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Result returned to JS.  Defined as a struct (rather than a
/// `serde_json::json!` value) so `serde_wasm_bindgen::to_value` emits
/// a plain JS object — `serde_json::Value::Object` would otherwise be
/// serialised as a JS `Map`, and `result.prove_ms` would be `undefined`
/// on the JS side.
#[derive(Serialize)]
struct ProveResult {
    prove_ms: f64,
    verify_ms: f64,
    byte_len: usize,
    proof_hex: String,
    policy_id_hex: String,
}

/// Browser-callable wrapper around `mmiyc_prover::prove_age`.
///
/// `today_days`, `min_age_years`, `max_age_years` form the public
/// policy.  `dob_days` is the user's secret.  Returns a JS object:
///
/// ```js
/// {
///   prove_ms:        f64,
///   verify_ms:       f64,        // local sanity verify
///   byte_len:        u32,
///   proof_hex:       string,     // serialized proof, hex-encoded
///   policy_id_hex:   string,     // 32-byte SHA3 policy commitment
/// }
/// ```
///
/// The hex encoding makes the proof JSON-friendly for posting to
/// the server's /register endpoint.  The policy_id is included so
/// the JS code can verify the binding it was issued against.
#[wasm_bindgen]
pub fn prove_age_in_browser(
    today_days: u32,
    min_age_years: u8,
    max_age_years: u8,
    dob_days: u32,
) -> Result<JsValue, JsValue> {
    let public = age::Public {
        today_days,
        min_age_years,
        max_age_years,
    };
    let witness = age::Witness { dob_days };

    let t0 = web_sys_now();
    let proof = mmiyc_prover::prove_age(&public, &witness)
        .map_err(|e| JsValue::from_str(&format!("prove_age: {e}")))?;
    let prove_ms = web_sys_now() - t0;

    // Local sanity verify so the JS side knows the proof is well-formed
    // before paying the upload cost.  Same code path the server runs
    // server-side at /verify/age.
    let t0 = web_sys_now();
    mmiyc_verifier::verify_age(&public, &proof)
        .map_err(|e| JsValue::from_str(&format!("local verify: {e}")))?;
    let verify_ms = web_sys_now() - t0;

    let pid = public.policy_id();
    let pid_hex: String = pid.iter().map(|b| format!("{b:02x}")).collect();
    let proof_hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();

    let out = ProveResult {
        prove_ms,
        verify_ms,
        byte_len: proof.len(),
        proof_hex,
        policy_id_hex: pid_hex,
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("to_value: {e}")))
}

/// Browser-callable wrapper around `mmiyc_prover::prove_country`,
/// pinned to the deployment's default EU-27 set policy.  The
/// witness is the user's ISO-3166 alpha-2 country code; on
/// success returns the same `ProveResult` shape as
/// [`prove_age_in_browser`].  Application-layer membership gate
/// fires before any STARK work, so non-EU codes are rejected
/// without burning prover CPU.
#[wasm_bindgen]
pub fn prove_country_in_browser(country_code: String) -> Result<JsValue, JsValue> {
    let (public, leaves) = country::eu_27_policy();
    let witness = country::Witness { country_code };

    let t0 = web_sys_now();
    let proof = mmiyc_prover::prove_country(&public, &witness, &leaves)
        .map_err(|e| JsValue::from_str(&format!("prove_country: {e}")))?;
    let prove_ms = web_sys_now() - t0;

    let t0 = web_sys_now();
    mmiyc_verifier::verify_country(&public, &proof)
        .map_err(|e| JsValue::from_str(&format!("local verify: {e}")))?;
    let verify_ms = web_sys_now() - t0;

    let pid = public.policy_id();
    let pid_hex: String = pid.iter().map(|b| format!("{b:02x}")).collect();
    let proof_hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();

    let out = ProveResult {
        prove_ms,
        verify_ms,
        byte_len: proof.len(),
        proof_hex,
        policy_id_hex: pid_hex,
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("to_value: {e}")))
}

/// Browser-callable wrapper around `mmiyc_prover::prove_income`,
/// pinned to the deployment's default GBP £25k–£1M bracket policy
/// AND to the operator's RSA-2048 modulus (passed in as `service_n_hex`,
/// fetched from `/service/pubkey` at page load).  Binding the policy
/// to the modulus means a proof issued under one operator's `pk`
/// cannot be replayed under another's — `policy_id` differs, so the
/// STARK transcript binds differently.
///
/// Pass `service_n_hex = ""` (empty string) to skip operator-binding;
/// the tests fixture and unbound flows use that path.
#[wasm_bindgen]
pub fn prove_income_in_browser(
    income_pence: u64,
    service_n_hex: String,
) -> Result<JsValue, JsValue> {
    let n_opt: Option<Vec<u8>> = if service_n_hex.is_empty() {
        None
    } else {
        Some(hex_to_bytes(&service_n_hex)
            .ok_or_else(|| JsValue::from_str("bad hex: service_n_hex"))?)
    };
    let public = income::Public::default_demo_bracket(n_opt);
    let witness = income::Witness { income_pence };

    let t0 = web_sys_now();
    let proof = mmiyc_prover::prove_income(&public, &witness)
        .map_err(|e| JsValue::from_str(&format!("prove_income: {e}")))?;
    let prove_ms = web_sys_now() - t0;

    let t0 = web_sys_now();
    mmiyc_verifier::verify_income(&public, &proof)
        .map_err(|e| JsValue::from_str(&format!("local verify: {e}")))?;
    let verify_ms = web_sys_now() - t0;

    let pid = public.policy_id();
    let pid_hex: String = pid.iter().map(|b| format!("{b:02x}")).collect();
    let proof_hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();

    let out = ProveResult {
        prove_ms,
        verify_ms,
        byte_len: proof.len(),
        proof_hex,
        policy_id_hex: pid_hex,
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("to_value: {e}")))
}

/// Browser-callable wrapper around `mmiyc_verifier::verify_income`.
/// Takes the cleartext STARK proof bytes (hex-encoded) and the
/// operator's modulus (hex-encoded; empty string for unbound).
/// Used by the exfiltration demo to show that a generic verifier
/// accepts a leaked proof — establishing that the STARK itself is
/// real — even when the designated-verifier PoK gate fails.
#[wasm_bindgen]
pub fn verify_income_in_browser(
    proof_hex: String,
    service_n_hex: String,
) -> Result<JsValue, JsValue> {
    let proof = hex_to_bytes(&proof_hex)
        .ok_or_else(|| JsValue::from_str("bad hex: proof_hex"))?;
    let n_opt: Option<Vec<u8>> = if service_n_hex.is_empty() {
        None
    } else {
        Some(hex_to_bytes(&service_n_hex)
            .ok_or_else(|| JsValue::from_str("bad hex: service_n_hex"))?)
    };
    let public = income::Public::default_demo_bracket(n_opt);

    let t0 = web_sys_now();
    let verified = mmiyc_verifier::verify_income(&public, &proof).is_ok();
    let verify_ms = web_sys_now() - t0;

    serde_wasm_bindgen::to_value(&VerifyResult { verified, verify_ms })
        .map_err(|e| JsValue::from_str(&format!("to_value: {e}")))
}

/// Result returned by the RSA-PoK verify wrapper.
#[derive(Serialize)]
struct VerifyResult {
    verified: bool,
    verify_ms: f64,
}

/// Browser-callable wrapper around `mmiyc_verifier::verify_rsa_pok`.
/// Used by the income-verification gate to check the operator's
/// designated-verifier proof of knowledge of `sk_rsa` for `pk_rsa`
/// without leaving the browser.
///
/// Inputs are hex-encoded so the JS side can stream them straight
/// from the `/verify/income/...` JSON response.
#[wasm_bindgen]
pub fn verify_rsa_pok_in_browser(
    n_hex: String,
    message_hex: String,
    proof_hex: String,
) -> Result<JsValue, JsValue> {
    fn decode(label: &str, s: &str) -> Result<Vec<u8>, JsValue> {
        hex_to_bytes(s).ok_or_else(|| JsValue::from_str(&format!("bad hex: {label}")))
    }
    let n_be    = decode("n_hex", &n_hex)?;
    let message = decode("message_hex", &message_hex)?;
    let proof   = decode("proof_hex", &proof_hex)?;

    let t0 = web_sys_now();
    let verified = mmiyc_verifier::verify_rsa_pok(&n_be, &message, &proof).is_ok();
    let verify_ms = web_sys_now() - t0;

    serde_wasm_bindgen::to_value(&VerifyResult { verified, verify_ms })
        .map_err(|e| JsValue::from_str(&format!("to_value: {e}")))
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = match bytes[i]     { b'0'..=b'9' => bytes[i]     - b'0',
                                       b'a'..=b'f' => bytes[i]     - b'a' + 10,
                                       b'A'..=b'F' => bytes[i]     - b'A' + 10,
                                       _ => return None };
        let lo = match bytes[i + 1] { b'0'..=b'9' => bytes[i + 1] - b'0',
                                       b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
                                       b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
                                       _ => return None };
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Wall-clock millisecond timer.  Browser-only (uses
/// `performance.now()`); falls through to a tiny stub on native
/// builds so the crate's `cargo test` still works.
#[cfg(target_arch = "wasm32")]
fn web_sys_now() -> f64 {
    js_sys::Date::now()
}

#[cfg(not(target_arch = "wasm32"))]
fn web_sys_now() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmiyc_air::age;

    /// Sanity test that the function is callable under cargo's
    /// native target — exercises the same code path, just with a
    /// stub timer.  The wasm-bindgen attributes are no-ops outside
    /// `--target wasm32-*`.
    #[test]
    fn native_path_compiles_and_runs() {
        let public = age::Public {
            today_days: 20_000,
            min_age_years: 18,
            max_age_years: 120,
        };
        let (lo, _) = public.dob_bounds();
        // Direct prover call — the wasm-bindgen wrapper expects a
        // browser context (Date.now), so we check only the
        // underlying crate works under the cdylib feature set.
        let proof = mmiyc_prover::prove_age(
            &public,
            &age::Witness { dob_days: lo + 5_000 },
        ).expect("native prove_age must succeed under the cdylib build");
        assert!(proof.len() > 100_000);
    }
}

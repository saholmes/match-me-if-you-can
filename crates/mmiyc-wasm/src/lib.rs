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

use mmiyc_air::age;
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

    use mmiyc_air::PolicyId;
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

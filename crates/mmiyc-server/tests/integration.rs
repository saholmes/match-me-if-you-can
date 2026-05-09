//! End-to-end HTTP integration tests for the unified `/register` and
//! `/verify/*` route surface.
//!
//! Each test boots a fresh router against a per-test tempfile-backed
//! SQLite database and drives requests through the router via
//! `tower::ServiceExt::oneshot`, which avoids binding to a real port.
//! The test therefore exercises the full middleware + handler stack
//! (CORS, JSON deserialisation, error mapping, DB layer) in-process.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use mmiyc_server::{db, router::build_router, AppState, Scenario};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tempfile::NamedTempFile;
use tower::ServiceExt;

/// Build a router + a tempfile-backed pool.  The tempfile is leaked
/// for the lifetime of the test (we keep the handle around) so the
/// SQLite file isn't deleted out from under the running pool.
/// `rsa_secret_key` is `None` here — these tests don't exercise the
/// `/verify/income/:id` gate, so we skip the slow RSA-2048 keygen.
async fn fixture(scenario: Scenario) -> (Router, SqlitePool, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let url = format!("sqlite:{}?mode=rwc", f.path().display());
    let pool = SqlitePool::connect(&url).await.expect("open sqlite");
    db::init_schemas(&pool).await.expect("init schemas");
    let state = AppState {
        pool: pool.clone(),
        scenario,
        rsa_secret_key: None,
    };
    let router = build_router(state, None);
    (router, pool, f)
}

/// Today as days-since-epoch, mirroring what the server computes.
fn today_days() -> u32 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    (secs / 86_400) as u32
}

/// dob_days for someone aged exactly `years_ago` years today.
fn dob_for_age(years_ago: u32) -> u32 {
    today_days().saturating_sub(years_ago * 365)
}

/// Adult-EU body that should pass both proofs in the Proofs scenario
/// and verify cleanly in the PII scenario.
fn adult_eu_body() -> Value {
    json!({
        "dob_days":     dob_for_age(30),
        "country_code": "DE",
        "postcode":     "10115",
        "email":        "alice@example.com",
        "income_pence": 4_500_000u64,
        "sex":          "F",
    })
}

async fn post_register(router: &Router, body: &Value) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    ).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

async fn get_verify(router: &Router, kind: &str, user_id: &str) -> StatusCode {
    router.clone().oneshot(
        Request::builder()
            .method("GET")
            .uri(format!("/verify/{kind}/{user_id}"))
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap().status()
}

// ─── /healthz ────────────────────────────────────────────────────

#[tokio::test]
async fn healthz_returns_ok() {
    let (router, _pool, _f) = fixture(Scenario::Proofs).await;
    let resp = router.oneshot(
        Request::builder().uri("/healthz").body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64).await.unwrap();
    assert_eq!(&bytes[..], b"ok");
}

// ─── Proofs scenario ────────────────────────────────────────────

#[tokio::test]
async fn proofs_register_then_verify_roundtrip() {
    let (router, pool, _f) = fixture(Scenario::Proofs).await;
    let (status, body) = post_register(&router, &adult_eu_body()).await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    assert_eq!(body["scenario"], "proofs");
    assert!(body["age_proof_bytes"].as_u64().unwrap() > 0);
    assert!(body["country_proof_bytes"].as_u64().unwrap() > 0);

    let user_id = body["user_id"].as_str().unwrap().to_string();
    assert_eq!(get_verify(&router, "age", &user_id).await,     StatusCode::NO_CONTENT);
    assert_eq!(get_verify(&router, "country", &user_id).await, StatusCode::NO_CONTENT);

    // The proofs row must NOT contain DOB / country / email columns.
    // (Schema enforces this.)  Sanity-check that the proof bytes and
    // the policy-replay JSON were both persisted.
    let row = db::fetch_proofs(&pool, &user_id).await.unwrap()
        .expect("row should exist");
    assert!(row.age_proof.unwrap().len() > 0);
    assert!(row.country_proof.unwrap().len() > 0);
    assert!(row.age_policy_json.unwrap().contains("min_age_years"));
    assert!(row.country_policy_json.unwrap().contains("set_root"));
    assert!(row.email_hash.unwrap().len() == 32, "SHA3-256 hash is 32 bytes");

    // No PII row ever written under this scenario.
    assert_eq!(db::count_rows_pii(&pool).await.unwrap(), 0);
}

#[tokio::test]
async fn proofs_register_under_18_returns_400() {
    let (router, pool, _f) = fixture(Scenario::Proofs).await;
    let mut body = adult_eu_body();
    body["dob_days"] = json!(dob_for_age(5)); // a 5-year-old
    let (status, _) = post_register(&router, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(db::count_rows_proofs(&pool).await.unwrap(), 0,
               "no row should be persisted on a failed proof");
}

#[tokio::test]
async fn proofs_register_non_eu_returns_400() {
    let (router, pool, _f) = fixture(Scenario::Proofs).await;
    let mut body = adult_eu_body();
    body["country_code"] = json!("US"); // ∉ EU27
    let (status, _) = post_register(&router, &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(db::count_rows_proofs(&pool).await.unwrap(), 0,
               "no row should be persisted on a failed proof");
}

#[tokio::test]
async fn proofs_verify_unknown_user_returns_404() {
    let (router, _pool, _f) = fixture(Scenario::Proofs).await;
    let id = "deadbeef00000000deadbeef";
    assert_eq!(get_verify(&router, "age", id).await,     StatusCode::NOT_FOUND);
    assert_eq!(get_verify(&router, "country", id).await, StatusCode::NOT_FOUND);
}

// ─── PII scenario ────────────────────────────────────────────────

#[tokio::test]
async fn pii_register_persists_attributes_verbatim() {
    // The whole point of the baseline scenario: a breach leaks the
    // full quasi-identifier tuple.  This test pins exactly what a
    // breach would expose by reading it back from the DB.
    let (router, pool, _f) = fixture(Scenario::Pii).await;
    let body = adult_eu_body();
    let (status, resp) = post_register(&router, &body).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(resp["scenario"], "pii");
    // No proof byte counts in PII responses.
    assert!(resp["age_proof_bytes"].is_null());
    assert!(resp["country_proof_bytes"].is_null());

    let user_id = resp["user_id"].as_str().unwrap().to_string();
    let row = db::fetch_pii(&pool, &user_id).await.unwrap()
        .expect("row should exist");
    assert_eq!(row.dob_days as u32,    body["dob_days"].as_u64().unwrap() as u32);
    assert_eq!(row.country_code,       "DE");
    assert_eq!(row.postcode.as_deref(), Some("10115"));
    assert_eq!(row.email,              "alice@example.com");
    assert_eq!(row.income_pence,       4_500_000);
    assert_eq!(row.sex,                "F");

    // Both verifies pass: adult and EU citizen.
    assert_eq!(get_verify(&router, "age",     &user_id).await, StatusCode::NO_CONTENT);
    assert_eq!(get_verify(&router, "country", &user_id).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn pii_under_18_registers_then_verify_age_unauthorised() {
    // Critical asymmetry: in the PII scenario, registration accepts
    // anyone (it's just a row insert) and the policy is enforced at
    // /verify time.  In the Proofs scenario, the same input would be
    // rejected at registration because the prover refuses.
    let (router, _pool, _f) = fixture(Scenario::Pii).await;
    let mut body = adult_eu_body();
    body["dob_days"] = json!(dob_for_age(5));
    let (status, resp) = post_register(&router, &body).await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = resp["user_id"].as_str().unwrap().to_string();
    assert_eq!(get_verify(&router, "age", &user_id).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pii_non_eu_country_verify_country_unauthorised() {
    let (router, _pool, _f) = fixture(Scenario::Pii).await;
    let mut body = adult_eu_body();
    body["country_code"] = json!("US");
    let (status, resp) = post_register(&router, &body).await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = resp["user_id"].as_str().unwrap().to_string();
    assert_eq!(get_verify(&router, "country", &user_id).await, StatusCode::UNAUTHORIZED);
    // Age still passes (the user is an adult).
    assert_eq!(get_verify(&router, "age", &user_id).await,     StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn pii_verify_unknown_user_returns_404() {
    let (router, _pool, _f) = fixture(Scenario::Pii).await;
    let id = "deadbeef00000000deadbeef";
    assert_eq!(get_verify(&router, "age", id).await,     StatusCode::NOT_FOUND);
    assert_eq!(get_verify(&router, "country", id).await, StatusCode::NOT_FOUND);
}

// ─── /service/scheme ─────────────────────────────────────────────

#[tokio::test]
async fn service_scheme_returns_active_metadata() {
    // Confirms the `/service/scheme` endpoint returns scheme name,
    // NIST level, and byte counts that match what the active
    // (mldsa-N, sha3-N) Cargo feature pair selects.  Replaces the
    // previously-hardcoded "ML-DSA-44 / 1,312 B / 2,420 B" strings
    // in the frontend.
    let (router, _pool, _f) = fixture(Scenario::Proofs).await;
    let resp = router.oneshot(
        Request::builder()
            .method("GET")
            .uri("/service/scheme")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).expect("valid JSON");

    // Must have all expected fields.
    let scheme           = body["scheme"].as_str().expect("scheme is a string");
    let nist_level       = body["nist_level"].as_u64().expect("nist_level is a number");
    let public_key_bytes = body["public_key_bytes"].as_u64().expect("public_key_bytes is a number");
    let signature_bytes  = body["signature_bytes"].as_u64().expect("signature_bytes is a number");
    let sha3_hash        = body["sha3_hash"].as_str().expect("sha3_hash is a string");
    let ext_field        = body["ext_field"].as_str().expect("ext_field is a string");
    let num_queries      = body["num_queries"].as_u64().expect("num_queries is a number");

    // Each (mldsa-N, sha3-N) feature pair fixes a specific row in
    // the FIPS 204 / paper Table III matrix; assert against that.
    match scheme {
        "ML-DSA-44" => {
            assert_eq!(nist_level, 1);
            assert_eq!(public_key_bytes, 1312);
            assert_eq!(signature_bytes, 2420);
            assert_eq!(sha3_hash, "SHA3-256");
            assert_eq!(ext_field, "Fp6");
            assert_eq!(num_queries, 54);
        }
        "ML-DSA-65" => {
            assert_eq!(nist_level, 3);
            assert_eq!(public_key_bytes, 1952);
            assert_eq!(signature_bytes, 3309);
            assert_eq!(sha3_hash, "SHA3-384");
            assert_eq!(ext_field, "Fp6");
            assert_eq!(num_queries, 79);
        }
        "ML-DSA-87" => {
            assert_eq!(nist_level, 5);
            assert_eq!(public_key_bytes, 2592);
            assert_eq!(signature_bytes, 4627);
            assert_eq!(sha3_hash, "SHA3-512");
            assert_eq!(ext_field, "Fp8");
            assert_eq!(num_queries, 105);
        }
        other => panic!("unexpected scheme: {other}"),
    }
}

#[tokio::test]
async fn service_scheme_works_in_pii_scenario_too() {
    // /service/scheme has no scenario gating; it exposes build-
    // time metadata only.  Confirm it responds the same way under
    // the PII fixture.
    let (router, _pool, _f) = fixture(Scenario::Pii).await;
    let resp = router.oneshot(
        Request::builder()
            .method("GET")
            .uri("/service/scheme")
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── /verify/income/ml_dsa_v2/:user_id (slow end-to-end test) ────

/// Full `/verify/income/ml_dsa_v2` round-trip: register an adult-EU
/// user (which runs the income STARK proof) and verify the resulting
/// ML-DSA PoK natively via `mmiyc_verifier::ml_dsa_pok::verify_ml_dsa_signature_pok_v2`.
///
/// This test confirms the v2 plumbing all the way through: register
/// → store income proof → server signs with active ML-DSA key →
/// server runs v2 STARK PoK → client recovers (pk, sig, proof_pok)
/// from JSON → native verify accepts.
///
/// **Slow** (~30–60 s at L1 / ~60–120 s at L3) because the register
/// path does prove_income (RSA-2048 STARK) and the verify response
/// does prove_ml_dsa_signature_pok_v2 (ML-DSA verify circuit STARK).
/// Marked `#[ignore]`; run with `cargo test --release ... v2_round_trip
/// -- --ignored --nocapture` to exercise.
#[tokio::test]
#[ignore]
async fn verify_income_ml_dsa_v2_round_trip() {
    use std::time::Instant;

    let (router, _pool, _f) = fixture(Scenario::Proofs).await;

    eprintln!("[v2-rt] register adult-EU body (this runs the income STARK)…");
    let t0 = Instant::now();
    let (status, body) = post_register(&router, &adult_eu_body()).await;
    eprintln!("[v2-rt] register: {:?} in {:.1}s", status, t0.elapsed().as_secs_f64());
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    let user_id = body["user_id"].as_str().unwrap().to_string();

    // Random 32-byte nonce binds this verify call.
    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);

    eprintln!("[v2-rt] POST /verify/income/ml_dsa_v2 (this runs the v2 ML-DSA PoK STARK)…");
    let t0 = Instant::now();
    let resp = router.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/verify/income/ml_dsa_v2/{}", user_id))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "nonce_hex": nonce_hex }).to_string()))
            .unwrap(),
    ).await.unwrap();
    eprintln!("[v2-rt] verify HTTP: {:?} in {:.1}s", resp.status(), t0.elapsed().as_secs_f64());
    assert_eq!(resp.status(), StatusCode::OK);

    // Body shape: { verified, ml_dsa_pk_hex, signed_message_hex, sig_hex, proof_pok_hex }.
    // The v2 PoK is ~2-6 MiB binary, hex-encoded ~4-12 MiB; the
    // overall JSON can exceed 16 MiB at L3/L5.  Bump the cap to
    // 128 MiB so all 3 NIST PQ Levels fit comfortably.
    let bytes = to_bytes(resp.into_body(), 128 * 1024 * 1024).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert_eq!(v["verified"], json!(true), "income STARK must verify on honest body");
    let pk_hex  = v["ml_dsa_pk_hex"].as_str().expect("ml_dsa_pk_hex");
    let msg_hex = v["signed_message_hex"].as_str().expect("signed_message_hex");
    let sig_hex = v["sig_hex"].as_str().expect("sig_hex");
    let pok_hex = v["proof_pok_hex"].as_str().expect("proof_pok_hex");

    let pk_bytes  = hex::decode(pk_hex).expect("pk hex");
    let msg_bytes = hex::decode(msg_hex).expect("msg hex");
    let sig_bytes = hex::decode(sig_hex).expect("sig hex");
    let pok_bytes = hex::decode(pok_hex).expect("pok hex");

    // Assert byte counts match the active scheme (sourced from
    // /service/scheme to keep the assertion level-aware).
    let scheme_resp = router.oneshot(
        Request::builder().method("GET").uri("/service/scheme")
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    let scheme_bytes = to_bytes(scheme_resp.into_body(), 1024).await.unwrap();
    let scheme: Value = serde_json::from_slice(&scheme_bytes).unwrap();
    let exp_pk  = scheme["public_key_bytes"].as_u64().unwrap() as usize;
    let exp_sig = scheme["signature_bytes"].as_u64().unwrap()  as usize;
    assert_eq!(pk_bytes.len(),  exp_pk,  "pk bytes must match active scheme");
    assert_eq!(sig_bytes.len(), exp_sig, "sig bytes must match active scheme");

    // Native ML-DSA verify (Layer-1 sanity).
    eprintln!("[v2-rt] native ML-DSA verify…");
    mmiyc_server::ml_dsa::verify(&pk_bytes, &msg_bytes, &sig_bytes)
        .expect("native ML-DSA verify must accept the server's signature");

    // STARK PoK verify (the actual Layer-2 binding).
    eprintln!("[v2-rt] verify_ml_dsa_signature_pok_v2 native (this runs FRI verify)…");
    let t0 = Instant::now();
    let result = mmiyc_verifier::ml_dsa_pok::verify_ml_dsa_signature_pok_v2(
        &pk_bytes, &msg_bytes, &sig_bytes, &pok_bytes,
    );
    eprintln!("[v2-rt] STARK verify: {:?} in {:.2}s", result.is_ok(),
              t0.elapsed().as_secs_f64());
    assert!(result.is_ok(),
        "v2 STARK PoK must verify on honest server output: {:?}", result.err());
}

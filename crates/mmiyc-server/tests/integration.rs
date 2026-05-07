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

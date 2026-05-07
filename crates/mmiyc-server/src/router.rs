//! HTTP route surface.
//!
//! ```text
//!   POST /register          { ... }   201 + {"user_id": "..."}
//!   GET  /verify/age/:id              204 if valid, 401 if not
//!   GET  /verify/country/:id          204 / 401
//!   GET  /healthz                     200 "ok"
//! ```
//!
//! The `/register` body shape depends on the active scenario:
//!
//! * **PII**: a [`PiiRegisterRequest`] with raw attributes.
//! * **Proofs**: a [`ProofsRegisterRequest`] with proof bytes
//!   (hex-encoded) and the public-input JSON for each AIR.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use mmiyc_air::{age, country};
use mmiyc_verifier::{verify_age, verify_country};

use crate::{db, AppState, Scenario};

/// Build the application router with all registered routes.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/register", post(register))
        .route("/verify/age/:user_id", get(verify_age_h))
        .route("/verify/country/:user_id", get(verify_country_h))
        .with_state(state)
}

async fn health() -> &'static str { "ok" }

// ─── /register ────────────────────────────────────────────────────

/// PII-scenario registration body.
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
pub struct PiiRegisterRequest {
    pub dob_days:     u32,
    pub country_code: String,
    pub postcode:     Option<String>,
    pub email:        String,
    pub income_pence: u64,
    pub sex:          String,
}

/// Proofs-scenario registration body.  Proof bytes hex-encoded for
/// JSON friendliness; public inputs as JSON-serialised AIR types so
/// the verifier knows what policy to check against.
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
pub struct ProofsRegisterRequest {
    pub age_proof_hex:        String,
    pub age_public:           age::Public,
    pub country_proof_hex:    String,
    pub country_public:       country::Public,
    /// SHA3 of the e-mail, kept separately for login lookup.  The
    /// e-mail value itself is never stored.
    pub email_hash_hex:       String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse { user_id: String }

async fn register(
    State(state): State<AppState>,
    body: String,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let user_id = mint_user_id(&body, now);

    match state.scenario {
        Scenario::Pii => {
            let req: PiiRegisterRequest = serde_json::from_str(&body)
                .map_err(|e| AppError::BadRequest(format!("invalid PII body: {}", e)))?;
            db::insert_pii(&state.pool, &db::PiiRow {
                user_id:      user_id.clone(),
                dob_days:     i64::from(req.dob_days),
                country_code: req.country_code,
                postcode:     req.postcode,
                email:        req.email,
                income_pence: req.income_pence as i64,
                sex:          req.sex,
                created_at:   now,
            }).await.map_err(AppError::Internal)?;
        }

        Scenario::Proofs => {
            let req: ProofsRegisterRequest = serde_json::from_str(&body)
                .map_err(|e| AppError::BadRequest(format!("invalid Proofs body: {}", e)))?;
            // Verify both proofs server-side BEFORE persisting.  This
            // is a sanity-check on the client's prover; the verifier
            // will re-run on every /verify query against the stored
            // bytes anyway.
            let age_proof = hex::decode(&req.age_proof_hex)
                .map_err(|e| AppError::BadRequest(format!("age proof not hex: {}", e)))?;
            let country_proof = hex::decode(&req.country_proof_hex)
                .map_err(|e| AppError::BadRequest(format!("country proof not hex: {}", e)))?;
            verify_age(&req.age_public, &age_proof)
                .map_err(|e| AppError::BadRequest(format!("age proof rejected at registration: {}", e)))?;
            verify_country(&req.country_public, &country_proof)
                .map_err(|e| AppError::BadRequest(format!("country proof rejected at registration: {}", e)))?;
            let email_hash = hex::decode(&req.email_hash_hex)
                .map_err(|e| AppError::BadRequest(format!("email hash not hex: {}", e)))?;
            db::insert_proofs(&state.pool, &db::ProofsRow {
                user_id:             user_id.clone(),
                age_proof:           Some(age_proof),
                age_policy_json:     Some(serde_json::to_string(&req.age_public).unwrap()),
                country_proof:       Some(country_proof),
                country_policy_json: Some(serde_json::to_string(&req.country_public).unwrap()),
                email_hash:          Some(email_hash),
                created_at:          now,
            }).await.map_err(AppError::Internal)?;
        }
    }

    Ok((StatusCode::CREATED, Json(RegisterResponse { user_id })))
}

fn mint_user_id(body: &str, ts: i64) -> String {
    // Stable-ish per-registration ID.  Not security-critical.
    let mut h = Sha3_256::new();
    h.update(b"mmiyc/v1/user_id");
    h.update(ts.to_be_bytes());
    h.update(body.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..12])
}

// ─── /verify/* ────────────────────────────────────────────────────

async fn verify_age_h(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, AppError> {
    match state.scenario {
        Scenario::Pii => {
            // For the PII scenario: re-derive the boolean answer from
            // the stored DOB against a server-side default policy
            // (≥18 years).  In production this would come from a
            // per-deployment policy doc.
            let row = db::fetch_pii(&state.pool, &user_id).await
                .map_err(AppError::Internal)?
                .ok_or(AppError::NotFound)?;
            let today_days = current_days();
            let age_years = today_days.saturating_sub(row.dob_days as u32) / 365;
            if age_years >= 18 { Ok(StatusCode::NO_CONTENT) }
            else { Err(AppError::Unauthorised) }
        }
        Scenario::Proofs => {
            let row = db::fetch_proofs(&state.pool, &user_id).await
                .map_err(AppError::Internal)?
                .ok_or(AppError::NotFound)?;
            let proof = row.age_proof.ok_or_else(|| AppError::BadRequest("no age proof".into()))?;
            let policy_json = row.age_policy_json
                .ok_or_else(|| AppError::BadRequest("no age policy".into()))?;
            let public: age::Public = serde_json::from_str(&policy_json)
                .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
            verify_age(&public, &proof)
                .map_err(|_| AppError::Unauthorised)?;
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

async fn verify_country_h(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, AppError> {
    match state.scenario {
        Scenario::Pii => {
            let row = db::fetch_pii(&state.pool, &user_id).await
                .map_err(AppError::Internal)?
                .ok_or(AppError::NotFound)?;
            // Default policy: country ∈ EU27.  In production this
            // would come from a per-deployment policy doc.
            const EU: &[&str] = &[
                "AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE",
                "GR","HU","IE","IT","LV","LT","LU","MT","NL","PL","PT",
                "RO","SK","SI","ES","SE",
            ];
            if EU.contains(&row.country_code.as_str()) { Ok(StatusCode::NO_CONTENT) }
            else { Err(AppError::Unauthorised) }
        }
        Scenario::Proofs => {
            let row = db::fetch_proofs(&state.pool, &user_id).await
                .map_err(AppError::Internal)?
                .ok_or(AppError::NotFound)?;
            let proof = row.country_proof
                .ok_or_else(|| AppError::BadRequest("no country proof".into()))?;
            let policy_json = row.country_policy_json
                .ok_or_else(|| AppError::BadRequest("no country policy".into()))?;
            let public: country::Public = serde_json::from_str(&policy_json)
                .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
            verify_country(&public, &proof)
                .map_err(|_| AppError::Unauthorised)?;
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

fn current_days() -> u32 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    (secs / 86_400) as u32
}

// ─── error mapping ────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("unauthorised")]
    Unauthorised,
    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match &self {
            AppError::BadRequest(s) => (StatusCode::BAD_REQUEST, s.clone()),
            AppError::NotFound      => (StatusCode::NOT_FOUND,    "not found".into()),
            AppError::Unauthorised  => (StatusCode::UNAUTHORIZED, "unauthorised".into()),
            AppError::Internal(e)   => (StatusCode::INTERNAL_SERVER_ERROR, format!("internal: {e}")),
        };
        (status, msg).into_response()
    }
}

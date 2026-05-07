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
use tower_http::{cors::CorsLayer, services::ServeDir};

use mmiyc_air::{age, country};
use mmiyc_prover::{prove_age, prove_country};
use mmiyc_verifier::{verify_age, verify_country};

use crate::{db, AppState, Scenario};

/// Build the application router with all registered routes.
///
/// `static_dir` is an optional path to a directory of static files
/// to serve at `/` (typically the demo HTML form).  When `None`, no
/// static fallback is registered.
pub fn build_router(state: AppState, static_dir: Option<std::path::PathBuf>) -> Router {
    let mut app = Router::new()
        .route("/healthz", get(health))
        .route("/register", post(register))
        .route("/verify/age/:user_id", get(verify_age_h))
        .route("/verify/country/:user_id", get(verify_country_h))
        .with_state(state);

    if let Some(dir) = static_dir {
        // Mount static files at root, with the API routes above
        // taking precedence (they're registered first).
        app = app.fallback_service(ServeDir::new(dir));
    }

    // Permissive CORS — fine for a research demo.  Tighten in any
    // production deployment.
    app.layer(CorsLayer::permissive())
}

async fn health() -> &'static str { "ok" }

// ─── /register ────────────────────────────────────────────────────

/// Unified registration body.  In both storage scenarios the
/// client submits the raw attribute values; the server's
/// behaviour at `/register` depends on the active scenario:
///
/// * **PII**: persist the attributes verbatim into `users_pii`.
/// * **Proofs**: run the local prover on the attributes against
///   the deployment's policy, persist the resulting proof bytes
///   (plus policy JSON for replay) into `users_proofs`, and
///   discard the attribute values.
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub dob_days:     u32,
    pub country_code: String,
    pub postcode:     Option<String>,
    pub email:        String,
    pub income_pence: u64,
    pub sex:          String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    user_id: String,
    /// Storage scenario the row was persisted under.
    scenario: &'static str,
    /// For the Proofs scenario, the byte counts the server stored —
    /// useful for the live demo's "look how little is leaked" panel.
    age_proof_bytes:     Option<usize>,
    country_proof_bytes: Option<usize>,
}

/// Default deployment policies.  In a production system these
/// would be loaded from a config file; we hardcode them for the
/// demo.
fn default_age_policy() -> age::Public {
    age::Public {
        today_days: current_days(),
        min_age_years: 18,
        max_age_years: 120,
    }
}

fn default_eu_country_policy() -> (country::Public, Vec<[u8; 32]>) {
    const EU_27: &[&str] = &[
        "AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IE",
        "IT","LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","SE",
    ];
    country::build_set(EU_27)
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let body_repr = format!("{}-{}-{}-{}", req.dob_days, req.country_code, req.email, now);
    let user_id = mint_user_id(&body_repr, now);

    let (age_bytes, country_bytes) = match state.scenario {
        Scenario::Pii => {
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
            (None, None)
        }

        Scenario::Proofs => {
            // ----------------------------------------------------------
            // Server-side prover (Phase 1 of the paper).  The raw
            // attributes are present in this function's stack frame
            // for the duration of the proof generation, then dropped.
            // The client-side WASM prover variant of Phase 2 moves
            // this prove() call into the browser; the resulting wire
            // format would carry proof bytes instead of raw values.
            // ----------------------------------------------------------
            let age_pub = default_age_policy();
            let age_w = age::Witness { dob_days: req.dob_days };
            let age_proof = prove_age(&age_pub, &age_w)
                .map_err(|e| AppError::BadRequest(format!("age proof failed: {}", e)))?;

            let (country_pub, country_leaves) = default_eu_country_policy();
            let country_w = country::Witness { country_code: req.country_code.clone() };
            let country_proof = prove_country(&country_pub, &country_w, &country_leaves)
                .map_err(|e| AppError::BadRequest(format!("country proof failed: {}", e)))?;

            let email_hash = {
                let mut h = Sha3_256::new();
                h.update(b"mmiyc/v1/email-hash");
                h.update(req.email.to_lowercase().as_bytes());
                h.finalize().to_vec()
            };

            let age_n = age_proof.len();
            let country_n = country_proof.len();

            db::insert_proofs(&state.pool, &db::ProofsRow {
                user_id:             user_id.clone(),
                age_proof:           Some(age_proof),
                age_policy_json:     Some(serde_json::to_string(&age_pub).unwrap()),
                country_proof:       Some(country_proof),
                country_policy_json: Some(serde_json::to_string(&country_pub).unwrap()),
                email_hash:          Some(email_hash),
                created_at:          now,
            }).await.map_err(AppError::Internal)?;

            (Some(age_n), Some(country_n))
        }
    };

    Ok((StatusCode::CREATED, Json(RegisterResponse {
        user_id,
        scenario: match state.scenario { Scenario::Pii => "pii", Scenario::Proofs => "proofs" },
        age_proof_bytes:     age_bytes,
        country_proof_bytes: country_bytes,
    })))
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

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
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tower_http::{cors::CorsLayer, services::ServeDir};

use mmiyc_air::{age, country, income};
use mmiyc_prover::{prove_age, prove_country, prove_income};
use mmiyc_verifier::{verify_age, verify_country, verify_income};

use crate::{at_rest, db, AppState, Scenario};

/// Build the application router with all registered routes.
///
/// `static_dir` is an optional path to a directory of static files
/// to serve at `/` (typically the demo HTML form).  When `None`, no
/// static fallback is registered.
pub fn build_router(state: AppState, static_dir: Option<std::path::PathBuf>) -> Router {
    // Three Phase-2 proofs hex-encoded run ~2.9 MB; default axum body
    // limit is 2 MB.  Bump to 8 MB so a future bigger AIR (or extra
    // proven attribute) doesn't trip 413 silently.  Tighten later by
    // switching the wire format to base64 or raw bytes.
    const REGISTER_BODY_LIMIT: usize = 8 * 1024 * 1024;

    let mut app = Router::new()
        .route("/healthz", get(health))
        .route(
            "/register",
            post(register).layer(DefaultBodyLimit::max(REGISTER_BODY_LIMIT)),
        )
        .route("/verify/age/:user_id", get(verify_age_h))
        .route("/verify/country/:user_id", get(verify_country_h))
        .route("/verify/income/:user_id", post(verify_income_locked))
        .route("/service/pubkey", get(service_pubkey))
        .route("/service/ml_dsa_pok", post(ml_dsa_pok_demo))
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
    /// Cleartext DOB in days-since-epoch.  Required for the PII
    /// scenario (server stores it verbatim) and for the Phase-1
    /// Proofs path (server proves on the user's behalf).  In the
    /// Phase-2 Proofs path the browser supplies `age_proof_hex`
    /// and `dob_days` may be omitted — the server then never sees
    /// the cleartext DOB even in transit.
    #[serde(default)]
    pub dob_days:     Option<u32>,
    /// Cleartext ISO-3166 alpha-2 country.  Required for the PII
    /// scenario and for the Phase-1 country prove path.  May be
    /// omitted under Phase-2 when `country_proof_hex` carries a
    /// browser-issued proof.
    #[serde(default)]
    pub country_code: Option<String>,
    pub postcode:     Option<String>,
    pub email:        String,
    /// Cleartext income in minor currency units (pence).  Required
    /// for the PII scenario and for the Phase-1 income-prove path.
    /// Omitted under Phase-2 when `income_proof_hex` carries a
    /// browser-issued bracket proof.
    #[serde(default)]
    pub income_pence: Option<u64>,
    pub sex:          String,
    /// Phase-2 (client-side) age proof, hex-encoded.  When present in
    /// the Proofs scenario, the server skips its own prove() call and
    /// just verifies the submitted bytes against the deployment's age
    /// policy.  When absent, the server falls back to Phase-1
    /// behaviour (prove from cleartext `dob_days`).
    #[serde(default)]
    pub age_proof_hex: Option<String>,
    /// Phase-2 country-set-membership proof, hex-encoded.  When
    /// present, server verifies against the deployment's EU-27
    /// policy and skips its own prove().  When absent, the server
    /// falls back to Phase-1 (prove from cleartext `country_code`).
    #[serde(default)]
    pub country_proof_hex: Option<String>,
    /// Phase-2 income-bracket proof, hex-encoded.  When present,
    /// server verifies against the deployment's default GBP £25k–£1M
    /// bracket and skips its own prove().  When absent, the server
    /// falls back to Phase-1 (prove from cleartext `income_pence`).
    #[serde(default)]
    pub income_proof_hex: Option<String>,
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
    income_proof_bytes:  Option<usize>,
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
    country::eu_27_policy()
}

/// Build the live income policy.  Includes the operator's RSA-2048
/// modulus when configured, so a proof issued under one operator's
/// pk cannot verify under another's.  `None` falls through to the
/// unbound default — used by integration tests that don't pay the
/// RSA keygen cost.
fn default_income_policy(state: &AppState) -> income::Public {
    use rsa::traits::PublicKeyParts;
    let n_be = state.rsa_secret_key.as_ref()
        .map(|sk| sk.to_public_key().n().to_bytes_be());
    income::Public::default_demo_bracket(n_be)
}

/// Decrypt an at-rest proof blob if the server has a key; otherwise
/// pass through (the test-fixture path).  Used by `/verify/age`,
/// `/verify/country`, and the income gate to recover the original
/// STARK bytes before running the verifier.
fn decrypt_at_rest(state: &AppState, stored: Vec<u8>) -> Result<Vec<u8>, AppError> {
    if let Some(sk) = state.rsa_secret_key.as_ref() {
        at_rest::decrypt_with(sk, &stored)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("at-rest decrypt: {e}")))
    } else {
        Ok(stored)
    }
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let body_repr = format!(
        "{}-{}-{}-{}",
        req.dob_days.map(|d| d.to_string()).unwrap_or_else(|| "_".into()),
        req.country_code.as_deref().unwrap_or("_"),
        req.email, now,
    );
    let user_id = mint_user_id(&body_repr, now);

    let (age_bytes, country_bytes, income_bytes) = match state.scenario {
        Scenario::Pii => {
            let dob_days = req.dob_days.ok_or_else(|| AppError::BadRequest(
                "dob_days is required under the PII scenario".into(),
            ))?;
            let country_code = req.country_code.ok_or_else(|| AppError::BadRequest(
                "country_code is required under the PII scenario".into(),
            ))?;
            let income_pence = req.income_pence.ok_or_else(|| AppError::BadRequest(
                "income_pence is required under the PII scenario".into(),
            ))?;
            db::insert_pii(&state.pool, &db::PiiRow {
                user_id:      user_id.clone(),
                dob_days:     i64::from(dob_days),
                country_code,
                postcode:     req.postcode,
                email:        req.email,
                income_pence: income_pence as i64,
                sex:          req.sex,
                created_at:   now,
            }).await.map_err(AppError::Internal)?;
            (None, None, None)
        }

        Scenario::Proofs => {
            // ----------------------------------------------------------
            // Age proof: Phase 2 (browser-issued) when the request
            // carries `age_proof_hex`; Phase 1 (server-issued from
            // cleartext) otherwise.  Both paths persist the same
            // bytes in the same column — the only difference is who
            // ran prove().  Verify-on-submit guarantees we never
            // store a malformed or off-policy proof.
            // ----------------------------------------------------------
            let age_pub = default_age_policy();
            let age_proof = match req.age_proof_hex.as_deref() {
                Some(hex) => {
                    let bytes = hex::decode(hex)
                        .map_err(|e| AppError::BadRequest(format!("age_proof_hex: {}", e)))?;
                    verify_age(&age_pub, &bytes)
                        .map_err(|e| AppError::BadRequest(format!("client age proof rejected: {}", e)))?;
                    bytes
                }
                None => {
                    let dob_days = req.dob_days.ok_or_else(|| AppError::BadRequest(
                        "Phase-1 register requires either age_proof_hex or cleartext dob_days".into(),
                    ))?;
                    let age_w = age::Witness { dob_days };
                    prove_age(&age_pub, &age_w)
                        .map_err(|e| AppError::BadRequest(format!("age proof failed: {}", e)))?
                }
            };

            let (country_pub, country_leaves) = default_eu_country_policy();
            let country_proof = match req.country_proof_hex.as_deref() {
                Some(hex) => {
                    let bytes = hex::decode(hex)
                        .map_err(|e| AppError::BadRequest(format!("country_proof_hex: {}", e)))?;
                    verify_country(&country_pub, &bytes)
                        .map_err(|e| AppError::BadRequest(format!("client country proof rejected: {}", e)))?;
                    bytes
                }
                None => {
                    let country_code = req.country_code.clone().ok_or_else(|| AppError::BadRequest(
                        "Phase-1 register requires either country_proof_hex or cleartext country_code".into(),
                    ))?;
                    let country_w = country::Witness { country_code };
                    prove_country(&country_pub, &country_w, &country_leaves)
                        .map_err(|e| AppError::BadRequest(format!("country proof failed: {}", e)))?
                }
            };

            let income_pub = default_income_policy(&state);
            let income_proof = match req.income_proof_hex.as_deref() {
                Some(hex) => {
                    let bytes = hex::decode(hex)
                        .map_err(|e| AppError::BadRequest(format!("income_proof_hex: {}", e)))?;
                    verify_income(&income_pub, &bytes)
                        .map_err(|e| AppError::BadRequest(format!("client income proof rejected: {}", e)))?;
                    bytes
                }
                None => {
                    let income_pence = req.income_pence.ok_or_else(|| AppError::BadRequest(
                        "Phase-1 register requires either income_proof_hex or cleartext income_pence".into(),
                    ))?;
                    let income_w = income::Witness { income_pence };
                    prove_income(&income_pub, &income_w)
                        .map_err(|e| AppError::BadRequest(format!("income proof failed: {}", e)))?
                }
            };

            let email_hash = {
                let mut h = Sha3_256::new();
                h.update(b"mmiyc/v1/email-hash");
                h.update(req.email.to_lowercase().as_bytes());
                h.finalize().to_vec()
            };

            let age_n = age_proof.len();
            let country_n = country_proof.len();
            let income_n = income_proof.len();

            // All three proofs are encrypted at rest under the
            // operator's RSA-2048 public key.  An attacker with the
            // DB but not `sk_rsa` recovers only ciphertext — they
            // can't feed any row to a STARK verifier to learn its
            // truth value.  When no service key is configured (test
            // fixture), proofs fall through to cleartext storage.
            let encrypt = |bytes: Vec<u8>| -> Result<Vec<u8>, AppError> {
                if let Some(sk) = state.rsa_secret_key.as_ref() {
                    at_rest::encrypt_for(&sk.to_public_key(), &bytes)
                        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))
                } else {
                    Ok(bytes)
                }
            };
            let age_blob     = encrypt(age_proof)?;
            let country_blob = encrypt(country_proof)?;
            let income_blob  = encrypt(income_proof)?;

            db::insert_proofs(&state.pool, &db::ProofsRow {
                user_id:             user_id.clone(),
                age_proof:           Some(age_blob),
                age_policy_json:     Some(serde_json::to_string(&age_pub).unwrap()),
                country_proof:       Some(country_blob),
                country_policy_json: Some(serde_json::to_string(&country_pub).unwrap()),
                income_proof:        Some(income_blob),
                income_policy_json:  Some(serde_json::to_string(&income_pub).unwrap()),
                email_hash:          Some(email_hash),
                created_at:          now,
            }).await.map_err(AppError::Internal)?;

            (Some(age_n), Some(country_n), Some(income_n))
        }
    };

    Ok((StatusCode::CREATED, Json(RegisterResponse {
        user_id,
        scenario: match state.scenario { Scenario::Pii => "pii", Scenario::Proofs => "proofs" },
        age_proof_bytes:     age_bytes,
        country_proof_bytes: country_bytes,
        income_proof_bytes:  income_bytes,
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
            let stored = row.age_proof.ok_or_else(|| AppError::BadRequest("no age proof".into()))?;
            let proof = decrypt_at_rest(&state, stored)?;
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

// ─── /service/pubkey ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ServicePubkey {
    /// Hex-encoded RSA-2048 modulus `n` (big-endian).  Together
    /// with the implicit exponent `e = 65537` this is the operator's
    /// public key.  Callers pin this and pass it to
    /// `verify_rsa_pok_in_browser` along with the message to gate
    /// trust on a `/verify/income/:user_id` response.
    n_hex: String,
}

// ─── /service/ml_dsa_pok (demo) ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MlDsaPokDemoRequest {
    /// 32-byte hex nonce; both server and browser derive the same
    /// synthetic NTT-domain inputs from this nonce.
    nonce_hex: String,
}

#[derive(Debug, Serialize)]
struct MlDsaPokDemoResponse {
    /// Hex-encoded FRI proof bytes.
    proof_pok_hex: String,
    /// Server-side prove wall time (informational).
    prove_ms: f64,
    /// Size of the proof bytes (informational).
    proof_bytes: usize,
}

async fn ml_dsa_pok_demo(
    Json(req): Json<MlDsaPokDemoRequest>,
) -> Result<Json<MlDsaPokDemoResponse>, AppError> {
    let nonce_vec = hex::decode(&req.nonce_hex)
        .map_err(|e| AppError::BadRequest(format!("nonce_hex: {e}")))?;
    if nonce_vec.len() != 32 {
        return Err(AppError::BadRequest(format!(
            "nonce must be 32 bytes; got {}", nonce_vec.len()
        )));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_vec);

    let t0 = std::time::Instant::now();
    let (pi, witness) = mmiyc_prover::ml_dsa_pok::synthesise_from_nonce(&nonce);
    let proof = mmiyc_prover::ml_dsa_pok::prove_ml_dsa_pok(&pi, &witness)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("ml-dsa-pok prove: {e}")))?;
    let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;

    Ok(Json(MlDsaPokDemoResponse {
        proof_bytes: proof.len(),
        proof_pok_hex: hex::encode(&proof),
        prove_ms,
    }))
}

async fn service_pubkey(State(state): State<AppState>)
    -> Result<Json<ServicePubkey>, AppError>
{
    use rsa::traits::PublicKeyParts;
    let sk = state.rsa_secret_key.as_ref().ok_or_else(|| AppError::Internal(
        anyhow::anyhow!("server has no rsa secret key configured")
    ))?;
    let n_hex = hex::encode(sk.to_public_key().n().to_bytes_be());
    Ok(Json(ServicePubkey { n_hex }))
}

// ─── /verify/income/:user_id (RSA-STARK designated-verifier gate) ──

/// Caller-chosen random nonce binds each call so a stored response
/// can't be replayed against a different request.
#[derive(Debug, Deserialize)]
struct VerifyIncomeRequest {
    nonce_hex: String,
}

#[derive(Debug, Serialize)]
struct VerifyIncomeResponse {
    /// True iff the stored STARK income proof verified.
    verified: bool,
    /// Hex-encoded RSA-2048 modulus (echoed for caller convenience).
    service_n_hex: String,
    /// `SHA3-256(b"mmiyc/v1/verify-income-rsa-binding" ‖ nonce ‖
    ///           proof_bytes ‖ policy_json)` — the message the
    /// server signs.  Caller reconstructs this independently and
    /// passes it to `verify_rsa_pok` along with `proof_pok_hex`.
    signed_message_hex: Option<String>,
    /// RSA-2048 STARK PoK proof: a Fiat-Shamir NIZK that the
    /// server holds `sk_rsa` for `pk_rsa = (n, 65537)` AND signed
    /// `signed_message`.  The signature itself is the *witness*
    /// inside the STARK — never appears on the wire.  Returned
    /// **only** when `verified` is true; otherwise `null` — the
    /// gate's "returns nil" mode.
    proof_pok_hex: Option<String>,
}

async fn verify_income_locked(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<VerifyIncomeRequest>,
) -> Result<Json<VerifyIncomeResponse>, AppError> {
    use rsa::{
        pkcs1v15::SigningKey, signature::{Signer, SignatureEncoding},
        traits::PublicKeyParts,
    };
    use sha2::Sha256;

    let sk = state.rsa_secret_key.as_ref().ok_or_else(|| AppError::Internal(
        anyhow::anyhow!("server has no rsa secret key configured")
    ))?;

    let nonce = hex::decode(&req.nonce_hex)
        .map_err(|e| AppError::BadRequest(format!("nonce_hex: {}", e)))?;

    let row = match state.scenario {
        Scenario::Pii => return Err(AppError::BadRequest(
            "/verify/income/:id is only meaningful under the Proofs scenario".into(),
        )),
        Scenario::Proofs => db::fetch_proofs(&state.pool, &user_id)
            .await.map_err(AppError::Internal)?
            .ok_or(AppError::NotFound)?,
    };
    let stored_blob = row.income_proof
        .ok_or_else(|| AppError::BadRequest("no income proof on record".into()))?;
    let policy_json = row.income_policy_json
        .ok_or_else(|| AppError::BadRequest("no income policy on record".into()))?;
    let public: income::Public = serde_json::from_str(&policy_json)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    // Decrypt the at-rest envelope.  An attacker with the DB but
    // not `sk_rsa` cannot reach this point — they'd see only the
    // RSA-OAEP-wrapped AES-256-GCM blob from `at_rest::encrypt_for`.
    let _ = sk; // sk is used inside decrypt_at_rest via state
    let proof = decrypt_at_rest(&state, stored_blob)?;

    let verified = verify_income(&public, &proof).is_ok();
    let n_hex = hex::encode(sk.to_public_key().n().to_bytes_be());

    if !verified {
        return Ok(Json(VerifyIncomeResponse {
            verified: false,
            service_n_hex: n_hex,
            signed_message_hex: None,
            proof_pok_hex: None,
        }));
    }

    // Bind to (nonce, stark_proof, policy_json) so a replay
    // attempt can't reuse a stored response across requests.
    let signed_message = {
        let mut h = Sha3_256::new();
        h.update(b"mmiyc/v1/verify-income-rsa-binding");
        h.update(&nonce);
        h.update(b"|proof|");
        h.update(&proof);
        h.update(b"|policy|");
        h.update(policy_json.as_bytes());
        h.finalize().to_vec()
    };

    // Sign the message under the operator's RSA-2048 key, then
    // produce a STARK PoK that the signature verifies — the
    // signature itself stays inside the STARK as the witness.
    let signing_key = SigningKey::<Sha256>::new((**sk).clone());
    let sig = signing_key.sign(&signed_message);
    let sig_be = sig.to_bytes().to_vec();
    let n_be = sk.to_public_key().n().to_bytes_be();

    let pok = mmiyc_prover::prove_rsa_pok(&n_be, &signed_message, &sig_be)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("prove_rsa_pok: {e}")))?;

    Ok(Json(VerifyIncomeResponse {
        verified: true,
        service_n_hex: n_hex,
        signed_message_hex: Some(hex::encode(&signed_message)),
        proof_pok_hex: Some(hex::encode(&pok)),
    }))
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
            let stored = row.country_proof
                .ok_or_else(|| AppError::BadRequest("no country proof".into()))?;
            let proof = decrypt_at_rest(&state, stored)?;
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

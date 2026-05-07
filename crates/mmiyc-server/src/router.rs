//! HTTP route surface.
//!
//! ```text
//!   POST /register          { proofs: ProofBundle, public: PublicInputs }
//!   GET  /verify/age/:id    -> 204 No Content   if proof verifies
//!   GET  /verify/country/:id-> 204 No Content   if proof verifies
//!   GET  /healthz           -> 200 OK
//! ```
//!
//! All routes are stub for now — the live wire-up to a real Postgres
//! pool and to the verifier crate happens once the AIRs themselves
//! are no longer placeholder.

use axum::{routing::{get, post}, Router};

/// Build the application router with all registered routes.
pub fn build_router() -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/register", post(register))
        .route("/verify/age/{user_id}", get(verify_age))
        .route("/verify/country/{user_id}", get(verify_country))
}

async fn health() -> &'static str { "ok" }

async fn register() -> &'static str {
    // TODO: deserialise ProofBundle, persist via sqlx, run verifier
    //       in dry-run mode for sanity, return 201 Created.
    "register stub"
}

async fn verify_age() -> &'static str { "verify-age stub" }
async fn verify_country() -> &'static str { "verify-country stub" }

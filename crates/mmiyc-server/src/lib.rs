//! axum HTTP service for Match-Me-If-You-Can.
//!
//! Two scenarios share the same wire format; they differ only in
//! which database table backs the registration.  See
//! [`router::build_router`] for the full route surface.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

pub mod db;
pub mod router;

use std::sync::Arc;

use sqlx::SqlitePool;

/// Server-wide configuration.
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Config {
    /// SQLite database URL.  e.g. ``sqlite:mmiyc.db?mode=rwc``.
    pub database_url: String,
    /// HTTP listen address.
    pub bind_addr: String,
    /// Which scenario to run: PII (baseline) or Proofs (privacy).
    pub scenario: Scenario,
}

/// The two storage scenarios the paper compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Baseline: store PII attributes verbatim (encrypted at rest).
    Pii,
    /// Proposed: store STARK proofs of attribute predicates.
    Proofs,
}

impl Scenario {
    /// Parse from a CLI / env-var string.  Accepts ``pii``,
    /// ``baseline``, ``proofs``, ``privacy`` (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pii" | "baseline"        => Some(Scenario::Pii),
            "proofs" | "privacy" | "p"=> Some(Scenario::Proofs),
            _ => None,
        }
    }
}

/// Application state passed to every axum handler.
#[allow(missing_docs)]
#[derive(Clone)]
pub struct AppState {
    /// Live SQLite pool.
    pub pool: SqlitePool,
    /// Active scenario.
    pub scenario: Scenario,
    /// Service signing key for the income-proof designated-verifier
    /// gate.  Optional so integration tests that don't exercise
    /// `/verify/income/:id` can construct an `AppState` without
    /// paying the ~500 ms RSA-2048 keygen cost; the gate handler
    /// returns 503 when this is `None`.  In production this is
    /// always `Some(...)` (generated at startup, persisted in HSM/
    /// KMS in a real deployment).  Public modulus `n` is published
    /// at `GET /service/pubkey`; the secret never leaves process
    /// memory.
    pub rsa_secret_key: Option<Arc<rsa::RsaPrivateKey>>,
}

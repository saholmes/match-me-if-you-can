//! axum HTTP service for Match-Me-If-You-Can.
//!
//! Two scenarios share the same wire format; they differ only in
//! which database table backs the registration.  See
//! [`router::build_router`] for the full route surface.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

pub mod router;

/// Server-wide configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Database URL (PostgreSQL or SQLite).
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

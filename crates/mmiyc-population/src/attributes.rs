//! User-attribute schema.
//!
//! Mirrors the fields a typical website registration form captures
//! and the paper compares between PII and Proofs storage.

use serde::{Deserialize, Serialize};

/// One synthetic user.  Each attribute is included verbatim so the
/// breach-simulation harness can run linkage attacks against it; the
/// "Proofs" storage scenario derives proof bytes from these values
/// at write-time and discards the values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    /// Stable per-record identifier — opaque to the breach simulation.
    pub user_id: String,
    /// Date of birth, days since the Unix epoch.  Clear text in PII
    /// scenario; not persisted in Proofs scenario.
    pub dob_days: u32,
    /// ISO 3166-1 alpha-2 country code.
    pub country_code: String,
    /// UK outward-code prefix (first one or two letters), or empty
    /// for non-UK records.
    pub postcode_prefix: String,
    /// Lowercase email domain (e.g. "gmail.com").
    pub email_domain: String,
    /// Annual income bracket as integer pence; one of the standard
    /// bracket centres.
    pub income_pence: u64,
    /// Sex code, used by the breach simulation as a quasi-identifier.
    /// "M" / "F" / "X" — kept short on purpose.
    pub sex: String,
}

impl User {
    /// Bytes-on-disk under the "PII" scenario, assuming text
    /// representation in CSV.  Used by the storage cost analysis.
    pub fn pii_csv_bytes(&self) -> usize {
        // user_id + commas + dob (10 chars) + cc (2) + pc (2-4) +
        //   email_domain (variable) + income (12) + sex (1) + newline
        self.user_id.len()
            + 1 + 10
            + 1 + self.country_code.len()
            + 1 + self.postcode_prefix.len()
            + 1 + self.email_domain.len()
            + 1 + 12
            + 1 + self.sex.len()
            + 1
    }
}

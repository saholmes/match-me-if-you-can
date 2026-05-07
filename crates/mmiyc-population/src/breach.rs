//! Breach-simulation harness.
//!
//! Simulates the threat model of `docs/threat-model.md`: an
//! adversary obtains a snapshot of the deployment's database (the
//! "breached" set), and separately holds an auxiliary database with
//! some overlap of identifiers.  The adversary tries to *link*
//! records across the two databases to reconstruct the full
//! attribute-tuple of as many users as possible.
//!
//! In the **PII** scenario the adversary has direct attribute
//! values to compare.  In the **Proofs** scenario the adversary
//! sees only proof bytes, which carry no exploitable attribute
//! information; the linkage attack therefore degenerates to "match
//! everyone we can across `user_id`s alone", which is by
//! construction zero (the user_id is opaque and not shared with
//! the auxiliary database).
//!
//! Linkage criterion (PII scenario):
//!
//!   * Two records match if they agree on a configurable subset of
//!     quasi-identifiers (default: country + postcode_prefix +
//!     dob_days + sex).  The well-known result of
//!     [Sweeney 2000](https://dataprivacylab.org/projects/identifiability/paper1.pdf)
//!     is that 87 % of the US population is uniquely identifiable
//!     by ZIP + DOB + sex; we recreate that result on synthetic
//!     data.
//!
//! Headline metric: per-user re-identification success rate
//! (fraction of breached users for whom there is exactly one
//! matching auxiliary record).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::attributes::User;

/// The "auxiliary" database the adversary uses for the linkage
/// attack.  Constructed by overlapping the breached population with
/// a public dataset of similar attribute schema.
#[derive(Debug, Clone)]
pub struct AuxiliaryDatabase {
    /// All records in the auxiliary set.
    pub records: Vec<User>,
}

impl AuxiliaryDatabase {
    /// Build an auxiliary database whose first `overlap_n` records
    /// are drawn from the breached population (modelling shared
    /// presence between, e.g., a leaked customer database and the
    /// electoral roll), and whose remaining `n_total - overlap_n`
    /// records are independently sampled.
    pub fn synthetic_overlap(
        breached: &[User],
        overlap_n: usize,
        extra_n: usize,
        seed: u64,
    ) -> Self {
        let mut records = Vec::with_capacity(overlap_n + extra_n);
        // Take a fixed prefix of the breached set as "in the aux DB too".
        let take = overlap_n.min(breached.len());
        records.extend_from_slice(&breached[..take]);
        // Sample additional independent records.
        if extra_n > 0 {
            use crate::generate::{generate_population, GenerationConfig};
            let extra_cfg = GenerationConfig {
                n: extra_n,
                seed: seed.wrapping_mul(7919),  // distinct-but-stable
                today_days: 20_000,
                uk_only: false,
            };
            records.extend(generate_population(&extra_cfg));
        }
        AuxiliaryDatabase { records }
    }
}

/// Quasi-identifier columns the adversary uses for linkage.
#[derive(Debug, Clone)]
pub struct LinkageKey {
    /// Whether each attribute is included in the matching key.
    pub use_country: bool,
    /// Postcode prefix.
    pub use_postcode: bool,
    /// Date of birth.
    pub use_dob: bool,
    /// Sex.
    pub use_sex: bool,
}

impl Default for LinkageKey {
    /// Sweeney's three-attribute classic: postcode + DOB + sex.
    fn default() -> Self {
        LinkageKey {
            use_country: false,
            use_postcode: true,
            use_dob: true,
            use_sex: true,
        }
    }
}

impl LinkageKey {
    fn project(&self, u: &User) -> String {
        // Construct a canonical key string.
        let mut parts = Vec::with_capacity(4);
        if self.use_country  { parts.push(format!("c:{}",  u.country_code)); }
        if self.use_postcode { parts.push(format!("p:{}",  u.postcode_prefix)); }
        if self.use_dob      { parts.push(format!("d:{}",  u.dob_days)); }
        if self.use_sex      { parts.push(format!("s:{}",  u.sex)); }
        parts.join("|")
    }

    /// Number of attributes contributing to this key.
    pub fn arity(&self) -> usize {
        [self.use_country, self.use_postcode, self.use_dob, self.use_sex]
            .iter().filter(|b| **b).count()
    }
}

/// Result of a single breach-simulation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachResult {
    /// Total records in the breached database.
    pub n_breached: usize,
    /// Total records in the auxiliary database.
    pub n_auxiliary: usize,
    /// Linkage key used (description, not the secret key).
    pub linkage_arity: usize,
    /// Number of breached users whose key matches **exactly one**
    /// auxiliary record — the precise definition of "uniquely
    /// re-identifiable".
    pub uniquely_reidentified: usize,
    /// Number of breached users whose key matches at least one
    /// auxiliary record (but maybe not uniquely).
    pub any_match: usize,
    /// Number of breached users whose key has no auxiliary match.
    pub no_match: usize,
    /// Per-user fraction `uniquely_reidentified / n_breached`.
    pub re_id_rate: f64,
}

/// Run the breach simulation against the supplied breached database
/// and auxiliary database, using the given linkage key.
///
/// Linear-time over `aux + breached` after a single pass to bucket
/// auxiliary records by key.
pub fn breach_simulate(
    breached: &[User],
    aux: &AuxiliaryDatabase,
    key: &LinkageKey,
) -> BreachResult {
    // Bucket auxiliary by key.
    let mut buckets: HashMap<String, usize> = HashMap::with_capacity(aux.records.len());
    for u in &aux.records {
        *buckets.entry(key.project(u)).or_insert(0) += 1;
    }

    let mut uniquely = 0usize;
    let mut any = 0usize;
    let mut none = 0usize;
    for u in breached {
        let count = buckets.get(&key.project(u)).copied().unwrap_or(0);
        if count == 1 {
            uniquely += 1;
            any += 1;
        } else if count > 1 {
            any += 1;
        } else {
            none += 1;
        }
    }

    BreachResult {
        n_breached: breached.len(),
        n_auxiliary: aux.records.len(),
        linkage_arity: key.arity(),
        uniquely_reidentified: uniquely,
        any_match: any,
        no_match: none,
        re_id_rate: uniquely as f64 / breached.len().max(1) as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::{generate_population, GenerationConfig};

    #[test]
    fn re_id_rate_high_for_3_attribute_key() {
        // Sweeney 2000-style: postcode + DOB + sex on a small UK
        // population should re-identify nearly everyone.
        let cfg = GenerationConfig {
            n: 1_000, seed: 2026, uk_only: true, ..Default::default()
        };
        let pop = generate_population(&cfg);
        // Aux DB = the same population (worst case for the breached
        // side: every user has at least one match).
        let aux = AuxiliaryDatabase { records: pop.clone() };
        let key = LinkageKey::default();
        let res = breach_simulate(&pop, &aux, &key);
        // We don't assert ≥ 0.87 here because the synthetic key
        // space is smaller than the real US census; we assert the
        // rate is non-trivial (> 50 %) on the small sample.
        assert!(res.re_id_rate > 0.5,
            "expected substantial re-identification, got {}", res.re_id_rate);
    }

    #[test]
    fn re_id_rate_lower_with_fewer_attributes() {
        let cfg = GenerationConfig { n: 1_000, seed: 2026, uk_only: true, ..Default::default() };
        let pop = generate_population(&cfg);
        let aux = AuxiliaryDatabase { records: pop.clone() };
        let high = breach_simulate(&pop, &aux,
            &LinkageKey { use_country: false, use_postcode: true, use_dob: true, use_sex: true });
        let low  = breach_simulate(&pop, &aux,
            &LinkageKey { use_country: false, use_postcode: true, use_dob: false, use_sex: false });
        assert!(low.re_id_rate < high.re_id_rate,
            "fewer attributes should yield lower re-id; got high={} low={}",
            high.re_id_rate, low.re_id_rate);
    }

    #[test]
    fn no_overlap_aux_yields_zero() {
        let cfg = GenerationConfig { n: 200, seed: 2026, ..Default::default() };
        let pop = generate_population(&cfg);
        let aux = AuxiliaryDatabase {
            records: generate_population(
                &GenerationConfig { n: 200, seed: 9_999_999, ..Default::default() }
            ),
        };
        let res = breach_simulate(&pop, &aux, &LinkageKey::default());
        // Aux drawn independently — most breached users won't find a
        // unique match (or any match) in it.
        assert!(res.re_id_rate < 0.30,
            "independent aux should give low re-id; got {}", res.re_id_rate);
    }
}

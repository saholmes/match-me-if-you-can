//! Synthetic-user generation with realistic attribute distributions.
//!
//! The distributions are deliberately simple and reproducible — they
//! are *not* a fit to any real-world dataset, but they preserve the
//! statistical structure that makes the breach simulation
//! meaningful: postcode and DOB are uncorrelated and uniformly
//! distributed across their domains, email-domain has a fat-tailed
//! Zipfian, country has a Pareto distribution biased toward the EU,
//! and income is log-normal.

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;

use crate::attributes::User;

/// Population-generation parameters.
#[derive(Debug, Clone)]
pub struct GenerationConfig {
    /// Number of users to produce.
    pub n: usize,
    /// PRNG seed; same seed → same population.
    pub seed: u64,
    /// Today's date, days since the Unix epoch (for age-window calculation).
    pub today_days: u32,
    /// UK-only flag: when true, every user gets a UK postcode prefix
    /// and country=GB.  When false, the country is sampled from the
    /// `COUNTRY_WEIGHTS` table.
    pub uk_only: bool,
}

impl Default for GenerationConfig {
    fn default() -> Self {
        GenerationConfig {
            n:          1_000,
            seed:       2026,
            today_days: 20_000, // ≈ 2024-09; arbitrary fixed reference
            uk_only:    false,
        }
    }
}

/// Generate a synthetic population.
pub fn generate_population(config: &GenerationConfig) -> Vec<User> {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut out = Vec::with_capacity(config.n);
    for i in 0..config.n {
        out.push(generate_user(i, &mut rng, config));
    }
    out
}

fn generate_user(idx: usize, rng: &mut StdRng, cfg: &GenerationConfig) -> User {
    // user_id: 16 hex chars derived from idx + seed for stability.
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&((cfg.seed.wrapping_mul(31) ^ idx as u64).to_be_bytes()));
    let user_id = hex::encode(id_bytes);

    // Age in [18, 80], bell-ish — sample uniformly for now.
    let age_years: u32 = rng.gen_range(18..=80);
    // dob_days = today - age*365 - jitter(0..365)
    let dob_jitter: u32 = rng.gen_range(0..365);
    let dob_days = cfg.today_days
        .saturating_sub(age_years * 365 + dob_jitter);

    // Country.
    let country_code = if cfg.uk_only {
        "GB".to_string()
    } else {
        weighted_pick(rng, COUNTRY_WEIGHTS).to_string()
    };

    // Postcode prefix: UK only.
    let postcode_prefix = if country_code == "GB" {
        UK_POSTCODE_PREFIXES.choose(rng).unwrap().to_string()
    } else {
        String::new()
    };

    // Email domain.
    let email_domain = weighted_pick(rng, EMAIL_DOMAIN_WEIGHTS).to_string();

    // Income — log-normal-ish, in pence, capped at ~£500k.
    let log_mean = 10.5_f64; // log of ~£36k median
    let log_std  = 0.6_f64;
    let z: f64 = rng.gen::<f64>().mul_add(2.0, -1.0); // ~ uniform [-1, 1]
    let income_pounds = (log_mean + log_std * z).exp().min(500_000.0);
    let income_pence = (income_pounds * 100.0) as u64;

    // Sex.
    let sex = ["M", "F", "F", "M", "X"]
        .choose(rng)
        .unwrap()
        .to_string();

    User {
        user_id,
        dob_days,
        country_code,
        postcode_prefix,
        email_domain,
        income_pence,
        sex,
    }
}

fn weighted_pick<'a, R: Rng>(rng: &mut R, items: &'a [(&'a str, u32)]) -> &'a str {
    let total: u32 = items.iter().map(|(_, w)| *w).sum();
    let mut roll = rng.gen_range(0..total);
    for (s, w) in items {
        if roll < *w {
            return s;
        }
        roll -= *w;
    }
    items[0].0
}

// ─── Reference distributions ───────────────────────────────────────

/// Country weights for the breach-simulation default mix.
/// Hand-picked to match a representative European-leaning user
/// population without being overly UK-skewed.
pub const COUNTRY_WEIGHTS: &[(&str, u32)] = &[
    ("GB", 30), ("DE", 15), ("FR", 12), ("IT", 8),  ("ES", 7),
    ("NL", 5),  ("PL", 4),  ("SE", 3),  ("BE", 3),  ("AT", 3),
    ("DK", 2),  ("FI", 2),  ("IE", 2),  ("PT", 2),  ("CZ", 2),
    ("US", 5),  ("CA", 2),  ("AU", 1),  ("JP", 1),  ("CH", 1),
];

/// First two characters of a UK postcode (the "outward code").
/// 50 reasonable picks; the real list has ~120 area codes, but
/// for our breach simulation 50 gives realistic coincidence rates.
pub const UK_POSTCODE_PREFIXES: &[&str] = &[
    "AB", "AL", "B",  "BA", "BB", "BD", "BH", "BL", "BN", "BR",
    "BS", "BT", "CA", "CB", "CF", "CH", "CM", "CO", "CR", "CT",
    "CV", "CW", "DA", "DD", "DE", "DH", "DL", "DN", "DT", "DY",
    "E",  "EC", "EH", "EN", "EX", "FK", "FY", "G",  "GL", "GU",
    "HA", "HD", "HG", "HP", "HR", "HS", "HU", "HX", "IG", "IP",
];

/// Email domain weights, fat-tailed Zipfian.
pub const EMAIL_DOMAIN_WEIGHTS: &[(&str, u32)] = &[
    ("gmail.com",   45),
    ("outlook.com", 18),
    ("yahoo.com",   12),
    ("hotmail.com", 10),
    ("icloud.com",   6),
    ("proton.me",    3),
    ("aol.com",      2),
    ("yandex.com",   1),
    ("zoho.com",     1),
    ("fastmail.com", 1),
    // Long tail of corporate/edu addresses.
    ("nhs.uk",       1),
    ("surrey.ac.uk", 1),
    ("ox.ac.uk",     1),
    ("cam.ac.uk",    1),
    ("mit.edu",      1),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn population_is_deterministic() {
        let cfg = GenerationConfig::default();
        let a = generate_population(&cfg);
        let b = generate_population(&cfg);
        assert_eq!(a, b, "same seed must give same population");
    }

    #[test]
    fn population_is_distinct_under_different_seeds() {
        let mut cfg = GenerationConfig::default();
        cfg.n = 100;
        let a = generate_population(&cfg);
        cfg.seed = 9999;
        let b = generate_population(&cfg);
        assert_ne!(a, b, "different seeds must give different populations");
    }

    #[test]
    fn uk_only_mode_uses_only_gb() {
        let cfg = GenerationConfig {
            n: 200, uk_only: true, ..Default::default()
        };
        let pop = generate_population(&cfg);
        assert!(pop.iter().all(|u| u.country_code == "GB"));
        assert!(pop.iter().all(|u| !u.postcode_prefix.is_empty()));
    }

    #[test]
    fn ages_lie_in_18_to_80_window() {
        let cfg = GenerationConfig { n: 500, ..Default::default() };
        let pop = generate_population(&cfg);
        for u in &pop {
            let age_days = cfg.today_days.saturating_sub(u.dob_days);
            let age_years = age_days / 365;
            assert!((18..=81).contains(&age_years),
                "age {} out of range for user {}", age_years, u.user_id);
        }
    }
}

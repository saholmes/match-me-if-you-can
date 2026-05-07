//! Match-Me-If-You-Can benchmark harness.
//!
//! ```text
//!   mmiyc-bench generate --n 100000 --out data/synthetic-users.csv
//!     -- create N synthetic users with reasonable attribute distributions
//!
//!   mmiyc-bench storage --in data/synthetic-users.csv
//!     -- compare bytes-per-user under PII vs Proofs scenarios
//!
//!   mmiyc-bench breach --in data/synthetic-users.csv \
//!                      --aux-overlap 5000 --aux-extra 50000
//!     -- run linkage-attack re-identification simulation
//!
//!   mmiyc-bench bench --scenario both --n 1000
//!     -- (stub until deep_ali wiring lands)
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use mmiyc_population::{
    attributes::User,
    breach::{breach_simulate, AuxiliaryDatabase, BreachResult, LinkageKey},
    generate::{generate_population, GenerationConfig},
    io::{read_population, write_population},
    regulatory::{
        analyze, sensitivity_breach_probability, sensitivity_per_record_cost,
        RegulatoryParams,
    },
};

#[derive(Parser, Debug)]
#[command(version, about = "Match-Me-If-You-Can benchmark harness")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate N synthetic users with realistic attribute distributions.
    Generate {
        /// Number of users.
        #[arg(long, default_value_t = 1000)]
        n: usize,
        /// PRNG seed (same seed → same population).
        #[arg(long, default_value_t = 2026)]
        seed: u64,
        /// "Today" reference, days since the Unix epoch.
        #[arg(long, default_value_t = 20_000)]
        today_days: u32,
        /// Restrict to UK-only postcodes (helpful for the 3-attribute breach test).
        #[arg(long)]
        uk_only: bool,
        /// Output CSV path.
        #[arg(long, default_value = "data/synthetic-users.csv")]
        out: PathBuf,
    },

    /// Compute storage cost per user under each scenario.
    Storage {
        /// Input CSV from a previous `generate` run.
        #[arg(long, default_value = "data/synthetic-users.csv")]
        input: PathBuf,
        /// Estimated proof bytes per attribute.  Default mirrors a
        /// typical `deep_ali` proof at ~(STARK security) parameters.
        #[arg(long, default_value_t = 6_500)]
        proof_bytes: usize,
        /// Number of distinct attributes proven per user.
        #[arg(long, default_value_t = 2)]
        attributes: usize,
    },

    /// Run breach-simulation re-identification analysis.
    Breach {
        /// Input CSV with the breached population.
        #[arg(long, default_value = "data/synthetic-users.csv")]
        input: PathBuf,
        /// Number of breached records also present in the auxiliary DB.
        #[arg(long, default_value_t = 5_000)]
        aux_overlap: usize,
        /// Independent records added to the auxiliary DB.
        #[arg(long, default_value_t = 50_000)]
        aux_extra: usize,
        /// Auxiliary-DB sampling seed.
        #[arg(long, default_value_t = 9_999)]
        aux_seed: u64,
    },

    /// Translate a breach result into expected GDPR fine differential.
    ///
    /// Runs `breach` internally, then maps the re-identification rate
    /// onto an annual-fine estimate under PII vs Proofs storage.
    Regulatory {
        /// Input CSV with the breached population.
        #[arg(long, default_value = "data/synthetic-users.csv")]
        input: PathBuf,
        /// Number of breached records also present in the auxiliary DB.
        #[arg(long, default_value_t = 5_000)]
        aux_overlap: usize,
        /// Independent records added to the auxiliary DB.
        #[arg(long, default_value_t = 50_000)]
        aux_extra: usize,
        /// Auxiliary-DB sampling seed.
        #[arg(long, default_value_t = 9_999)]
        aux_seed: u64,
        /// Per-year breach probability (default 0.05).
        #[arg(long, default_value_t = 0.05)]
        breach_prob: f64,
        /// GBP fine attributed to each re-identified record (default 130).
        #[arg(long, default_value_t = 130.0)]
        per_record_cost: f64,
        /// Multiplier on the Proofs side; 0.01 by default (99% discount).
        #[arg(long, default_value_t = 0.01)]
        unintelligibility_discount: f64,
    },

    /// (Stub until `deep_ali` wiring lands.)
    Bench {
        #[arg(long, value_enum, default_value_t = ScenarioArg::Both)]
        scenario: ScenarioArg,
        #[arg(long, default_value_t = 1000)]
        n: usize,
    },
}

#[derive(clap::ValueEnum, Debug, Clone)]
enum ScenarioArg { Pii, Proofs, Both }

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Cmd::Generate { n, seed, today_days, uk_only, out } => {
            let cfg = GenerationConfig { n, seed, today_days, uk_only };
            eprintln!("generating {} users (seed={}, uk_only={}) …", n, seed, uk_only);
            let pop = generate_population(&cfg);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            write_population(&out, &pop)
                .with_context(|| format!("writing population to {}", out.display()))?;
            eprintln!("wrote {} users → {}", pop.len(), out.display());
            Ok(())
        }

        Cmd::Storage { input, proof_bytes, attributes } => {
            let pop = read_population(&input)
                .with_context(|| format!("reading population from {}", input.display()))?;
            run_storage(&pop, proof_bytes, attributes);
            Ok(())
        }

        Cmd::Breach { input, aux_overlap, aux_extra, aux_seed } => {
            let pop = read_population(&input)
                .with_context(|| format!("reading population from {}", input.display()))?;
            run_breach(&pop, aux_overlap, aux_extra, aux_seed);
            Ok(())
        }

        Cmd::Regulatory {
            input, aux_overlap, aux_extra, aux_seed,
            breach_prob, per_record_cost, unintelligibility_discount,
        } => {
            let pop = read_population(&input)
                .with_context(|| format!("reading population from {}", input.display()))?;
            let params = RegulatoryParams {
                breach_probability_per_year: breach_prob,
                fine_per_record_gbp: per_record_cost,
                unintelligibility_discount,
            };
            run_regulatory(&pop, aux_overlap, aux_extra, aux_seed, &params);
            Ok(())
        }

        Cmd::Bench { scenario, n } => {
            eprintln!("[stub — pending deep_ali wiring] bench scenario={scenario:?} n={n}");
            Ok(())
        }
    }
}

// ─── storage ───────────────────────────────────────────────────────

fn run_storage(pop: &[User], proof_bytes: usize, attributes: usize) {
    let pii_total: usize  = pop.iter().map(User::pii_csv_bytes).sum();
    let proofs_total      = pop.len() * (proof_bytes * attributes
                                         + 32  // commitment metadata
                                         + 32  // policy_id
                                         + 16  // user_id reference
                                        );
    let pii_avg    = pii_total    as f64 / pop.len() as f64;
    let proofs_avg = proofs_total as f64 / pop.len() as f64;

    println!("Match-Me-If-You-Can — storage cost analysis");
    println!("--------------------------------------------------");
    println!("population:         {} users", pop.len());
    println!("attributes/user:    {}", attributes);
    println!("proof bytes/attr:   {}", proof_bytes);
    println!();
    println!("PII scenario:       {:>10} bytes total | {:>7.1} bytes/user",
             pii_total, pii_avg);
    println!("Proofs scenario:    {:>10} bytes total | {:>7.1} bytes/user",
             proofs_total, proofs_avg);
    println!();
    println!("multiplier (P/PII): {:.1}×", proofs_avg / pii_avg.max(1.0));
}

// ─── breach simulation ────────────────────────────────────────────

fn run_breach(pop: &[User], overlap: usize, extra: usize, seed: u64) {
    let aux = AuxiliaryDatabase::synthetic_overlap(pop, overlap, extra, seed);

    println!("Match-Me-If-You-Can — breach simulation");
    println!("--------------------------------------------------");
    println!("breached:    {} users", pop.len());
    println!("auxiliary:   {} records ({} overlap + {} extra)",
             aux.records.len(), overlap, extra);
    println!();

    // Sweep over a few common quasi-identifier combos.
    let keys: &[(&str, LinkageKey)] = &[
        ("dob",                       LinkageKey { use_country: false, use_postcode: false, use_dob: true,  use_sex: false }),
        ("postcode + sex",            LinkageKey { use_country: false, use_postcode: true,  use_dob: false, use_sex: true  }),
        ("postcode + DOB",            LinkageKey { use_country: false, use_postcode: true,  use_dob: true,  use_sex: false }),
        ("postcode + DOB + sex",      LinkageKey { use_country: false, use_postcode: true,  use_dob: true,  use_sex: true  }),
        ("country + postcode + DOB + sex", LinkageKey { use_country: true,  use_postcode: true,  use_dob: true,  use_sex: true }),
    ];

    println!("{:<35}  {:>10}  {:>10}  {:>10}  {:>10}",
             "key", "uniq", "any-match", "no-match", "rate");
    for (label, key) in keys {
        let r: BreachResult = breach_simulate(pop, &aux, key);
        println!("{:<35}  {:>10}  {:>10}  {:>10}  {:>9.1}%",
                 label, r.uniquely_reidentified, r.any_match,
                 r.no_match, r.re_id_rate * 100.0);
    }

    println!();
    println!("Proofs scenario:");
    println!("    no quasi-identifiers in the breached database, so");
    println!("    every linkage attempt above produces no-match.");
    println!("    re-identification rate = 0.00% by construction.");
}

// ─── regulatory cost ──────────────────────────────────────────────

fn run_regulatory(
    pop: &[User],
    overlap: usize,
    extra: usize,
    seed: u64,
    params: &RegulatoryParams,
) {
    // First run the breach simulation under the canonical 3-attribute key.
    let aux = AuxiliaryDatabase::synthetic_overlap(pop, overlap, extra, seed);
    let key = LinkageKey::default(); // postcode + DOB + sex
    let breach = breach_simulate(pop, &aux, &key);
    let analysis = analyze(&breach, params);

    println!("Match-Me-If-You-Can — regulatory cost analysis");
    println!("==================================================");
    println!("inputs");
    println!("  population size:         {} users", pop.len());
    println!("  auxiliary records:       {}", aux.records.len());
    println!("  linkage key:             postcode + DOB + sex (Sweeney 2000)");
    println!();
    println!("breach simulation");
    println!("  uniquely re-identified:  {:>6} ({:5.1}%)",
             breach.uniquely_reidentified, breach.re_id_rate * 100.0);
    println!();
    println!("regulatory parameters");
    println!("  breach probability/yr:   {}", params.breach_probability_per_year);
    println!("  fine per record:         £{:.2}", params.fine_per_record_gbp);
    println!("  unintelligibility disc:  {}", params.unintelligibility_discount);
    println!();
    println!("expected fines");
    println!("                              PII scenario       Proofs scenario");
    println!("  E[fine | breach]:           £{:>12.2}    £{:>12.2}",
             analysis.expected_fine_pii_gbp, analysis.expected_fine_proofs_gbp);
    println!("  Annualised (× breach prob): £{:>12.2}    £{:>12.2}",
             analysis.annual_pii_gbp, analysis.annual_proofs_gbp);
    println!();
    println!("differential");
    println!("  annual savings:          £{:.2}", analysis.annual_savings_gbp);
    if analysis.savings_multiplier.is_infinite() {
        println!("  PII / Proofs ratio:      ∞ (Proofs scenario fines = 0)");
    } else {
        println!("  PII / Proofs ratio:      {:.1}×", analysis.savings_multiplier);
    }
    println!();

    // Sensitivity sweeps.
    println!("sensitivity: breach probability per year");
    println!("  {:>10}   {:>14}   {:>14}   {:>14}",
             "P(breach)", "annual PII (£)", "annual Proofs (£)", "savings (£)");
    let probs = [0.01, 0.025, 0.05, 0.10, 0.25];
    for (p, a) in sensitivity_breach_probability(&breach, params, &probs) {
        println!("  {:>10.3}   {:>14.2}   {:>14.2}   {:>14.2}",
                 p, a.annual_pii_gbp, a.annual_proofs_gbp, a.annual_savings_gbp);
    }
    println!();
    println!("sensitivity: per-record fine (GBP)");
    println!("  {:>12}   {:>14}   {:>14}   {:>14}",
             "£/record", "annual PII (£)", "annual Proofs (£)", "savings (£)");
    let costs = [50.0, 100.0, 130.0, 200.0, 500.0];
    for (c, a) in sensitivity_per_record_cost(&breach, params, &costs) {
        println!("  {:>12.2}   {:>14.2}   {:>14.2}   {:>14.2}",
                 c, a.annual_pii_gbp, a.annual_proofs_gbp, a.annual_savings_gbp);
    }
}

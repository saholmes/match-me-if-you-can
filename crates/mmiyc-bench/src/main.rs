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

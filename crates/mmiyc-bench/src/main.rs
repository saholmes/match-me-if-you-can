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
//!   mmiyc-bench bench --air fibonacci --log-rows 5 --iters 20
//!     -- real STARK prove + verify against deep_ali, capturing
//!        proof size, prove ms, verify ms.  Used to anchor the
//!        compute and storage tables in §6 of the paper.
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

    /// Real STARK-STIR prove + verify against deep_ali.  The age- and
    /// country-AIRs in `mmiyc-air` are not yet plug-in-able into
    /// deep_ali (deep_ali_merge_general dispatches over a closed
    /// AirType enum), so the bench drives one or more of the
    /// existing AIRs as a structural proxy:
    ///
    ///   * `fibonacci`   — w=2, k=1, deg-2 transitions.  Tightest
    ///                     lower-bound proxy for an age range AIR
    ///                     (which has w=2 boolean cols + 2 deg-2
    ///                     constraints).
    ///   * `hash-rollup` — w=4, k=3, deg-2.  Upper-bound proxy.
    ///   * `all`         — both, useful for the paper's compute table.
    ///
    /// Proof bytes and timings are reported with median of `iters`
    /// runs to dampen wall-clock jitter.
    Bench {
        /// Which AIR to drive.
        #[arg(long, value_enum, default_value_t = AirArg::All)]
        air: AirArg,
        /// log2 of trace rows.  Defaults to a small ladder
        /// (5..=8 = {32, 64, 128, 256}) so we cover the regime
        /// the registration AIRs would actually run at.
        #[arg(long, value_delimiter = ',')]
        log_rows: Option<Vec<u32>>,
        /// How many prove+verify iterations per row count.
        /// Median across these is reported.
        #[arg(long, default_value_t = 20)]
        iters: usize,
        /// Number of FRI queries.  Default 54 mirrors §III of the
        /// stark-stir paper (~128-bit security with conservative gap).
        #[arg(long, default_value_t = 54)]
        queries: usize,
    },
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum AirArg { Fibonacci, AgeRange, HashRollup, Poseidon, Sha256, All }

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

        Cmd::Bench { air, log_rows, iters, queries } => {
            let logs = log_rows.unwrap_or_else(|| vec![5, 6, 7, 8]);
            run_bench(air, &logs, iters, queries)
        }
    }
}

// ─── real STARK bench ─────────────────────────────────────────────

mod stark_bench {
    //! Direct driver for `deep_ali_merge_general` + `deep_fri_prove` /
    //! `deep_fri_verify` at small trace sizes.

    use std::time::Instant;

    use ark_goldilocks::Goldilocks as F;
    use deep_ali::{
        air_workloads::{build_execution_trace, AirType},
        deep_ali_merge_general,
        fri::{
            deep_fri_proof_size_bytes, deep_fri_prove, deep_fri_verify,
            DeepFriParams, FriDomain,
        },
        sextic_ext::SexticExt,
        trace_import::lde_trace_columns,
    };

    /// Calibration mirroring §III of the stark-stir paper.
    /// 1/ρ₀ = 32 blowup, sextic extension, query count from caller.
    pub const BLOWUP: usize = 32;
    pub const SEED_Z: u64 = 0xDEEF_BAAD;
    type Ext = SexticExt;

    /// One run of the prove+verify pipeline.  Returns the wall-clock
    /// timings and proof byte count.
    pub struct Sample {
        pub setup_ms: f64,
        pub prove_ms: f64,
        pub verify_ms: f64,
        pub proof_bytes: usize,
    }

    fn make_schedule(n0: usize) -> Vec<usize> {
        // arity-2 (binary FRI) — matches the simplest, most portable
        // schedule and is the right baseline for a WASM-feasibility
        // estimate (no STIR-specific tricks).
        vec![2usize; n0.trailing_zeros() as usize]
    }

    fn combination_coeffs(num: usize) -> Vec<F> {
        (0..num).map(|i| F::from((i + 1) as u64)).collect()
    }

    pub fn run_one(air: AirType, n_trace: usize, num_queries: usize) -> Sample {
        let n0 = n_trace * BLOWUP;
        let domain = FriDomain::new_radix2(n0);

        let t_setup = Instant::now();
        let trace = build_execution_trace(air, n_trace);
        let lde   = lde_trace_columns(&trace, n_trace, BLOWUP)
            .expect("LDE failed");
        let coeffs = combination_coeffs(air.num_constraints());
        let (c_eval, _) = deep_ali_merge_general(
            &lde, &coeffs, air, domain.omega, n_trace, BLOWUP,
        );
        let setup_ms = t_setup.elapsed().as_secs_f64() * 1e3;

        let params = DeepFriParams {
            schedule: make_schedule(n0),
            r: num_queries,
            seed_z: SEED_Z,
            coeff_commit_final: true,
            d_final: 1,
            stir: false,
            s0: num_queries,
            public_inputs_hash: None,
        };

        let t_prove = Instant::now();
        let proof = deep_fri_prove::<Ext>(c_eval, domain, &params);
        let prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;

        let t_verify = Instant::now();
        let ok = deep_fri_verify::<Ext>(&params, &proof);
        let verify_ms = t_verify.elapsed().as_secs_f64() * 1e3;
        assert!(ok, "verify failed at n_trace = {n_trace}");

        let proof_bytes = deep_fri_proof_size_bytes::<Ext>(&proof, false);
        Sample { setup_ms, prove_ms, verify_ms, proof_bytes }
    }

    /// Run `iters` prove+verify cycles and return the median sample.
    pub fn median(air: AirType, n_trace: usize, num_queries: usize, iters: usize) -> Sample {
        let mut samples: Vec<Sample> = (0..iters)
            .map(|_| run_one(air, n_trace, num_queries))
            .collect();
        samples.sort_by(|a, b| a.prove_ms.partial_cmp(&b.prove_ms).unwrap());
        samples.swap_remove(iters / 2)
    }
}

fn run_bench(air: AirArg, log_rows: &[u32], iters: usize, queries: usize) -> Result<()> {
    use deep_ali::air_workloads::AirType;

    let airs: Vec<(&str, AirType)> = match air {
        AirArg::Fibonacci  => vec![("Fibonacci",     AirType::Fibonacci)],
        AirArg::AgeRange   => vec![("AgeRange32",    AirType::AgeRange32)],
        AirArg::HashRollup => vec![("HashRollup",    AirType::HashRollup)],
        AirArg::Poseidon   => vec![("PoseidonChain", AirType::PoseidonChain)],
        AirArg::Sha256     => vec![("Sha256DsKsk",   AirType::Sha256DsKsk)],
        AirArg::All        => vec![
            ("Fibonacci",     AirType::Fibonacci),
            ("AgeRange32",    AirType::AgeRange32),
            ("HashRollup",    AirType::HashRollup),
            ("PoseidonChain", AirType::PoseidonChain),
            ("Sha256DsKsk",   AirType::Sha256DsKsk),
        ],
    };

    println!("Match-Me-If-You-Can — real STARK bench (deep_ali backend)");
    println!("Calibration: 1/rho_0 = 32 blowup, sextic extension, {} queries, arity-2 FRI", queries);
    println!("Median of {} prove+verify cycles per row count.", iters);
    println!();
    println!("{:<13} {:>6} {:>4} {:>4} {:>9} {:>9} {:>10} {:>10} {:>10}",
             "AIR", "n_rows", "w", "k",
             "setup_ms", "fri_ms", "TOTAL_ms", "verify_ms", "proof_b");
    for (label, air) in &airs {
        let w = air.width();
        let k = air.num_constraints();
        for &log_n in log_rows {
            let n_trace = 1usize << log_n;
            let s = stark_bench::median(*air, n_trace, queries, iters);
            // TOTAL prove = setup (trace + LDE + composition) + FRI
            // (commit / fold / query).  This is the user-facing
            // "time to produce a proof"; the breakdown is kept for
            // diagnostic purposes — for large AIRs (Sha256DsKsk)
            // setup dominates; for small AIRs (AgeRange32) FRI does.
            let total = s.setup_ms + s.prove_ms;
            println!("{:<13} {:>6} {:>4} {:>4} {:>9.2} {:>9.2} {:>10.2} {:>10.2} {:>10}",
                     label, n_trace, w, k,
                     s.setup_ms, s.prove_ms, total, s.verify_ms, s.proof_bytes);
        }
    }
    println!();
    println!("AgeRange32 (w=2, k=2): first-class AIR for age / income / postcode");
    println!("range predicates.  Fibonacci (k=1) and HashRollup (k=3) bracket it.");
    println!("PoseidonChain (w=16, k=16): in-circuit Poseidon round-function,");
    println!("structural reference for the bulk of the Merkle-path AIRs.");
    println!("Sha256DsKsk (w=756): in-circuit SHA-256, same-order-of-magnitude");
    println!("proxy for the SHA3 trust-boundary hash in the dual-hash design");
    println!("(Poseidon inside, SHA3 at the boundary for FIPS compliance).");
    Ok(())
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

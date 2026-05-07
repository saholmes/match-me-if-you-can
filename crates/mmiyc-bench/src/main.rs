//! Match-Me-If-You-Can benchmark harness.
//!
//! Sub-commands:
//!
//! ```text
//!   mmiyc-bench generate --n 1000 --out data/synthetic-users.csv
//!     -- create N synthetic users with reasonable attribute distributions
//!
//!   mmiyc-bench bench --scenario both --n 1000
//!     -- run end-to-end registration + verify timing on the population
//!
//!   mmiyc-bench breach --aux data/public-aux.csv --n 1000
//!     -- simulate a breach: try to re-identify users via auxiliary DB
//! ```
//!
//! Currently scaffolds the CLI surface only; each sub-command is a
//! TODO whose body fills in once the upstream STARK-STIR prover is
//! wired into [`mmiyc_air`].

use clap::{Parser, Subcommand};

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
        #[arg(long, default_value_t = 1000)]
        n: usize,
        #[arg(long, default_value = "data/synthetic-users.csv")]
        out: String,
    },
    /// Run the end-to-end timing benchmark.
    Bench {
        #[arg(long, value_enum, default_value_t = ScenarioArg::Both)]
        scenario: ScenarioArg,
        #[arg(long, default_value_t = 1000)]
        n: usize,
    },
    /// Run the breach-simulation re-identification analysis.
    Breach {
        #[arg(long)]
        aux: String,
        #[arg(long, default_value_t = 1000)]
        n: usize,
    },
}

#[derive(clap::ValueEnum, Debug, Clone)]
enum ScenarioArg { Pii, Proofs, Both }

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    match args.command {
        Cmd::Generate { n, out } => {
            eprintln!("[stub] generate {n} users → {out}");
            Ok(())
        }
        Cmd::Bench { scenario, n } => {
            eprintln!("[stub] bench scenario={scenario:?} n={n}");
            Ok(())
        }
        Cmd::Breach { aux, n } => {
            eprintln!("[stub] breach simulation against {aux} (n={n})");
            Ok(())
        }
    }
}

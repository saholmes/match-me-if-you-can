# Match Me If You Can

Privacy-preserving user registration via STARK-STIR proofs over personally
identifiable information (PII).

A typical website registration captures name, date of birth, country,
postcode, email, income bracket, and other attributes — and stores them
verbatim (encrypted at rest, but still verbatim) in a database. When that
database is breached, the leaked data is *linkable* against publicly-available
records (electoral roll snapshots, breach corpora, social-media exports), and
the operator faces regulatory exposure under GDPR Art. 32 / 33 / 83.

This project replaces the verbatim PII columns with **STARK-STIR proofs of
attribute predicates** — range proofs ("user's age is in [18, 120]"), set
membership proofs ("user's country is in {EU member states}"), and similar
constructions. The server can answer every business-relevant query
("authorised to register?", "in the EU?", "over 18?") by re-verifying the
stored proof — but the underlying value is never present in the database
to be leaked.

The accompanying paper (in `docs/paper/`) quantifies the four cost / benefit
axes:

| Axis | Headline question |
|---|---|
| **Storage** | bytes per user record under each scenario |
| **Compute** | prove time, verify time, end-to-end registration latency |
| **Breach unlinkability** | re-identification rate against a public auxiliary database |
| **Regulatory cost** | expected GDPR Art. 83 fine differential, weighted by per-year breach probability |

## Status

Early scaffold. Workspace structure, AIR skeletons, and paper outline only.
See `docs/paper/paper.tex` for the planned argument and
`docs/threat-model.md` for the threat model.

## Repository layout

```
match-me-if-you-can/
├── Cargo.toml             # Rust workspace
├── crates/
│   ├── mmiyc-air/         # AIRs for age, country, postcode, …
│   ├── mmiyc-prover/      # proof generation
│   ├── mmiyc-verifier/    # native proof verification
│   ├── mmiyc-server/      # axum HTTP server: /register, /verify-*
│   └── mmiyc-bench/       # storage / latency / breach harness
├── frontend/              # demo registration form (vanilla HTML/JS)
├── docs/
│   ├── paper/             # LaTeX paper draft
│   ├── air-specs/         # formal AIR documentation
│   └── breach-simulation/ # methodology notes
├── data/                  # synthetic users + reference sets (gitignored)
└── benches/               # criterion microbenchmarks
```

## Dependencies

Builds against a sibling checkout of the STARK-STIR codebase:

```
../stark-stir-swarm/   # path-dependency in workspace Cargo.toml
```

If the path differs in your environment, edit `Cargo.toml`'s
`[workspace.dependencies]` block. Switching to a git or registry dependency
once the upstream stark-stir crate is published is a single-line change.

## Building

```bash
# Workspace check + tests
cargo check --workspace
cargo test  --workspace

# Run the server (development)
cargo run -p mmiyc-server

# Generate synthetic users for the bench
cargo run -p mmiyc-bench -- generate --n 1000 --out data/synthetic-users.csv

# End-to-end registration + verification microbenchmark
cargo run -p mmiyc-bench -- bench --scenario both --n 1000
```

## Author

Stephen A. Holmes — `s.a.holmes@surrey.ac.uk`

## Licence

Apache-2.0. See `LICENSE`.

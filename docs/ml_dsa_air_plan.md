# ML-DSA-44 verify AIR — design plan

**Goal.** Replace the RSA-PKCS#1 v1.5 designated-verifier gate with a
post-quantum equivalent: the operator's signing key is ML-DSA-44 (FIPS 204,
NIST security category 2 / "level 1"), and `/verify/income/:id` returns
a STARK proof of knowledge of an ML-DSA-44 signature on the bound
message — exactly mirroring `prove_rsa_pok` / `verify_rsa_pok` but with
the underlying signature scheme upgraded to a lattice primitive.

This document scopes the work. The actual implementation is multi-session.

---

## 1. ML-DSA-44 verify, decomposed

FIPS 204 §3 Algorithm 3 (`ML-DSA.Verify`):

```text
Verify(pk = (ρ, t1), m, σ = (c̃, z, h)) :
  1. A      ← ExpandA(ρ)                               // 4×4 matrix in R_q
  2. tr     ← H(BytesToBits(pk), 512)                  // SHAKE-256
  3. μ      ← H(BytesToBits(tr ‖ m), 512)              // SHAKE-256
  4. c      ← SampleInBall(c̃)                          // hash → poly with τ ones
  5. w'_approx ← NTT⁻¹( A·NTT(z) − NTT(c)·NTT(t1·2^d) )
  6. w'_1    ← UseHint(h, w'_approx)
  7. c̃' ← H(BytesToBits(μ ‖ w1Encode(w'_1)), 256)      // SHAKE-256
  8. accept iff c̃ = c̃'  AND  ‖z‖∞ < γ_1 - β  AND  ‖h‖_w ≤ ω
```

Parameters for ML-DSA-44:
- q = 8 380 417  (≈ 2^23, a prime)
- n = 256, polynomial ring R_q = Z_q[X]/(X^256 + 1)
- k = ℓ = 4
- η = 2,  τ = 39,  β = 78
- γ_1 = 2^17,  γ_2 = (q − 1)/88,  ω = 80
- d = 13  (low-bits drop)
- |pk| = 1 312 B,  |sk| = 2 560 B,  |σ| = 2 420 B

## 2. AIR component breakdown

| AIR module                       | What it proves                                              | Est. LoC | Reuses                  |
|----------------------------------|-------------------------------------------------------------|----------|-------------------------|
| `keccak_f1600_air`               | One Keccak-f[1600] permutation; SHAKE-256 absorb / squeeze  | 1 500–2 500 | (none — new)         |
| `ml_dsa_field_air`               | Modular arithmetic in Z_q (q = 8 380 417); Montgomery form  | 600–900  | reuses field-AIR pattern from `rsa2048_field_air` |
| `ml_dsa_ntt_air`                 | 256-point NTT over Z_q (Cooley-Tukey, ψ root of unity)      | 800–1 200 | builds on `ml_dsa_field_air` |
| `ml_dsa_polymul_air`             | Pointwise NTT-domain multiplication of polynomials          | 200–400  | builds on field-AIR     |
| `ml_dsa_decompose_air`           | `UseHint`, `MakeHint`, `Decompose` for HighBits/LowBits     | 400–600  | builds on field-AIR     |
| `ml_dsa_sample_in_ball_air`      | `SampleInBall(c̃)` — hash bits to ±1, 0 sparse polynomial    | 300–500  | needs SHAKE-256         |
| `ml_dsa_w1_encode_air`           | `w1Encode` byte-packing for the challenge re-derivation     | 100–200  | (small, table-driven)   |
| `ml_dsa_norm_check_air`          | Infinity-norm bound `‖z‖∞ < γ_1 - β`; hint weight `≤ ω`     | 150–250  | builds on field-AIR     |
| `ml_dsa_verify_air`              | Composes the above into the full §3 Algorithm 3             | 500–800  | composer / scheduler    |
| `deep_ali_merge_ml_dsa_verify`   | Streaming merge wrapper analogous to `deep_ali_merge_*`     | 100–150  | mirrors RSA / Ed25519   |

Total: ~5 000–8 000 LoC of constraint-system code, pre-optimisation.

## 3. Critical-path blocker: Keccak-f[1600]

The deep_ali fork we use has `sha256_air` and `sha512_air` but **no** Keccak
permutation AIR.  ML-DSA-44 verify hashes ~4 times per call (steps 2, 3, 7,
plus internal `SampleInBall`).  Without a Keccak-f AIR the rest of the
ML-DSA AIR can't be glued together end-to-end.

Options for the Keccak AIR:
- **(a)** Build it in this workspace.  Reference: Ben-Sasson et al.'s
  ethSTARK Keccak AIR; published academic constraints exist, ~1 500 LoC of
  trace + constraint code.  Largest single sub-task.
- **(b)** Pull a Keccak AIR from an existing open-source STARK project
  (Plonky2, ZK Email, etc.) and adapt to deep_ali's `eval_*_constraints`
  shape.  Requires careful soundness review of the imported code.
- **(c)** Use a non-Keccak-based hash inside the AIR (e.g. Poseidon-bn254)
  and define a "mmiyc-flavoured ML-DSA" with an in-circuit-friendly hash.
  This **diverges from FIPS 204** and forfeits the conformance claim.

Recommended: (a), unless (b) finds a credible donor.  (c) is a
demo-only escape hatch we should not take if we want the FIPS 204
compliance story.

## 4. Phasing (multi-session)

| Phase | Concrete deliverables                                                                                | Tests                                            |
|-------|------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| **0** ✅ | Native `ml_dsa::Keypair` wrapper, round-trip + negative tests                                  | `mmiyc_server::ml_dsa::tests` (4 passing)        |
| 1     | Decide AIR location (deep_ali vs new crate); create skeleton modules with constraint counts pinned   | `cargo check`                                    |
| 2     | `ml_dsa_field_air` — Z_q arithmetic                                                                  | trace-validity, mont-form round-trip             |
| 3     | `ml_dsa_ntt_air` + `ml_dsa_polymul_air` — NTT and pointwise multiplication                            | NTT(NTT⁻¹) = id; vs native `ml-dsa` reference    |
| 4     | `keccak_f1600_air` (or imported)                                                                     | matches NIST FIPS 202 test vectors               |
| 5     | `ml_dsa_decompose_air`, `ml_dsa_sample_in_ball_air`, `ml_dsa_w1_encode_air`, `ml_dsa_norm_check_air`  | each with native-reference round-trip            |
| 6     | `ml_dsa_verify_air` composes the above; `deep_ali_merge_ml_dsa_verify` glue                          | end-to-end honest verify                         |
| 7     | `prove_ml_dsa_pok` / `verify_ml_dsa_pok` in `mmiyc-prover` / `mmiyc-verifier`                        | round-trip with real keypair                     |
| 8     | Wire into `/verify/income/:id`; replace RSA-STARK PoK with ML-DSA-STARK PoK; frontend WASM verify    | exfiltration demo still shows asymmetry          |

Phase 0 is done in this session.  Phases 1–7 are 50–100 hours of focused
work; phase 4 (Keccak) is the largest single chunk.

## 5. Open questions

1. **Hash domain separation.**  ML-DSA's FIPS 204 already uses `tr` and
   `μ` for transcript binding.  When we wrap an ML-DSA signature in a
   STARK PoK whose `public_inputs_hash` also includes the message and
   pk, do we still need a separate transcript tag?  Probably yes for
   defence-in-depth, but worth thinking carefully about composition.
2. **Trace size.**  ML-DSA verify has ~4 × Keccak-f permutations + 4×4
   NTT ops.  At naive trace cost this is plausibly `n_trace = 8192`,
   making prove ~10× more expensive than the current RSA-PoK
   (which is `n_trace = 32`).  Worth a back-of-envelope estimate
   before committing the architecture.
3. **Witness layout.**  Does the signature `σ = (c̃, z, h)` go in
   private trace columns directly, or is each component first reduced
   to NTT-domain coefficients?  The former is simpler; the latter
   may make the constraint set smaller.  Need to lay out a sample
   trace before deciding.
4. **WASM verify cost.**  The ML-DSA verify AIR will be larger than
   `rsa2048_stacked_air` (n_trace=32, ~8 ms WASM verify).  Targeting
   ≤ 50 ms WASM verify would keep the gate's UX comparable.  Whether
   we hit that depends on the trace size answer in (2).

## 6. Native primitive — ready

Wrapper module: `crates/mmiyc-server/src/ml_dsa.rs`

```rust
pub struct Keypair(SigningKey<MlDsa44>);
impl Keypair {
    pub fn generate() -> Self;                            // OS CSPRNG
    pub fn public_key_bytes(&self) -> Vec<u8>;            // 1 312 B
    pub fn sign(&self, message: &[u8]) -> Vec<u8>;        // 2 420 B
}
pub fn verify(pk_bytes: &[u8], message: &[u8], sig: &[u8]) -> Result<()>;
```

Tests cover honest round-trip, wrong-message rejection, wrong-pk
rejection, and truncated-signature rejection.  Run with
`cargo test -p mmiyc-server --lib --release ml_dsa`.

## References

- FIPS 204 (NIST 2024-08-13): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- FIPS 202 (Keccak / SHA-3): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- RustCrypto `ml-dsa` 0.1.0-rc.9: https://docs.rs/ml-dsa/0.1.0-rc.9
- Ben-Sasson et al., "Scalable Zero Knowledge with No Trusted Setup" (CCS 2018, ethSTARK Keccak AIR)

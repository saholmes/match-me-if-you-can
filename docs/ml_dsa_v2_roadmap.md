# ML-DSA-44 STARK PoK — v2 (full in-circuit FIPS 204 verify) roadmap

**Goal.** Promote `verify_ml_dsa_signature_pok` from "FIPS 204 verify
with STARK packaging" (v1) to "STARK alone proves FIPS 204 verify"
(v2). After v2, native `ml_dsa::verify` is removed from the gate's
critical path; the STARK is the sole soundness layer.

**v1 status (2026-05-08).** Two-layer design:
- *Layer 1*: native `ml_dsa::verify` enforces full FIPS 204 §3
  Algorithm 3 acceptance (`c̃ = c̃'`, norms, hint weight, ExpandA,
  SampleInBall, NTT consistency). This layer is load-bearing.
- *Layer 2*: STARK PoK proves only the polynomial-arithmetic core
  (`w'_approx_ntt = Â·NTT(z) − NTT(c)·NTT(t1·2^d)`). Soundness:
  STIR + SHA-3, NIST PQ Level 3 unconditional.

**v2 promotes the STARK to enforce all of FIPS 204 §3 Algorithm 3.**

---

## Cost projection

For one ML-DSA-44 verify, fully in-circuit:

| Component                     | Trace cells (approx) | Constraints |
|-------------------------------|----------------------|-------------|
| 4× SHAKE absorptions/squeezes | 4 × 9 perms × 24 rounds × 12 k | ~10 M |
| 13 NTT/INTT calls             | 3 K field-AIR ops × 30 each × 13 | ~1.2 M |
| Polynomial-equation core      | 1 K × 6 (already in v1)        | ~6 k |
| Decompose (UseHint)           | 1 K × ~30                       | ~30 k |
| w1Encode                      | 1 K × ~10                       | ~10 k |
| Norm check on z + hint weight | 1 K + 84                        | ~50 k |
| **Total**                     |                                  | **~12 M** |

LDE working set (BLOWUP=32): ~400 M cells = **~10 GiB RAM**;
prove time projection: **minutes**, not seconds.

This is a real engineering project. The v2 demo is not a session
of work; it's a deliberate multi-week effort. Worth doing for the
"in-circuit FIPS 204 verify" claim, but not on the critical path
for the existing demo's narrative.

---

## Sub-task breakdown (with dependency graph)

```
                 ┌──────────────────────────────┐
                 │  keccak_f1600_air ✅ DONE    │
                 └───────────────┬──────────────┘
                                 │
                  ┌──────────────┴──────────────┐
                  ▼                             ▼
         shake_absorb_air            shake_squeeze_air
         (T1, ~3-5 hours)            (T2, ~2-3 hours)
                  │                             │
                  └──────────────┬──────────────┘
                                 ▼
                       SHAKE-128/256 in-circuit
                                 │
                ┌────────────────┼────────────────┐
                ▼                ▼                ▼
           ExpandA           SampleInBall    Transcript hashing
           (T3, ~4-6 h)      (T4, ~3-5 h)    (T5, ~3-5 h)
                                              │
                                              ▼
                                      c̃ = c̃' check (T6, ~2-3 h)
```

```
ntt_memory_argument                  ┌──────────────────────┐
(T7, ~6-10 hours, parallel track)    │  ml_dsa_norm_check ✅│
                                     └──────────┬───────────┘
                                                ▼
                                     compose into verify_air
                                     (T8, ~2-3 hours)
```

```
T1+T2 → T3+T4+T5+T6 → T7 → T8 → composer
                                  │
                                  ▼
                            ml_dsa_verify_air_v2
                            (T9, ~5-8 hours)
```

### T1: `shake_absorb_air`
- Pad input to multiple of rate (1088 bits for SHAKE-256, 1344 for SHAKE-128).
- For each rate-block: XOR rate-bits into state, run `keccak_f1600_air`.
- Tests: matches NIST FIPS 202 SHAKE test vectors; tamper detection.

### T2: `shake_squeeze_air`
- Extract first `rate` bits of state as output bytes.
- Re-run `keccak_f1600_air` between successive squeeze rounds.
- Tests: SHAKE output matches native `sha3::Shake256` for various lengths.

### T3: `ml_dsa_expand_a_air`
- Drives `shake_absorb_air` × 16 (one per matrix entry).
- Includes RejNTTPoly's rejection sampling: each squeezed 3-byte
  group tested against `< q`; counter only advances on accept.
- Tests: in-circuit Â matches native `expand_a(ρ)`; tamper detection.

### T4: `ml_dsa_sample_in_ball_air`
- SHAKE-256 absorb of c̃; squeeze for sign mask + position bytes.
- Rejection sampling for positions ≤ ctr.
- Constraints for the τ-sparse output structure.
- Tests: in-circuit c matches native `sample_in_ball(c_tilde)`.

### T5: `ml_dsa_transcript_air`
- SHAKE-256 hashes for `tr ← H(pk, 512)`, `μ ← H(tr ‖ m, 512)`,
  and `c̃' ← H(μ ‖ w1Encode(w'_1), 256)`.
- Wires the three transcript hashes through `shake_absorb` + `shake_squeeze`.

### T6: `c_tilde_equality_check`
- Compare 32-byte `c̃` from signature against in-circuit `c̃'`.
- Per-byte equality constraint; 32 deg-1 constraints.

### T7: `ml_dsa_ntt_memory_argument`
- Cross-row consistency: each butterfly's output is the input to
  butterflies two stages later.
- Approach: standard "memory argument" / permutation argument
  (analogous to Cairo / RISC-V STARKs). 
- Each butterfly emits `(addr, value)` reads + writes; a separate
  trace section proves the read/write log is a valid permutation.
- Tests: an in-circuit NTT trace that fakes one butterfly's output
  is rejected.

### T8: `ml_dsa_norm_check_composition`
- Add 4 × 256 = 1024 `ml_dsa_norm_check_air` rows to the verify
  trace, one per `z[l][i]`. Already-existing AIR, just compose.
- Drops the native norm check from Layer 1.

### T9: `ml_dsa_verify_air_v2`
- Composes T3, T4, T5, T6, T7, T8 + the existing v1 polynomial core.
- Trace has multiple regions (one per sub-AIR); region boundaries
  are bound via `public_inputs_hash`.
- Final v2 prove + verify; native ml_dsa::verify removed.

---

## Estimated total focused effort: 30–50 hours

This is realistic for a v2 deliverable but not a single session.
Recommended cadence: 1–2 sub-tasks per session, with cross-tests
against native references at each step.

## Interim cryptographic strengthenings (can land before v2)

These don't need full v2 but each closes a fraction of the
Layer-1 dependency:

- **(I1) Compose `ml_dsa_norm_check_air` into verify_air now.** Even
  without v2's full SHAKE pipeline, the norm check on z is
  self-contained and can be wired in. Adds ~1024 rows + ~38
  constraints/row = ~38 k constraints to the v1 verify_air. Removes
  the `‖z‖∞ < γ_1 - β` reliance from Layer 1. **~2-3 hours.**
- **(I2) Compose `ml_dsa_decompose_air` for UseHint.** Adds the
  hint-application step in-circuit. Still relies on Layer 1 for the
  `c̃ = c̃'` check (the hash-derived final acceptance), but moves
  the algebraic part of UseHint into the STARK. **~2-3 hours.**
- **(I3) Tighten v1's pi_hash binding.** Currently `compute_pi_hash`
  hashes (Â, c, t1·2^d, w_approx). Add the input message bytes and
  the encoded (pk, sig) to the hash so an adversary can't swap one
  signature for another while keeping the derived NTT-domain
  values fixed. **~1 hour.** *(Low cryptographic impact since both
  sides re-derive deterministically; primarily a defense in depth.)*

---

## Recommendation

Don't rush v2. The v1 design with native `ml_dsa::verify` as
defense-in-depth is honest, sound, and well-documented in §6.2.
Land I1 and I3 in interim sessions (5-6 hours total) for a clean
"shrunk Layer-1" v1.5 milestone. Schedule v2 deliberately as a
multi-session push when the demo's other priorities allow.

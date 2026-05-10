# MMIYC live-demo walkthrough — for an outside audience

A 10-15 minute scripted run-through of the MMIYC web demo, written so
that someone without a cryptography background can follow the flow
and understand the **operational** value at each step.  The
underlying construction — STIR-STARKs over Goldilocks, ML-DSA-65
under FIPS 204, RSA-2048 designated-verifier — is hidden behind
plain-English narration.

Two stories are told:

1. **The "before/after" story**: a regular registration form that
   stores raw personally-identifiable information (PII), versus the
   same form that stores only mathematical proofs of attribute
   predicates.
2. **The breach story**: what actually leaks when a database is
   exfiltrated AND the at-rest encryption key is compromised — the
   "catastrophic" assumption every regulator now has to plan for.

## 0. Setup

```bash
cd /path/to/match-me-if-you-can
./scripts/build-wasm.sh                      # builds the browser-side prover/verifier
MMIYC_STATIC_DIR="$(pwd)/frontend" \
BENCH_LDT=stir \
cargo run --release -p mmiyc-server          # starts the demo server on :8080
```

Open <http://127.0.0.1:8080/> in a browser.  Press F12 to open
developer tools — you'll want the *Network* tab visible during the
breach demo, to see the actual proof bundle sizes flying past.

If you started the server in a different terminal, leave its log
visible — the slow steps (the v2 gate especially) take 25-30 seconds
on Apple Silicon and you'll want to see "what the server is doing"
during the wait.

---

## Part 1 — The "before" world: register with raw PII

> **What you're showing**: a normal web registration form that
> collects six pieces of personally-identifiable information.  This
> is what every typical site does today.

1. Use the scenario toggle at the top of the page to select
   **"PII (legacy)"** mode.  The page should refresh to show that
   raw PII is being stored.
2. Fill the form (defaults are pre-filled with sensible values — date
   of birth 1990-06-15, country Germany, postcode AB, email
   alice@example.com, income £45 000, sex F).  Click **"Register"**.
3. Point at the result panel: every field has been stored in the
   database in cleartext (the at-rest encryption is still on, but
   we'll come back to that).

> **Lay explanation**: *"Right now this site is doing exactly what a
> normal web service does.  It collected six personal facts from
> Alice and stored them.  Whatever happens later — security
> incidents, insider access, regulator queries — every one of those
> facts is in the database, recoverable by anyone who can read it."*

---

## Part 2 — The "after" world: register with mathematical proofs

> **What you're showing**: the same registration form, same user
> input, but the stored data is replaced with **mathematical proofs
> of predicates** instead of the raw values.  The user proves
> "I'm over 18", "I'm in the EU", "my income is in band [£40k, £100k]"
> without revealing the underlying numbers.

1. Switch the scenario toggle to **"Proofs (privacy-preserving)"**
   mode.
2. Fill the form again with the same defaults.  Click **"Register"**.
   (This takes a second or two longer — the browser is computing
   three STARK proofs locally before sending anything to the
   server.)
3. Point at the result panel: instead of cleartext fields, the
   database now stores three mathematical objects, each ~800 KiB:
   - an "age proof" (a STARK proof that DOB-days encodes an age ≥ 18)
   - a "country proof" (a STARK proof that country-code is a member
     of the EU country list)
   - an "income proof" (a STARK proof that income-pence is in the
     declared band)
4. Use the developer tools' Application tab → IndexedDB or Local
   Storage to confirm: there is no DOB, no country code, no income
   number anywhere in the page state.  The browser is genuinely
   discarding the cleartext after producing the proof.

> **Lay explanation**: *"Same form, same user, same six pieces of
> personal data — but the database now contains a mathematical
> certificate that says 'this user satisfies the eligibility
> criteria' without saying what their DOB or income actually is.
> The site can still answer 'is this user over 18?' or 'is this
> user in the EU?' or 'is this user's income in the eligible band?'
> any time it wants — because the proofs are stored, just not the
> raw values they were derived from."*

---

## Part 3 — Designated-verifier income band check (RSA-STARK gate)

> **What you're showing**: the **service** vouching that this user's
> income falls in the eligible band, RIGHT NOW.  The signature on
> the response uses the service's own RSA key, so a third party
> trusting the service's API can be sure the response really came
> from this service and not from a stale snapshot or a forgery.

1. After registration, find the row of "Verify income" buttons.
   Click the **grey one** labelled *"Verify income (RSA-STARK
   gate)"*.  This takes 3-5 seconds.
2. The result panel will show "Service-attested verification ✓",
   with a *pk pin* — the first 24 hex characters of the service's
   RSA-2048 public key.  The same pin appears on every successful
   verification, because the service is using a stable RSA keypair
   (one per deployment).

> **Lay explanation**: *"A third party — say, a tax-credit
> calculator that wants to know 'is this user's income in the
> eligible band?' — asks the service.  The service does two
> things: (a) re-checks the stored income proof to confirm the
> user's income really IS in the band, and (b) signs the answer
> with its own private key, which only the service knows.  The
> third party can verify the signature against the service's
> published public key and be sure: 'yes, the live service just
> told me this answer'.  This is what a 'designated-verifier gate'
> means — the verifier is designated to be **the live service
> itself**, not just anyone who happens to have a copy of the
> proof."*

---

## Part 4 — Post-quantum income band check (gold v2 button)

> **What you're showing**: the same designated-verifier check, but
> with the signature primitive upgraded to ML-DSA-65 (the NIST PQ
> Level 3 standard, FIPS 204) AND with the entire signature
> verification proven in-circuit by a STARK.  This means even an
> attacker with a cryptographically-relevant quantum computer
> cannot forge a service response.

1. Click the **gold button** labelled *"Verify income (v2
   layer-1-free gate)"*.  This takes ~25 seconds — the server is
   running a 10-sub-AIR composite STARK proving every step of FIPS
   204 §3 Algorithm 3 in-circuit.  Watch the server log if you have
   it visible: you'll see "running v2 ML-DSA STARK PoK …" and a
   long pause.
2. When it returns, the result panel shows the same
   "Service-attested verification ✓" with a different pk pin —
   this time it's the first 24 hex characters of an ML-DSA-65
   public key, which is freshly generated by the server on every
   call.
3. Browser-side timing: ~300 ms WASM verify time on Apple Silicon
   (M-series).  The 25 second pause was the server proving; the
   browser only verifies a 7 MiB bundle.

> **Lay explanation**: *"The grey button used RSA-2048, which is
> standard today but breakable by a future quantum computer.  The
> gold button uses ML-DSA-65, which is the signature scheme NIST
> standardised in 2024 specifically for the post-quantum world.
> The mathematics is much harder — but the price is that producing
> the signed answer takes the server about 25 seconds because it's
> proving every step of the verification in zero-knowledge.  This
> is the cryptographically strongest gate the demo offers, and it
> remains secure even against the adversary the post-quantum
> standards are designed to resist."*

---

## Part 5 — The breach demo

> **What you're showing**: the breach scenario every regulator
> assumes WILL happen one day — the database is exfiltrated AND the
> at-rest encryption key is compromised.  In the legacy world this
> is catastrophic.  In the proof-based world it's a known,
> bounded leak.

1. Make sure you've registered Alice in **Proofs** mode (Part 2).
2. Click the **purple button** labelled *"Simulate exfiltration:
   generic ✓ vs gate ✗"*.  The result panel will show two
   scenarios side-by-side.

### Scenario 5a: the attacker has the proofs

The attacker now possesses the three STARK proofs from Alice's
record:

- The age proof (proves age ≥ 18, ~800 KiB)
- The country proof (proves country ∈ EU, ~1.2 MiB)
- The income proof (proves income ∈ [£40 k, £100 k], ~800 KiB)

**What the attacker learns**:
- Alice's age is in the bracket [18, ∞).  Not her exact DOB.
- Alice's country is in the EU set.  Not specifically Germany.
- Alice's income is in the band [£40 k, £100 k].  Not £45 000.

**What the attacker does NOT learn**:
- Alice's exact date of birth.
- Alice's specific country code.
- Alice's exact income.
- Her email address, postcode, sex (those were never collected by
  the proof-based version, so they were never in the database).

> **Lay explanation**: *"In the proof-based world, the worst-case
> leak is the bracketed answers — not the raw numbers.  An
> adversary who exfiltrates the database now knows that Alice is
> over 18, in the EU, and has an income in the eligibility band.
> They do not know her exact DOB, her exact country, or her exact
> income.  Compare to the legacy world, where the same breach
> would have given the adversary the literal date '1990-06-15',
> the literal country code 'DE', the literal income £45 000, plus
> her email, postcode, and sex.  The bracketed leak is what we
> traded for the privacy."*

### Scenario 5b: can the attacker forge a service response?

The simulation now tries to use the leaked proofs to impersonate
the service's `/verify/income` endpoint.  It does this by sending
the leaked proof bytes to a generic STARK verifier, AND
separately to the service's designated-verifier gate.

**Generic STARK verifier**: ✓ accepts.  The proofs ARE real, the
math holds, and any verifier checking the proofs in isolation
will believe them.

**Designated-verifier gate**: ✗ rejects.  Why?  The gate doesn't
just check that the proof is real — it requires the response to
be signed with the **service's RSA secret key** (or ML-DSA secret
key for the v2 gate).  The exfiltrated database does not contain
that key.  The attacker has the proofs but cannot produce a fresh
service-signed response.

> **Lay explanation**: *"This is the asymmetry the construction is
> designed for.  The proofs themselves are like signed receipts —
> the attacker can show them to a third party as 'I have a real
> proof Alice was eligible at the time of registration'.  But the
> service's designated-verifier gate is more like a notary stamp
> — it requires the live, currently-running service to attest 'yes,
> I just checked, and Alice IS eligible right now'.  The attacker
> cannot fake that, because the service's signing key isn't in the
> exfiltrated data.  So third parties trusting **the service's
> live API** are protected; third parties trusting **leaked proof
> bytes** are not.  The deployment chooses which threat model to
> support; the construction supports both with different
> properties."*

### Scenario 5c: terminology check — what "designated-verifier" actually means here

A common misconception worth clearing up before someone asks:
*"if the proof is stolen, can anyone run the proof, or only the
designated verifier?"*

**Answer: anyone can run a stolen proof.**  STARK proofs are
publicly-verifiable by construction.  Hand a leaked proof to any
verifier binary and it returns "yes, the math is valid, this user
satisfied the predicate at registration".  The MMIYC construction
does NOT make the proof itself non-transferable; it does NOT
restrict who can run the math.  The "designated-verifier gate"
label is loose — the real property is at a different layer.

To be precise, two trust questions to keep separate:

| Trust question | Answered by | Survives DB exfiltration? |
|---|---|---|
| *"Is the proof mathematically valid?"* | Anyone with a verifier (publicly verifiable math) | **Yes** — leaked proofs still verify forever |
| *"Did the live service just attest this user is currently eligible?"* | Only the service (signed with `sk_rsa` / `sk_ml_dsa`) | **No** — attacker can't produce new attestations |

The gate's value is at the **second** question, not the first.
When a third party (a benefits portal, a tax-credit calculator,
an age-gate) asks the service `/verify/income/<user>`, they're
not asking "is the proof valid?" — they could check that
themselves.  They're asking *"does the service, right now, with
its identity behind it, vouch that this user is eligible?"*
That second question requires the service's signing key, which
the exfiltrated database does not contain.

So the operational properties the construction actually
provides under the catastrophic-breach assumption:

1. **Bracketed leak, not exact-value leak.**  Leaked proofs
   reveal predicates ("income ∈ band Y"), not exact values
   ("£45 000").  Even with full DB + at-rest-key compromise.
2. **Replay protection on live attestations.**  Each
   `/verify/income/<id>` response is signed over a fresh
   nonce.  An attacker holding leaked proofs cannot replay
   them as a fresh service attestation, because the third
   party calling the API specifies a new nonce.
3. **Service-identity binding for newly-issued attestations.**
   A third party trusting the service's published public key
   can be sure a response came from the live service, not from
   a stale snapshot or an impersonator.  The attacker can't
   forge new attestations under the service's identity without
   `sk_rsa`.

What the construction does **not** provide:

- **Non-transferability of proofs.**  Leaked proofs reveal what
  they prove, forever.  If you want Alice to give Bob a proof
  that Bob can verify but cannot show to anyone else, that's a
  different cryptographic primitive (a proper designated-
  verifier signature scheme like Jakobsson-Sako-Impagliazzo).
  MMIYC does not implement that.
- **Privacy of leaked proof contents.**  The bracketed
  predicate is exposed.  An attacker learns "Alice's income is
  in [£40 k, £100 k]"; they don't learn "£45 000".  That's the
  privacy reduction — bracketed-leak rather than exact-value-
  leak — but the bracket itself is exposed.
- **Protection if the service itself is compromised.**  If
  `sk_rsa` is also exfiltrated (in addition to the DB), all
  bets are off.  The construction protects against DB-only
  exfiltration; it does not protect against full-service
  takeover.

> **Lay summary**: *"Anyone can verify a stolen proof — the math
> is public.  But only the live service can sign a fresh response
> with its identity attached.  Third parties choosing to trust the
> service's API instead of trusting random leaked proof bytes are
> what the gate protects."*

---

## Part 6 — What the layered defence actually buys

Recap, in plain language:

1. **Legacy world** (Part 1, "PII" scenario): a breach exposes
   exact PII for every user.  GDPR Art. 33 / 34 mandatory
   notification, regulatory exposure, civil exposure.  The leak is
   open-ended (every field for every user).
2. **Proof-based world without designated-verifier**: a breach
   exposes proof bytes.  Bracketed leak — the attacker learns
   "user X is in band Y" for every user, but not the exact value.
   Far smaller leak; still a leak, but bounded by the proof's
   policy.
3. **Proof-based world with designated-verifier gate**: a breach
   exposes proof bytes AND the at-rest key, but NOT the service's
   signing key.  Attacker can show old proofs to third parties who
   trust raw proofs; cannot impersonate the live service to
   third parties who trust the service's API.  The threat model
   distinguishes "what attackers can replay" from "what attackers
   can newly attest".
4. **Proof-based world with v2 (post-quantum) designated-verifier
   gate**: same as (3), but the signing primitive is ML-DSA-65 and
   the verification of the signature is itself proven in-circuit.
   Resistant to future cryptographically-relevant quantum
   adversaries.  Slower (25-30 s server prove), so reserved for
   high-stakes attestations.

The whole construction is a **layered defence**: each step
reduces the impact of a breach by a different mechanism.  No
single layer is meant to be the entire story — the value is in
the composition.

---

## Notes for the presenter

- The demo is fully local (single laptop), no third-party
  services involved.  Everything you see in the browser is the
  WASM prover/verifier loaded into the page; the server is a Rust
  process on the same machine.
- The 25-second wait on the gold v2 button is real STARK proving,
  not a sleep call.  If you have to fill the silence, that's a
  good moment to walk through the FIPS 204 §3 Algorithm 3 list
  shown on the page (V17 polynomial-arithmetic, NTT consistency,
  norm bounds, UseHint, W1Encode, transcript SHAKE-256, c̃ = c̃′
  acceptance).  The point isn't to teach the audience FIPS 204 —
  it's to convince them the in-circuit proof is doing real work,
  not a stub.
- The bundle size in the browser Network tab tells you whether
  STIR or FRI is active under the hood.  ~7 MiB → STIR.  ~80
  MiB → FRI.  If you started the server with `BENCH_LDT=stir` in
  the environment, you should see ~7 MiB.
- "Service-attested" and "designated-verifier" are
  interchangeable in the lay narration.  The phrasing on the page
  uses "service-attested" in the success message and
  "designated-verifier" in the technical detail; both describe
  the same property.
- For the breach demo (Part 5) you can also point at the
  developer-tools Application tab → IndexedDB / Cookies and
  confirm the absence of cleartext PII in browser state.  If a
  forensic examiner had access to the laptop only, they'd find
  the proofs but not the raw values.

## Suggested button-label changes (for a future polish pass)

The current button labels assume the visitor knows what "v1.5",
"v1.7", "v2", "RSA-STARK", "ML-DSA-STARK" mean.  For a public-
facing demo, the proposal is to rename:

| Current label | Proposed lay-friendly label | Audience tag |
|---|---|---|
| Verify income (RSA-STARK gate) | Service-attested check (RSA, classical) | "fast, current standard" |
| Verify income (ML-DSA-STARK gate) | Service-attested check (post-quantum, basic) | "PQ-ready, simple" |
| Verify income (v1.5 + norm bound) | Service-attested check (PQ, norm-bound check) | "researcher-grade" |
| Verify income (v1.7 PQ-airtight gate) | Service-attested check (PQ, NTT-consistency check) | "researcher-grade" |
| Verify income (v2 layer-1-free gate) | Service-attested check (PQ, full FIPS 204 in-circuit) | "strongest, slow" |
| Simulate exfiltration: generic ✓ vs gate ✗ | Simulate database breach: which guarantees survive? | breach demo |

Implementation: `frontend/index.html` lines ~554-585 and the JSON
emitted by `/service/scheme`.  Each rename is a one-line label
change plus an optional adjacent paragraph explaining what the
button means in the lay-friendly text already on the page.

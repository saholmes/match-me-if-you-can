# Threat Model

## Setting

A standard web application (registration, login, account management) handling
personally identifiable information. The operator is a typical SaaS business
or public-facing service subject to UK / EU GDPR. The user population is the
general public.

## Assets

| Asset | Description | Scenario A (PII) | Scenario B (Proofs) |
|---|---|---:|---:|
| Date of birth | calendar date | stored verbatim | not stored |
| Country code | 2-char ISO 3166 | stored verbatim | not stored |
| Postcode prefix | UK first 2–4 chars | stored verbatim | not stored |
| Email address | RFC 5322 | stored verbatim | hash + domain proof |
| Income bracket | numeric range | stored verbatim | not stored |
| Authorisation predicates | derived | computed at query time | stored as STARK proof |

## Adversary

A **passive observer with full read access to the at-rest database**, plus
the ability to consult publicly-available auxiliary databases:

- electoral-roll snapshots (UK Electoral Commission, partial)
- breach corpora (Have I Been Pwned, sectoral leaks)
- social-media exports (LinkedIn, X, Facebook bulk leaks)
- voter-registration data (US states, Brazil, similar)
- commercial data brokers (Acxiom-equivalent)

This is the **classical "honest-but-curious database breach"** — the
adversary does not actively interfere with the service, but at some
moment they obtain a complete read snapshot of the back-end store. The
adversary then attempts to *link* records in the breach to identities in
the auxiliary databases, completing the picture and enabling identity
theft, targeted phishing, or regulatory weaponisation.

The adversary is **bounded by classical computation** for the breach-
window analysis, but should additionally be assumed
**post-quantum-capable** for forward-secrecy claims about the proof
storage (one of STARK-STIR's selling points).

## What we explicitly do NOT defend against

- **Active service compromise**: an attacker with code-execution on the
  service can intercept PII before the proof is generated. Mitigations
  (TEE, client-side WASM prover) are discussed in §[future-work] but not
  the focus of this paper.
- **Side channels in the prover**: timing-based attribute leaks during
  proof generation are out of scope. The paper assumes the prover runs in
  a constant-time configuration.
- **Targeted compulsion**: legal demand to disclose the proofs themselves
  does not reduce to disclosure of the underlying values, but a court can
  compel either party to re-prove or otherwise reveal. Not addressed.
- **Verifier-side log leakage**: query-time logging of the verifier's
  decisions could in principle leak information; we assume verifier logs
  are subject to the same controls as any production access logs.

## Security claim (informal)

For each PII attribute stored in scenario B, an adversary holding the
breach data alone (no auxiliary information) cannot recover the
attribute's value with non-negligible probability beyond the *prior
distribution* of that attribute over the user population. Specifically:

- A range-proof of "age ≥ 18" reveals no information beyond the prior
  Pr[age ≥ 18 | user-population] minus the verifier's published policy
  binding.
- A set-membership proof of "country ∈ EU" reveals no information beyond
  Pr[country ∈ EU | user-population].

The classical STARK soundness and zero-knowledge properties of
STARK-STIR underwrite this claim. The paper does not re-derive STARK
ZK properties; it cites the upstream work.

## Comparison to scenario A (baseline)

For each attribute in scenario A, an adversary with the breach **and**
the right auxiliary database typically achieves >85 % re-identification
on the bulk of the user population, especially when ≥ 3 attributes are
present (the well-known "5-attribute uniqueness" result for postcode +
DOB + sex + first name + employer).

## Regulatory framing

Under UK / EU GDPR:

- **Art. 32** — security of processing: pseudonymisation and encryption
  are listed as appropriate technical measures.
- **Art. 4(5)** — pseudonymisation definition: the data should not be
  attributable to a specific data subject "without the use of additional
  information [kept separately]". Storing only proofs satisfies this
  more strongly than storing encrypted PII (where the key is the
  additional information).
- **Art. 33–34** — breach notification: the obligation reduces if the
  leaked data is "unintelligible" to anyone unauthorised. Proofs alone
  are arguably unintelligible in a stronger sense than ciphertext-with-
  key-elsewhere.
- **Art. 83** — fines: scaled to "the nature, gravity and duration of
  the infringement" and "the categories of personal data affected". The
  paper's empirical contribution is to quantify the differential under
  realistic ICO / EU DPA precedents.

## Out of scope but worth noting

The "right to be forgotten" (Art. 17) interacts oddly with proof
storage: deleting an attribute means deleting the proof, but the
proof's existence may itself be metadata. The paper notes this in
limitations.

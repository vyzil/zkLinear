# Parity Trace Matrix

This matrix defines what should be compared across currently available paths in this repo.

Compared paths:
- Spartan-like report-data path (`api/spartan_like`)
- Full-style NIZK path (`nizk/spartan_brakedown`)

## Must Match (same input case)

- case shape (`rows`, `cols`, `z.len`)
- `Az`, `Bz`, `Cz` derived from `(A,B,C,z)`
- residual vector `Az*Bz - Cz`
- outer-claim initial scalar:
  - `sum(eq(tau) * residual)` where `tau = derive_outer_tau_sha(...)`
- outer round count (`log2(rows)`)
- inner round count (`log2(cols)`)

These are transcript-schedule-independent invariants for the same case input.

## May Differ by Design

- outer/inner per-round challenges
- `gamma` and values derived from `gamma`
- joint bound and unblinded inner claim
- masked-claim values and blind components
- PCS query indices/openings and Merkle paths

Reason:
- the Spartan-like report path uses local SHA-style challenge flow
- the NIZK path uses a single Merlin transcript with different message ordering/binding

## Testing Policy

- parity tests should hard-assert only the **Must Match** section
- differences in the **May Differ** section should be documented, not treated as test failures

# zkLinear Code TODO (Immediate Engineering)

This is a concrete code-first TODO list for moving from "research E2E" to
"paper-ready engineering quality" without waiting for external audits.

## 1) Verifier Boundary Hard Lock
- Replace benchmark/report paths to use only `verify_with_compiled(...)`.
- Keep `verify_from_dir(...)` as debug-only and mark it clearly in code/docs.
- Add a test that fails if benchmark code accidentally calls strict replay verify.

## 2) Parameter + Context Fingerprint
- Add a deterministic fingerprint to compiled artifacts:
  - field profile
  - PCS knobs (`n_degree_tests`, `n_col_opens`, encoder settings)
  - transcript domain/version
- Enforce fingerprint equality in `prove` and `verify`.
- Add negative tests for fingerprint mismatch.

## 3) Wire-First Proof/Public Artifacts
- Keep JSON for readability/debug only.
- Add binary wire files for:
  - compiled
  - proof
  - public
- Make benchmark/proof-size reporting use wire bytes only.

## 4) Single Metrics Runner
- Add one benchmark runner that outputs machine-readable CSV/JSON:
  - prove ms
  - verify ms
  - proof bytes
  - payload breakdown
- Include warmup + repeated runs + avg/stddev in one place.
- Remove duplicated timing logic from multiple binaries.

## 5) Conformance Test Upgrade
- Strengthen external reference parity tests from optional to must-pass mode.
- Add transcript/challenge/opening-index conformance checks for multiple cases.
- Keep snapshots versioned with explicit update commands.

## 6) Report Consistency Cleanup
- Ensure field/profile labels always match actual active modulus/profile.
- Keep one canonical report schema for prove/inspect/verify stages.

## 7) CI Gate for Claims
- Add CI target that must pass before sharing performance numbers:
  - full tests
  - conformance tests
  - benchmark runner sanity check

---

## Suggested Execution Order
1. Verifier Boundary Hard Lock
2. Parameter + Context Fingerprint
3. Wire-First Artifacts
4. Single Metrics Runner
5. Conformance Test Upgrade
6. Report Consistency Cleanup
7. CI Gate


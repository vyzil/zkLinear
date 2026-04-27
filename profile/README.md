# Profile Workspace

This folder is dedicated to **analysis/profiling workflows** for
Spartan2 + Brakedown + Spielman encoding.

## Goals

1. Understand end-to-end flow with rich runtime explanation
- what each phase does
- what data shape moves between phases
- what is stored in proof/public boundary
- what verifier reads and recomputes
- which transcript labels/randomness paths are used

2. Profile kernel performance
- measure time while changing field/profile/scale
- optionally collect CPU counters (cache misses, branches, etc.)

## Quick Start

From repo root (`zkLinear/`):

```bash
# 1) Detailed E2E explain log
./profile/scripts/explain_e2e.sh

# 2) Multi-profile timing matrix (markdown)
./profile/scripts/profile_matrix.sh

# 3) Structured metrics output (json/csv)
./profile/scripts/profile_metrics.sh

# 4) Optional Linux perf counters (cache-miss, branch-miss, ...)
./profile/scripts/profile_perf.sh
```

Outputs are written under `profile/out/`.

## Scripts

- `scripts/explain_e2e.sh`
  - Runs `profile_e2e_explain` and prints step-by-step E2E trace.
  - Args: `[instance_dir] [profile] [head_len]`

- `scripts/profile_matrix.sh`
  - Runs profile matrix summary as Markdown.
  - Args: `[instance_dir] [runs] [profiles_csv] [out_md]`

- `scripts/profile_metrics.sh`
  - Runs repeated metrics and writes JSON/CSV.
  - Args: `[instance_dir] [out_prefix] [profile] [warmup_runs] [measured_runs]`

- `scripts/profile_perf.sh`
  - Same metrics runner under `perf stat` with hardware counters.
  - Args: `[instance_dir] [out_prefix] [profile] [warmup_runs] [measured_runs]`

## Notes

- For stable benchmarking, use `--release` paths (scripts already do).
- `perf` requires Linux + permissions (`perf_event_paranoid` setup may be needed).
- The explain mode is verbose by design and intended for research/debug analysis.

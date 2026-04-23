# Circom Repeat E2E Scaling

Command used:

```bash
for k in 8 9 10 11 12 13 14; do
  cargo run -q --bin circom_repeat_e2e_demo "$k"
done
```

Measured timings (ms):

| k | constraints | input_parse | spartan_prove_core | pcs_commit_open_prove | verify | total |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 256 | 1.011 | 21.695 | 1.616 | 24.490 | 48.813 |
| 9 | 512 | 1.867 | 41.027 | 1.630 | 46.554 | 91.077 |
| 10 | 1024 | 4.626 | 85.174 | 1.696 | 91.196 | 182.691 |
| 11 | 2048 | 8.376 | 206.914 | 2.363 | 179.246 | 396.899 |
| 12 | 4096 | 14.820 | 342.986 | 1.556 | 380.074 | 739.435 |
| 13 | 8192 | 30.971 | 709.394 | 1.537 | 708.893 | 1450.795 |
| 14 | 16384 | 66.570 | 1402.081 | 1.485 | 1514.993 | 2985.129 |

Notes:
- This benchmark uses `RepeatEq(2^k)` constraints in circom (same variable footprint, growing row count).
- Current path converts circom JSON to dense `A/B/C` rows in zkLinear.
- Results are for profiling trend, not production-optimized absolute numbers.

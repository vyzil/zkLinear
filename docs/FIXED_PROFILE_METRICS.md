# Fixed Profile Metrics (Case: inner_sumcheck_spartan)

| metric | mean_ms | min_ms | max_ms |
|---|---:|---:|---:|
| K0 input parse | 0.071 | 0.059 | 0.113 |
| K1 Spartan prove | 0.827 | 0.800 | 0.883 |
| K2 PCS prove | 1.753 | 1.698 | 1.854 |
| K3 verify | 3.122 | 3.041 | 3.205 |
| Total (K0+K1+K2+K3) | 5.773 | 5.669 | 5.941 |

## Payload Size (bytes)

| component | bytes |
|---|---:|
| verifier commitment wire | 106 |
| main PCS opening wire | 912 |
| blind PCS opening #1 wire | 912 |
| blind PCS opening #2 wire | 912 |
| PCS subtotal | 2842 |
| sumcheck rounds (field elements only, est.) | 104 |
| scalar public/proof values (est.) | 40 |
| protocol subtotal (PCS + estimates) | 2986 |

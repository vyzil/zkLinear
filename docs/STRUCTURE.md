# File Structure

## Runtime Modules
- `src/nizk/`
  - 실제 proof/public 경계와 verify 로직
- `src/pcs/brakedown/`
  - commitment/open/verify, wire codec, encoder, challenge sampling
- `src/sumcheck/`
  - inner/outer sumcheck core
- `src/protocol/`
  - transcript/spec/shared helper
- `src/io/`
  - case/R1CS import

## Entrypoints
- `src/bin/spark_e2e_cli.rs`
  - compile / prove / verify / inspect
- `src/main.rs`
  - 개발용 데모 엔트리

## Test Scope (kept)
- PCS 정합성/직렬화
- NIZK prove/verify 경계
- compiled boundary consistency
- shape guard / field profile / transcript vector 핵심
- leakage probe (reference-style 위험 재현)

## Excluded from default scope
- parity snapshot 비교
- external reference repo pinning
- 장기 프로파일링/메트릭 문서 생성 테스트

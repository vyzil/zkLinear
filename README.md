# zkLinear

Spartan2-like + Brakedown-like PCS 조합을 연구/검증하는 Rust 코드베이스입니다.
현재 기준의 실제 공개 검증 경로는 `nizk::spartan_brakedown` 입니다.

## 핵심 포인트
- proof/public 경계를 최소화한 NIZK 경로 유지
- metadata(`reference_profile`, `context_fingerprint`)는 sidecar로 분리
- `spark_e2e_cli` 기반 compile/prove/verify 워크플로우 제공

## 프로젝트 구조
- `src/nizk/`: proof/public 타입, prove/verify 경계
- `src/pcs/brakedown/`: PCS(encoding/commit/open/verify/wire)
- `src/sumcheck/`: inner/outer sumcheck
- `src/protocol/`: transcript/spec/shared helper
- `src/io/`: case 및 R1CS import
- `src/bin/spark_e2e_cli.rs`: 운영용 CLI

자세한 구조/설계는 문서 참고:
- `docs/DESIGN.md`
- `docs/STRUCTURE.md`
- `docs/RUNBOOK.md`
- `docs/SPEC_V1.md`

## 빠른 실행
```bash
cargo run --bin spark_e2e_cli -- compile tests/inner_sumcheck_spartan /tmp/compiled.json m61
cargo run --bin spark_e2e_cli -- prove /tmp/compiled.json tests/inner_sumcheck_spartan /tmp/proof.json /tmp/public.json
cargo run --bin spark_e2e_cli -- verify /tmp/compiled.json /tmp/proof.json /tmp/public.json
```

## 테스트
```bash
cargo test -q
```

현재 테스트셋은 핵심 정합성(PCS/NIZK/compiled boundary/shape guard/leakage probe) 위주로 최소화되어 있습니다.

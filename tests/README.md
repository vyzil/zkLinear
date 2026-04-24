# Tests

현재 `cargo test` 기본셋은 최종 경로에 필요한 핵심 항목만 유지합니다.

## 포함 범위
- PCS commit/open/verify + wire codec
- NIZK prove/verify (public + compiled boundary)
- 입력 shape guard
- field profile 산술 sanity
- transcript/spec 경계 sanity
- leakage probe

## 실행
```bash
cargo test -q
```

추가 프로파일링/대규모 벤치/외부 레퍼런스 parity 테스트는
필요 시 별도 테스트로 재도입하는 것을 권장합니다.

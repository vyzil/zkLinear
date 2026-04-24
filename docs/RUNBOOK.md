# Runbook

## Build
```bash
cargo build
```

## Main CLI (recommended)
```bash
cargo run --bin spark_e2e_cli -- compile tests/inner_sumcheck_spartan /tmp/compiled.json m61
cargo run --bin spark_e2e_cli -- prove /tmp/compiled.json tests/inner_sumcheck_spartan /tmp/proof.json /tmp/public.json
cargo run --bin spark_e2e_cli -- verify /tmp/compiled.json /tmp/proof.json /tmp/public.json
cargo run --bin spark_e2e_cli -- inspect /tmp/proof.json
```

## Metadata Sidecars
`prove` 단계에서 아래 sidecar가 생성된다.
- `proof.meta.json`, `proof.meta.wire`
- `public.meta.json`, `public.meta.wire`

core proof/public은 verify 판정에 사용되고,
meta는 운영/추적/디버그 정보를 분리 저장하는 용도다.

## Minimal Test Set
```bash
cargo test -q
```

핵심 경로만 남겨둔 상태이며,
추가 프로파일링/확장 테스트는 이후 별도 추가를 권장한다.

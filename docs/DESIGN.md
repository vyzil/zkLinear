# Design

`zkLinear`는 Spartan2-like + Brakedown-like PCS 조합을 연구/구현하는 코드베이스다.
현재 기준에서 "실제 검증 경로"는 `nizk::spartan_brakedown`의 `verify_public` / `verify_with_compiled` 이다.

## Core Principles
- Proof/Public 경계 최소화
  - `proof`에는 canonical sumcheck 메시지와 PCS opening만 포함
  - `public`에는 shape/digest/profile만 포함
- 메타 분리
  - `reference_profile`, `context_fingerprint`는 sidecar metadata로 분리
  - 검증 성공/실패 판정은 proof/public core + compiled 일관성으로 결정
- Transcript 일관성
  - outer/inner/PCS challenge는 단일 transcript 도메인 규약을 따름

## Verification Boundaries
- `verify_public(proof, public)`
  - 공개 입력만으로 compact sumcheck + PCS claimed evaluation을 검증
- `verify_with_compiled(compiled, proof, public)`
  - `verify_public` + compiled/public/proof shape/profile/digest 일관성 검증
- `verify_from_dir_strict(...)`
  - 디버그/리플레이 경로 (입력 케이스 재로딩)

## PCS Notes
- encoder는 `BrakedownEncoderKind` 기반
- 현재 공개 검증 경로에서 column opening 샘플링은 `col_open_start`를 반영
- wire 포맷은 `pcs/brakedown/wire.rs`에서 관리

## Non-Goals
- 이 저장소는 production-hardening 완료본이 아님
- 외부 레퍼런스와 바이트 단위 동일성은 목표가 아님

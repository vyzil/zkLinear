# zkLinear Spec v1 (Current)

이 문서는 현재 코드베이스의 검증 경계와 transcript 계약을 고정한다.

## 1. Transcript
- 엔진: `merlin`
- 도메인: `zklinear/v1/spartan-brakedown`
- NIZK 라벨: `zklinear/v1/spartan-brakedown/nizk`

## 2. Canonical Sumcheck Messages
- outer round: prover -> verifier 에 `g(0), g(2), g(3)` 전달
- inner round: prover -> verifier 에 `h(0), h(1), h(2)` 전달
- 각 round challenge는 transcript replay로 검증

## 3. Public/Proof Boundary

### proof 포함
- compact outer/inner trace
- `gamma`
- `verifier_commitment`
- `pcs_proof_joint_eval_at_r`

### public 포함
- `rows`, `cols`
- `case_digest`
- `field_profile`

### meta(sidecar) 포함
- `reference_profile`
- `context_fingerprint`

메타는 관측/운영용이며 verify accept/reject의 필수 입력이 아니다.

## 4. Verify APIs
- `verify_public(proof, public)`
  - 공개 경계 검증
  - sumcheck transition + PCS claimed-evaluation 검증
- `verify_with_compiled(compiled, proof, public)`
  - `verify_public` + compiled/public 일관성 체크

## 5. PCS Wire Contract
- verifier commitment 태그: `ZKVCB001`
- eval proof 태그: `ZKPFB002`
- unknown tag/version, trailing bytes는 reject
- field decode는 canonical range를 강제

## 6. Column Sampling Contract
- open column은 transcript 기반 deterministic sampling
- sampling range는 `[col_open_start, n_cols)`
- `n_open <= n_cols - col_open_start` 강제

## 7. Profile Contract
- default reference profile: `Spartan2Like + LcpcBrakedownLike`
- default field profile: `Mersenne61Ext2`
- production-like preset에서는 고정 challenge count를 사용
  - `n_degree_tests = 8`
  - `n_col_opens = 16`

## 8. Scope
- 본 spec은 이 저장소의 현재 구현 경계 정의다.
- Spartan2/lcpc와의 완전 동등성(바이트 단위)을 주장하지 않는다.

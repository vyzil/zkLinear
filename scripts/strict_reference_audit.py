#!/usr/bin/env python3
import json
import pathlib
import re
import subprocess
import sys


def read(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8")


def has(text: str, pattern: str) -> bool:
    return re.search(pattern, text, flags=re.MULTILINE) is not None


def run_rg(repo: pathlib.Path, pattern: str, path_glob: str) -> bool:
    cmd = [
        "rg",
        "-n",
        pattern,
        str(repo / path_glob),
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode == 0


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parents[1]
    flow = read(repo / "src/nizk/flow.rs")
    spec = read(repo / "src/protocol/spec_v1.rs")
    shared = read(repo / "src/protocol/shared.rs")
    transcript = read(repo / "src/core/transcript.rs")
    pcs_chal = read(repo / "src/pcs/brakedown/challenges.rs")
    pcs_prove = read(repo / "src/pcs/brakedown/prove.rs")
    pcs_verify = read(repo / "src/pcs/brakedown/verify.rs")
    e2e = read(repo / "tests/e2e.rs")
    brakedown_tests = read(repo / "tests/brakedown.rs")
    types = read(repo / "src/nizk/types.rs")
    wire = read(repo / "src/pcs/brakedown/wire.rs")
    cli = read(repo / "src/bin/spark_e2e_cli.rs")

    status = {}
    notes = {}

    # 1) Transcript labels + append order (strict reference-equivalence)
    # Expect fail unless transcript labels and domain align to Spartan2/lcpc conventions.
    if has(spec, r'NIZK_TRANSCRIPT_LABEL:\s*&\[u8\]\s*=\s*b"SpartanSNARK"'):
        status["1"] = "PASS"
    else:
        status["1"] = "FAIL"
        notes["1"] = "NIZK transcript label/domain are zkLinear-specific, not Spartan2/lcpc-equivalent."

    # 2) Commit-before-challenge ordering
    prove_start = flow.find("let mut tr_p = Transcript::new(NIZK_TRANSCRIPT_LABEL);")
    prove_scope = flow[prove_start : prove_start + 5000] if prove_start >= 0 else flow
    i_commit = prove_scope.find('tr_p.append_message(b"polycommit"')
    i_ncols = prove_scope.find('append_u64_le(&mut tr_p, b"ncols"')
    i_tau = prove_scope.find("sample_outer_tau_from_transcript(&mut tr_p")
    commit_before_tau = (
        i_commit >= 0
        and i_ncols >= 0
        and i_tau >= 0
        and i_commit < i_tau
        and i_ncols < i_tau
    )
    status["2"] = "PASS" if commit_before_tau else "FAIL"
    if status["2"] == "FAIL":
        notes["2"] = "Commitment binding does not occur before outer challenge sampling."

    # 3) Canonical sumcheck message form + challenge derivation
    # Spartan2 references absorb univariate polynomial "p" then squeeze "c".
    # zkLinear strict-equivalence would need that pattern in live verifier path.
    uses_spartan2_pc = has(flow, r'absorb\(b"p"') or has(transcript, r'challenge_bytes\(b"c"')
    status["3"] = "PASS" if uses_spartan2_pc else "FAIL"
    if status["3"] == "FAIL":
        notes["3"] = "Round challenges are derived from msg_0/msg_1/msg_2 fields, not absorb(\"p\")->squeeze(\"c\")."

    # 4) Joint challenge derivation points
    # PASS when a single reference-style r challenge is sampled and expanded into
    # fixed coefficients (1, r, r^2) for joint binding.
    if (
        has(shared, r'challenge_bytes\(JOINT_CHALLENGE_R_LABEL')
        and has(shared, r"let r_a = Fp::new\(1\)")
        and has(shared, r"let r_b = r;")
        and has(shared, r"let r_c = r\.mul\(r\);")
    ):
        status["4"] = "PASS"
    else:
        status["4"] = "FAIL"
        notes["4"] = "Joint challenge derivation does not follow single-r expansion semantics."

    # 5) PCS degree-test + column-open semantics
    # lcpc reference uses with-replacement over full [0,n_cols).
    with_replacement = has(pcs_chal, r"repeat_with") and has(pcs_chal, r"Uniform::new")
    full_range_no_start = not has(pcs_chal, r"start_col")
    status["5"] = "PASS" if (with_replacement and full_range_no_start) else "FAIL"
    if status["5"] == "FAIL":
        notes["5"] = "Column sampling uses unique/no-replacement and start-gated range."

    # 6) Systematic region opening policy
    # PASS only if no systematic exclusion policy appears.
    has_systematic_gate = has(pcs_chal, r"start_col") or has(brakedown_tests, r"col_open_start")
    status["6"] = "FAIL" if has_systematic_gate else "PASS"
    if status["6"] == "FAIL":
        notes["6"] = "Systematic-region exclusion policy exists via col_open_start."

    # 7) Verifier boundary
    boundary_ok = (
        has(cli, r"verify_with_compiled\(")
        and not has(cli, r"verify_strict\(")
        and has(flow, r"pub fn verify_strict")
        and has(flow, r"pub fn verify_public")
    )
    status["7"] = "PASS" if boundary_ok else "FAIL"
    if status["7"] == "FAIL":
        notes["7"] = "Public/strict boundaries are not clearly separated on CLI/runtime path."

    # 8) proof/public/wire fields + rejection behavior (strict reference-equivalence)
    # PASS only if dedicated reference-compatible codec/mode exists.
    has_ref_codec = run_rg(repo, r"reference_compat|spartan2_wire|lcpc_wire", "src")
    status["8"] = "PASS" if has_ref_codec else "FAIL"
    if status["8"] == "FAIL":
        notes["8"] = "Only zkLinear-native proof/public/wire schema is present."

    # 9) Encoder profile enforcement
    encoder_policy_ok = (
        has(flow, r"enforce_reference_aligned_commitment_profile")
        and has(e2e, r"e2e_008")
        and has(e2e, r"e2e_009")
        and has(e2e, r"e2e_010")
    )
    status["9"] = "PASS" if encoder_policy_ok else "FAIL"
    if status["9"] == "FAIL":
        notes["9"] = "Reference-aligned Spielman encoder policy is not fully enforced/tested."

    # 10) Failure behavior on tamper cases
    tamper_suite_ok = (
        has(e2e, r"e2e_003")
        and has(e2e, r"e2e_004")
        and has(e2e, r"e2e_011")
        and has(e2e, r"e2e_012")
        and has(brakedown_tests, r"trailing bytes")
    )
    status["10"] = "PASS" if tamper_suite_ok else "FAIL"
    if status["10"] == "FAIL":
        notes["10"] = "Tamper/rejection coverage is missing required paths."

    p0_items = ["1", "3", "4", "5"]
    p1_items = ["6", "8"]
    total_fail = sum(1 for i in status.values() if i == "FAIL")
    p0_fail = sum(1 for i in p0_items if status[i] == "FAIL")
    p1_fail = sum(1 for i in p1_items if status[i] == "FAIL")

    out = {
        "metric_name": "strict_reference_fail_count",
        "total_fail_count": total_fail,
        "p0_fail_count": p0_fail,
        "p1_fail_count": p1_fail,
        "per_item_status": status,
        "notes": notes,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

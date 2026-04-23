use crate::core::field::{current_modulus, Fp};

use super::data::SpartanLikeReportData;

fn fmt_vec(v: &[Fp]) -> String {
    format!("{:?}", v.iter().map(|x| x.0).collect::<Vec<_>>())
}

fn fmt_matrix(m: &[Vec<Fp>]) -> String {
    let rows: Vec<String> = m.iter().map(|row| fmt_vec(row)).collect();
    format!("[\n  {}\n]", rows.join(",\n  "))
}

fn explain_bound(name: &str, matrix: &[Vec<Fp>], weights: &[Fp], bound: &[Fp]) -> String {
    let p = current_modulus();
    let mut s = String::new();
    s.push_str(&format!("{}[j] = sum_i eq_i * {}[i][j]\n", name, name));
    for j in 0..bound.len() {
        let mut terms = Vec::new();
        for i in 0..matrix.len() {
            if matrix[i][j] != Fp::zero() {
                terms.push(format!("{}*{}", weights[i].0, matrix[i][j].0));
            }
        }
        if terms.is_empty() {
            terms.push("0".to_string());
        }
        s.push_str(&format!(
            "  {}[{}] = ({}) mod {} = {}\n",
            name,
            j,
            terms.join(" + "),
            p,
            bound[j].0
        ));
    }
    s
}

pub fn format_spartan_like_report(data: &SpartanLikeReportData) -> String {
    let p = current_modulus();
    let mut out = String::new();
    out.push_str("=== Spartan-like R1CS Sumcheck Report ===\n");
    out.push_str("--------------------------------------------------\n");
    out.push_str("\n[Info]\n");
    out.push_str(&format!("field: F_{}\n", p));
    out.push_str("hash/transcript: SHA-256 Fiat-Shamir\n");
    out.push_str(&format!(
    "outer challenge format: r = H(\"spartan-outer-sumcheck\", round, g(0), g(2), g(3)) mod {}\n",
    p
  ));
    out.push_str(&format!(
        "inner challenge format: r = H(label, round, h0, h1, h2) mod {}\n",
        p
    ));
    out.push_str(&format!(
        "shape: rows={}, cols={}\n",
        data.case.a.len(),
        data.case.a[0].len()
    ));
    out.push_str(&format!("z: {}\n", fmt_vec(&data.case.z)));
    out.push_str(&format!("A:\n{}\n", fmt_matrix(&data.case.a)));
    out.push_str(&format!("B:\n{}\n", fmt_matrix(&data.case.b)));
    out.push_str(&format!("C:\n{}\n", fmt_matrix(&data.case.c)));

    out.push_str("\n[Claim]\n");
    out.push_str(&format!("Az = A*z = {}\n", fmt_vec(&data.az)));
    out.push_str(&format!("Bz = B*z = {}\n", fmt_vec(&data.bz)));
    out.push_str(&format!("Cz = C*z = {}\n", fmt_vec(&data.cz)));
    out.push_str(&format!(
        "residual = Az*Bz-Cz = {}\n",
        fmt_vec(&data.residual)
    ));
    out.push_str("outer claim uses eq(tau, x) weighting (Spartan-style):\n");
    out.push_str(&format!("tau = {}\n", fmt_vec(&data.tau)));
    out.push_str(&format!("eq(tau) = {}\n", fmt_vec(&data.eq_tau)));
    out.push_str(&format!(
        "weighted_residual = eq(tau) * residual = {}\n",
        fmt_vec(&data.weighted_residual)
    ));
    out.push_str("--------------------------------------------------\n");

    out.push_str("\n[Outer Prove]\n");
    out.push_str(&format!(
        "initial claim C0 = sum(weighted_residual) = {}\n",
        data.outer_trace.claim_initial.0
    ));
    for r in &data.outer_trace.rounds {
        let folded_sum = r
            .folded_values
            .iter()
            .fold(Fp::zero(), |acc, v| acc.add(*v));
        out.push_str(&format!(
            "  round {} -> send g(0)={}, g(2)={}, g(3)={}, challenge_r=hash({}, {}, {}, {})={}\n",
            r.round,
            r.g_at_0.0,
            r.g_at_2.0,
            r.g_at_3.0,
            r.round,
            r.g_at_0.0,
            r.g_at_2.0,
            r.g_at_3.0,
            r.challenge_r.0
        ));
        out.push_str("    verifier derives g(1) from claim relation g(0)+g(1)=claim_in\n");
        out.push_str(&format!(
            "    folded residual = {:?}\n",
            r.folded_values.iter().map(|x| x.0).collect::<Vec<_>>()
        ));
        out.push_str(&format!(
            "    next claim (from folded residual sum) = {}\n",
            folded_sum.0
        ));
    }
    out.push_str(&format!(
        "outer prove end: final_value={} | final_claim={}\n",
        data.outer_trace.final_value.0, data.outer_trace.final_claim.0
    ));
    out.push_str("--------------------------------------------------\n");

    out.push_str("\n[Dependency]\n");
    out.push_str("Inner phase depends on outer challenges r_x.\n");
    out.push_str("r_x is NOT newly sampled; it reuses outer-round Fiat-Shamir challenges.\n");
    for rr in &data.outer_trace.rounds {
        out.push_str(&format!(
            "  r_x[{}] = H(\"spartan-outer-sumcheck\", {}, g0={}, g2={}, g3={}) mod {} = {}\n",
            rr.round, rr.round, rr.g_at_0.0, rr.g_at_2.0, rr.g_at_3.0, p, rr.challenge_r.0
        ));
    }
    out.push_str(&format!("r_x = {}\n", fmt_vec(&data.r_x)));
    out.push_str("eq(r_x) weights are built by iterative split with w.\n");
    out.push_str("  start: w^(0) = [1]\n");
    for (i, r) in data.r_x.iter().enumerate() {
        let one_minus_r = Fp::new(1).sub(*r);
        out.push_str(&format!(
            "  step {} with r_x[{}]={}: each w -> [w*(1-r), w*r], where (1-r)={}\n",
            i, i, r.0, one_minus_r.0
        ));
        out.push_str(&format!(
            "    w^({}) = {}\n",
            i + 1,
            fmt_vec(&data.eq_states[i + 1])
        ));
    }
    out.push_str(&format!(
        "eq(r_x) row weights = {}\n",
        fmt_vec(&data.row_weights)
    ));
    out.push_str("--------------------------------------------------\n");

    out.push_str("\n[Inner Prove: Spartan-like JOINT path]\n");
    out.push_str("joint challenge is Fiat-Shamir sampled from (Az || Bz || Cz).\n");
    out.push_str(&format!(
        "gamma = H(\"spartan-like-joint-challenge\", Az, Bz, Cz) mod {} = {}\n",
        p, data.gamma.0
    ));
    out.push_str(&format!(
        "  Az input = {}\n  Bz input = {}\n  Cz input = {}\n",
        fmt_vec(&data.az),
        fmt_vec(&data.bz),
        fmt_vec(&data.cz)
    ));
    out.push_str(&format!("gamma^2 mod {} = {}\n", p, data.gamma_sq.0));
    out.push_str(&explain_bound(
        "A",
        &data.case.a,
        &data.row_weights,
        &data.a_bound,
    ));
    out.push_str(&explain_bound(
        "B",
        &data.case.b,
        &data.row_weights,
        &data.b_bound,
    ));
    out.push_str(&explain_bound(
        "C",
        &data.case.c,
        &data.row_weights,
        &data.c_bound,
    ));
    out.push_str(&format!("A_bound = {}\n", fmt_vec(&data.a_bound)));
    out.push_str(&format!("B_bound = {}\n", fmt_vec(&data.b_bound)));
    out.push_str(&format!("C_bound = {}\n", fmt_vec(&data.c_bound)));
    out.push_str(&format!(
        "joint_bound = A_bound + gamma*B_bound + gamma^2*C_bound = {}\n",
        fmt_vec(&data.joint_bound)
    ));

    out.push_str(&format!(
        "joint initial claim = {}\n",
        data.joint_trace.claim_initial.0
    ));
    for rr in &data.joint_trace.rounds {
        out.push_str(&format!(
            "  round {} -> h0={}, h1={}, h2={}, challenge_r=hash({}, {}, {}, {})={}\n",
            rr.round,
            rr.h_at_0.0,
            rr.h_at_1.0,
            rr.h_at_2.0,
            rr.round,
            rr.h_at_0.0,
            rr.h_at_1.0,
            rr.h_at_2.0,
            rr.challenge_r.0
        ));
        out.push_str(&format!(
            "    folded f={} | folded g={}\n",
            fmt_vec(&rr.folded_f),
            fmt_vec(&rr.folded_g)
        ));
    }
    out.push_str("--------------------------------------------------\n");

    out.push_str("\n[Proof Payload]\n");
    out.push_str("Values verifier needs (recomputing Fiat-Shamir challenges locally):\n");
    out.push_str(&format!(
        "  outer initial claim: {}\n",
        data.outer_trace.claim_initial.0
    ));
    out.push_str("  outer rounds: [(g(0), g(2), g(3))]\n");
    out.push_str("  outer-derived point: r_x (from outer transcript)\n");
    out.push_str("  eq(r_x) row weights (recomputed from r_x)\n");
    out.push_str(&format!(
        "  inner initial claim: {}\n",
        data.joint_trace.claim_initial.0
    ));
    out.push_str("  inner rounds: [(h0, h1, h2)]\n");
    out.push_str(&format!(
        "  final opening values: final_f={}, final_g={}, final_claim={}\n",
        data.joint_trace.final_f.0, data.joint_trace.final_g.0, data.joint_trace.final_claim.0
    ));
    out.push_str("--------------------------------------------------\n");

    out.push_str("\n[Verify]\n");
    out.push_str("outer verify checks:\n");
    for r in &data.outer_verify.rounds {
        out.push_str(&format!(
            "  round {}: claim_in={} | derived g(1)={} | claim_ok={}\n",
            r.round, r.claim_in.0, r.g1_derived.0, r.claim_consistent
        ));
        out.push_str(&format!(
            "           r={} -> g(r)={} | folded_claim={} | transition_ok={}\n",
            r.challenge_r.0,
            r.gr_from_interpolation.0,
            r.folded_claim_from_vectors.0,
            r.transition_consistent
        ));
    }
    out.push_str(&format!(
        "  outer final: verifier_claim={} | trace_final_claim={} | ok={}\n",
        data.outer_verify.final_claim_from_verifier.0,
        data.outer_trace.final_claim.0,
        data.outer_verify.final_consistent
    ));

    out.push_str("inner verify checks:\n");
    for vr in &data.joint_verify.rounds {
        out.push_str(&format!(
            "  round {}: claim_in={} | h0+h1={} | claim_ok={}\n",
            vr.round, vr.claim_in.0, vr.expected_claim_from_h01.0, vr.claim_consistent
        ));
        out.push_str(&format!(
            "           r={} -> h(r)={} | folded_claim={} | transition_ok={}\n",
            vr.challenge_r.0,
            vr.hr_from_interpolation.0,
            vr.folded_claim_from_vectors.0,
            vr.transition_consistent
        ));
    }
    out.push_str(&format!(
        "  final check: final_f*final_g={}*{}={} | trace_final_claim={}\n",
        data.joint_trace.final_f.0,
        data.joint_trace.final_g.0,
        data.joint_trace.final_f.mul(data.joint_trace.final_g).0,
        data.joint_trace.final_claim.0
    ));
    out.push_str(&format!(
        "  verifier final claim={} | trace final claim={} | ok={}\n",
        data.joint_verify.final_claim_from_verifier.0,
        data.joint_trace.final_claim.0,
        data.joint_verify.final_consistent
    ));
    out.push_str("--------------------------------------------------\n");

    out.push_str("\n[Compare: Separate A/B/C Inner Paths]\n");
    out.push_str(&format!(
        "A path initial/final: {}/{}\n",
        data.a_trace.claim_initial.0, data.a_trace.final_claim.0
    ));
    out.push_str(&format!(
        "B path initial/final: {}/{}\n",
        data.b_trace.claim_initial.0, data.b_trace.final_claim.0
    ));
    out.push_str(&format!(
        "C path initial/final: {}/{}\n",
        data.c_trace.claim_initial.0, data.c_trace.final_claim.0
    ));
    out.push_str(
        "Note: Spartan proof path uses the JOINT inner sumcheck, not three separate proofs.\n",
    );

    out
}

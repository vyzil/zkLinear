use crate::{
    core::field::{MODULUS, Fp},
    sumcheck::inner::{verify_inner_sumcheck_trace, CHALLENGE_HASH_NAME, CHALLENGE_LABEL},
};

use super::{data::MatrixVectorInnerSumcheckReport, prove_matrix_vector_inner_sumcheck};

pub fn format_matrix_vector_inner_sumcheck_report(report: &MatrixVectorInnerSumcheckReport) -> String {
    fn format_dot_expansion(row: &[Fp], y: &[Fp]) -> String {
        let terms: Vec<String> = row
            .iter()
            .zip(y.iter())
            .map(|(a, b)| format!("{}*{}={}", a.0, b.0, a.0 * b.0))
            .collect();
        let sum_u64: u64 = row.iter().zip(y.iter()).map(|(a, b)| a.0 * b.0).sum();
        let reduced = sum_u64 % MODULUS;
        format!(
            "{} ; integer_sum={} ; mod {} => {}",
            terms.join(" + "),
            sum_u64,
            MODULUS,
            reduced
        )
    }

    let mut out = String::new();

    out.push_str("=== Spartan Matrix-Vector Inner Sumcheck Report ===\n");
    out.push_str("\n[Info]\n");
    out.push_str(&format!(
        "Field: F_{} (all arithmetic reduced mod {})\n",
        MODULUS, MODULUS
    ));
    out.push_str(&format!(
        "Transcript challenge: hash={}, label={:?}, input=(round, h0, h1, h2), encoding=u64 big-endian\n",
        CHALLENGE_HASH_NAME,
        std::str::from_utf8(CHALLENGE_LABEL).unwrap_or("binary")
    ));
    out.push_str("Fiat-Shamir scope: per-row independent in this demo (row 0 and row 1 can run in parallel)\n");
    out.push_str(&format!(
        "A size: {}x{}\n",
        report.a.len(),
        report.a.first().map_or(0, |r| r.len())
    ));
    out.push_str(&format!(
        "y size: {}\ny values: {:?}\n",
        report.y.len(),
        report.y.iter().map(|x| x.0).collect::<Vec<_>>()
    ));
    out.push_str("\n[Claim]\n");
    out.push_str(&format!(
        "Expected A*y (direct): {:?}\n",
        report.direct_ay.iter().map(|x| x.0).collect::<Vec<_>>()
    ));
    out.push_str("A values:\n");
    for (i, row) in report.a.iter().enumerate() {
        out.push_str(&format!(
            "  A[{}] = {:?}\n",
            i,
            row.iter().map(|x| x.0).collect::<Vec<_>>()
        ));
        out.push_str(&format!(
            "    dot detail: {}\n",
            format_dot_expansion(row, &report.y)
        ));
    }
    out.push_str("Now proving each row inner-product via sumcheck trace.\n");
    out.push_str(
        "Note: final claim is the claim after Fiat-Shamir folds, so it is not expected to equal direct A[row]*y.\n",
    );

    for (row_idx, trace) in report.traces.iter().enumerate() {
        out.push_str("\n[Sumcheck]\n");
        out.push_str(&format!("\n[row {}]\n", row_idx));
        out.push_str(&format!(
            "  direct A[row]*y = {}\n",
            report.direct_ay[row_idx].0
        ));
        out.push_str(&format!("  initial claim C0 = {}\n", trace.claim_initial.0));

        for r in &trace.rounds {
            out.push_str(&format!(
                "  round {} -> h(0)={}, h(1)={}, h(2)={}, challenge r={} = hash({}, {}, {}, {}) mod {}\n",
                r.round,
                r.h_at_0.0,
                r.h_at_1.0,
                r.h_at_2.0,
                r.challenge_r.0,
                r.round + 1,
                r.h_at_0.0,
                r.h_at_1.0,
                r.h_at_2.0,
                MODULUS
            ));
            out.push_str(&format!(
                "    folded f={:?}\n",
                r.folded_f.iter().map(|x| x.0).collect::<Vec<_>>()
            ));
            out.push_str(&format!(
                "    folded g={:?}\n",
                r.folded_g.iter().map(|x| x.0).collect::<Vec<_>>()
            ));
        }

        out.push_str(&format!(
            "  final check: f={} g={} claim={}\n",
            trace.final_f.0, trace.final_g.0, trace.final_claim.0
        ));

        let v = verify_inner_sumcheck_trace(trace);
        out.push_str("\n[Verify]\n");
        for vr in &v.rounds {
            out.push_str(&format!(
                "  round {}: claim_in={} | h0+h1={} | claim_ok={}\n",
                vr.round, vr.claim_in.0, vr.expected_claim_from_h01.0, vr.claim_consistent
            ));
            out.push_str(&format!(
                "           r={} = hash({}, {}, {}, {}) mod {} -> h(r)={} | folded_claim={} | transition_ok={}\n",
                vr.challenge_r.0,
                vr.round + 1,
                vr.h0.0,
                vr.h1.0,
                vr.h2.0,
                MODULUS,
                vr.hr_from_interpolation.0,
                vr.folded_claim_from_vectors.0,
                vr.transition_consistent
            ));
        }
        out.push_str(&format!(
            "  verifier final claim={} | trace final claim={} | final_ok={}\n",
            v.final_claim_from_verifier.0, v.final_claim_from_trace.0, v.final_consistent
        ));
    }

    out
}

pub fn demo_matrix_vector_trace() {
    let a: Vec<Vec<Fp>> = vec![
        [3, 1, 4, 1, 5, 9, 2, 6].map(Fp::new).to_vec(),
        [5, 8, 9, 7, 9, 3, 2, 3].map(Fp::new).to_vec(),
    ];
    let y: Vec<Fp> = [2, 7, 1, 8, 2, 8, 1, 8].map(Fp::new).to_vec();

    let report = prove_matrix_vector_inner_sumcheck(&a, &y);
    println!("{}", format_matrix_vector_inner_sumcheck_report(&report));
}

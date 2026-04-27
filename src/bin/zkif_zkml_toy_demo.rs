use std::{fs, path::PathBuf};

use anyhow::{anyhow, Result};
use zk_linear::{
    io::r1cs_zkif::import_spartan_like_instance_from_zkif_workspace, nizk::spartan_brakedown::prove,
};
use zkinterface::{
    producers::{builder::Sink, workspace::WorkspaceSink},
    structs::{
        constraints::{BilinearConstraint, ConstraintSystem},
        header::CircuitHeader,
        variables::Variables,
        witness::Witness,
    },
};

fn encode_u64_le(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 8);
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

fn make_lc(terms: &[(u64, u64)]) -> Variables {
    let ids = terms.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let vals = terms.iter().map(|(_, c)| *c).collect::<Vec<_>>();
    Variables {
        variable_ids: ids,
        values: Some(encode_u64_le(&vals)),
    }
}

fn build_toy_zkml_workspace(ws_dir: &PathBuf) -> Result<()> {
    // toy MLP:
    // x(4) -> hidden(4) -> y(2)
    // h_i = <W1_i, x> + b1_i
    // y_j = <W2_j, h> + b2_j
    //
    // variable ids
    // 0: constant one
    // 1..4: x (public)
    // 5..8: h (witness)
    // 9..10: y (public)
    let x = [2u64, 3, 5, 7];
    let w1 = [[1u64, 0, 2, 1], [0, 1, 1, 1], [1, 1, 0, 2], [2, 1, 1, 0]];
    let b1 = [1u64, 2, 3, 1];
    let w2 = [[1u64, 2, 1, 0], [0, 1, 2, 1]];
    let b2 = [1u64, 2];

    let mut h = [0u64; 4];
    for i in 0..4 {
        h[i] = b1[i] + w1[i].iter().zip(x.iter()).map(|(a, b)| a * b).sum::<u64>();
    }
    let mut y = [0u64; 2];
    for j in 0..2 {
        y[j] = b2[j] + w2[j].iter().zip(h.iter()).map(|(a, b)| a * b).sum::<u64>();
    }

    let header = CircuitHeader {
        instance_variables: Variables {
            variable_ids: vec![1, 2, 3, 4, 9, 10],
            values: Some(encode_u64_le(&[x[0], x[1], x[2], x[3], y[0], y[1]])),
        },
        free_variable_id: 11,
        field_maximum: None,
        configuration: None,
    };

    let witness = Witness {
        assigned_variables: Variables {
            variable_ids: vec![5, 6, 7, 8],
            values: Some(encode_u64_le(&h)),
        },
    };

    let mut constraints = Vec::<BilinearConstraint>::new();

    // hidden constraints: 1 * (b1_i + sum w1_i_k * x_k) = h_i
    for i in 0..4 {
        let mut terms_b = vec![(0u64, b1[i])];
        for (k, &coeff) in w1[i].iter().enumerate() {
            if coeff != 0 {
                terms_b.push(((k as u64) + 1, coeff));
            }
        }
        constraints.push(BilinearConstraint {
            linear_combination_a: make_lc(&[(0, 1)]),
            linear_combination_b: make_lc(&terms_b),
            linear_combination_c: make_lc(&[((i as u64) + 5, 1)]),
        });
    }

    // output constraints: 1 * (b2_j + sum w2_j_i * h_i) = y_j
    for j in 0..2 {
        let mut terms_b = vec![(0u64, b2[j])];
        for (i, &coeff) in w2[j].iter().enumerate() {
            if coeff != 0 {
                terms_b.push(((i as u64) + 5, coeff));
            }
        }
        constraints.push(BilinearConstraint {
            linear_combination_a: make_lc(&[(0, 1)]),
            linear_combination_b: make_lc(&terms_b),
            linear_combination_c: make_lc(&[((j as u64) + 9, 1)]),
        });
    }

    let cs = ConstraintSystem { constraints };

    let mut sink = WorkspaceSink::new(ws_dir).map_err(|e| anyhow!(e.to_string()))?;
    sink.push_header(header)
        .map_err(|e| anyhow!(e.to_string()))?;
    sink.push_witness(witness)
        .map_err(|e| anyhow!(e.to_string()))?;
    sink.push_constraints(cs)
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}

fn main() -> Result<()> {
    let base = PathBuf::from("tests/generated_cases/zkif_zkml_toy");
    let src_ws = base.join("workspace");
    let dst_instance = base.join("instance");
    fs::create_dir_all(&src_ws)?;
    fs::create_dir_all(&dst_instance)?;

    build_toy_zkml_workspace(&src_ws)?;
    import_spartan_like_instance_from_zkif_workspace(&src_ws, &dst_instance)?;
    let res = prove(&dst_instance)?;

    println!("generated zkif workspace: {}", src_ws.display());
    println!("generated zklinear instance: {}", dst_instance.display());
    println!("model: toy MLP (4 -> 4 -> 2), affine-only");
    let t = &res.timings;
    println!("timing(ms):");
    println!(
        "  input_parse: {:.3} ({:.1}%)",
        t.k0_input_parse_ms,
        t.pct(t.k0_input_parse_ms)
    );
    println!(
        "  spartan_prove_core: {:.3} ({:.1}%)",
        t.k1_spartan_prove_ms,
        t.pct(t.k1_spartan_prove_ms)
    );
    println!(
        "  pcs_commit_open_prove: {:.3} ({:.1}%)",
        t.k2_pcs_prove_ms,
        t.pct(t.k2_pcs_prove_ms)
    );
    println!(
        "  verify: {:.3} ({:.1}%)",
        t.k3_verify_ms,
        t.pct(t.k3_verify_ms)
    );
    println!("  total: {:.3}", t.total_ms());
    println!(
        "proof payload: joint_eval_at_r_openings={}",
        res.proof.pcs_proof_joint_eval_at_r.columns.len()
    );
    Ok(())
}

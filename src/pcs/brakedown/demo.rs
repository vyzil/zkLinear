use anyhow::Result;
use merlin::Transcript;

use crate::{
    core::field::{Fp, MODULUS},
    pcs::traits::PolynomialCommitmentScheme,
    protocol::spec_v1::{
        append_spec_domain, append_u64_le, LCPC_DEG_TEST_LABEL, PCS_DEMO_TRANSCRIPT_LABEL,
    },
};

use super::{
    challenges::{sample_field_vec, sample_unique_cols},
    merkle::{merkle_root, verify_column_path},
    types::{BrakedownEncoderKind, BrakedownParams},
    BrakedownPcs,
};

pub fn build_brakedown_demo_report() -> Result<String> {
    let params = BrakedownParams::new(8);
    let pcs = BrakedownPcs::new(params.clone());

    let n_rows = 4;
    let coeffs: Vec<Fp> = (0..(n_rows * params.n_per_row))
        .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
        .collect();

    let prover_commitment = pcs.commit(&coeffs)?;
    let verifier_commitment = pcs.verifier_commitment(&prover_commitment);
    let root = merkle_root(&prover_commitment.merkle_nodes);

    let x = Fp::new(7);
    let mut inner = Vec::with_capacity(params.n_per_row);
    let mut p = Fp::new(1);
    for _ in 0..params.n_per_row {
        inner.push(p);
        p = p.mul(x);
    }

    let xr = x.mul(*inner.last().unwrap());
    let mut outer = Vec::with_capacity(n_rows);
    let mut q = Fp::new(1);
    for _ in 0..n_rows {
        outer.push(q);
        q = q.mul(xr);
    }

    let mut tr_p = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    tr_p.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let proof = pcs.open(&prover_commitment, &outer, &mut tr_p)?;

    let mut tr_v = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    tr_v.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_v, b"ncols", pcs.encoding.n_cols as u64);
    let claimed_eval = inner
        .iter()
        .zip(proof.p_eval.iter())
        .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    let mut tr_v_detail = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v_detail);
    tr_v_detail.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_v_detail, b"ncols", pcs.encoding.n_cols as u64);
    let mut rand_tensors = Vec::new();
    for p_rand in &proof.p_random_vec {
        let t = sample_field_vec(&mut tr_v_detail, LCPC_DEG_TEST_LABEL, prover_commitment.n_rows);
        rand_tensors.push(t);
        for v in p_rand {
            tr_v_detail.append_message(b"p_random", &v.0.to_le_bytes());
        }
    }
    for v in &proof.p_eval {
        tr_v_detail.append_message(b"p_eval", &v.0.to_le_bytes());
    }
    let expected_cols =
        sample_unique_cols(&mut tr_v_detail, pcs.encoding.n_cols, params.n_col_opens)?;
    let p_eval_enc = pcs.encoding.encode_row(&proof.p_eval);
    let p_rand_enc: Vec<Vec<Fp>> = proof
        .p_random_vec
        .iter()
        .map(|v| pcs.encoding.encode_row(v))
        .collect();
    let recomputed_eval = inner
        .iter()
        .zip(proof.p_eval.iter())
        .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    pcs.verify(
        &verifier_commitment,
        &proof,
        &outer,
        &inner,
        claimed_eval,
        &mut tr_v,
    )?;

    let mut out = String::new();
    out.push_str("=== Independent Mini Brakedown-style Trace ===\n");
    out.push_str("\n[Demo Scope]\n");
    out.push_str("this is a research/demo PCS trace, not a production Brakedown parameter set\n");
    let enc_desc = match pcs.encoding.kind {
        BrakedownEncoderKind::ToyHybrid => {
            "toy-hybrid encoder (systematic + RS-like parity + sparse parity)"
        }
        BrakedownEncoderKind::SpielmanLike => {
            "spielman-like SDIG-inspired encoder (sparse precode/postcode + base RS-like layer)"
        }
    };
    out.push_str(&format!("encoder: {}\n", enc_desc));
    out.push_str("purpose: inspect commit/open/verify boundaries and transcript flow\n");
    out.push_str("\n[Input]\n");
    out.push_str(&format!("field: F_{}\n", MODULUS));
    out.push_str(&format!(
        "coeffs len={} (rows={} x per_row={})\n",
        coeffs.len(),
        n_rows,
        params.n_per_row
    ));
    out.push_str(&format!(
        "coeffs (first 16): {:?}\n",
        coeffs.iter().take(16).map(|x| x.0).collect::<Vec<_>>()
    ));
    out.push_str(&format!(
        "inner tensor (len={}): {:?}\n",
        inner.len(),
        inner.iter().map(|x| x.0).collect::<Vec<_>>()
    ));
    out.push_str(&format!(
        "outer tensor (len={}): {:?}\n",
        outer.len(),
        outer.iter().map(|x| x.0).collect::<Vec<_>>()
    ));

    out.push_str("\n[Commit]\n");
    out.push_str(&format!(
        "dims: n_rows={}, n_per_row={}, n_cols={}\n",
        prover_commitment.n_rows, prover_commitment.n_per_row, prover_commitment.n_cols
    ));
    out.push_str(&format!(
        "security params (demo): n_col_opens={}, n_degree_tests={}\n",
        params.n_col_opens, params.n_degree_tests
    ));
    out.push_str("\n[Commit: Encode]\n");
    for r in 0..prover_commitment.n_rows {
        let coeff_row = &prover_commitment.coeffs
            [r * prover_commitment.n_per_row..(r + 1) * prover_commitment.n_per_row];
        let enc_row = &prover_commitment.encoded
            [r * prover_commitment.n_cols..(r + 1) * prover_commitment.n_cols];
        out.push_str(&format!(
            "  row {} coeffs: {:?}\n",
            r,
            coeff_row.iter().map(|x| x.0).collect::<Vec<_>>()
        ));
        out.push_str(&format!(
            "  row {} encoded: {:?}\n",
            r,
            enc_row.iter().map(|x| x.0).collect::<Vec<_>>()
        ));
    }

    out.push_str("\n[Commit: Hash/Merkle]\n");
    out.push_str("  leaf input is each encoded column vector\n");
    for c in 0..prover_commitment.n_cols {
        let mut col = Vec::with_capacity(prover_commitment.n_rows);
        for r in 0..prover_commitment.n_rows {
            col.push(prover_commitment.encoded[r * prover_commitment.n_cols + c].0);
        }
        out.push_str(&format!("  col {} values: {:?}\n", c, col));
        out.push_str(&format!(
            "    leaf_hash[{}]: {}\n",
            c,
            hex::encode(prover_commitment.leaf_hashes[c])
        ));
    }
    out.push_str(&format!(
        "  leaf count: {}\n",
        prover_commitment.leaf_hashes.len()
    ));
    out.push_str(&format!("  Merkle root(hex): {}\n", hex::encode(root)));

    out.push_str("\n[Prove]\n");
    out.push_str(&format!(
        "proof payload: p_eval_len={}, p_random_count={}, opened_cols={}\n",
        proof.p_eval.len(),
        proof.p_random_vec.len(),
        proof.columns.len()
    ));
    out.push_str(&format!(
        "p_eval: {:?}\n",
        proof.p_eval.iter().map(|x| x.0).collect::<Vec<_>>()
    ));
    out.push_str(&format!(
        "opened col indices: {:?}\n",
        proof.columns.iter().map(|c| c.col_idx).collect::<Vec<_>>()
    ));
    for (i, col) in proof.columns.iter().enumerate() {
        out.push_str(&format!(
            "  opening[{}]: col={}, values(first 4)={:?}, path_len={}\n",
            i,
            col.col_idx,
            col.values.iter().take(4).map(|x| x.0).collect::<Vec<_>>(),
            col.merkle_path.len()
        ));
    }

    out.push_str("\n[Payload: Prover -> Verifier]\n");
    out.push_str(&format!(
        "commitment root: {}\n",
        hex::encode(verifier_commitment.root)
    ));
    out.push_str(&format!(
        "p_random vectors ({}):\n",
        proof.p_random_vec.len()
    ));
    for (i, p_rand) in proof.p_random_vec.iter().enumerate() {
        out.push_str(&format!(
            "  p_random[{}]: {:?}\n",
            i,
            p_rand.iter().map(|x| x.0).collect::<Vec<_>>()
        ));
    }
    out.push_str(&format!(
        "p_eval: {:?}\n",
        proof.p_eval.iter().map(|x| x.0).collect::<Vec<_>>()
    ));
    out.push_str("openings:\n");
    for (i, col) in proof.columns.iter().enumerate() {
        out.push_str(&format!(
            "  opening[{}]: col_idx={}, values={:?}\n",
            i,
            col.col_idx,
            col.values.iter().map(|x| x.0).collect::<Vec<_>>()
        ));
        for (d, sib) in col.merkle_path.iter().enumerate() {
            out.push_str(&format!("    path[{}]: {}\n", d, hex::encode(sib)));
        }
    }

    out.push_str("\n[Verify Details]\n");
    out.push_str(&format!(
        "expected opened cols from transcript: {:?}\n",
        expected_cols
    ));
    for (i, col) in proof.columns.iter().enumerate() {
        out.push_str(&format!(
            "  opening[{}] col={} | expected={} | idx_ok={}\n",
            i,
            col.col_idx,
            expected_cols[i],
            col.col_idx == expected_cols[i]
        ));
        for j in 0..proof.p_random_vec.len() {
            let dot = rand_tensors[j]
                .iter()
                .zip(col.values.iter())
                .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
            out.push_str(&format!(
                "    degree-test {}: <rand_t, opened_col>={} | encoded[p_random][col]={} | ok={}\n",
                j,
                dot.0,
                p_rand_enc[j][col.col_idx].0,
                dot == p_rand_enc[j][col.col_idx]
            ));
        }
        let dot_eval = outer
            .iter()
            .zip(col.values.iter())
            .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
        out.push_str(&format!(
            "    eval-check: <outer_t, opened_col>={} | encoded[p_eval][col]={} | ok={}\n",
            dot_eval.0,
            p_eval_enc[col.col_idx].0,
            dot_eval == p_eval_enc[col.col_idx]
        ));
        let merkle_ok = verify_column_path(verifier_commitment.root, col);
        out.push_str(&format!("    merkle path check: ok={}\n", merkle_ok));
    }

    out.push_str("\n[Verify]\n");
    out.push_str(&format!("claimed eval: {}\n", claimed_eval.0));
    out.push_str(&format!(
        "recomputed eval from (inner tensor · p_eval): {}\n",
        recomputed_eval.0
    ));
    out.push_str(&format!(
        "claimed==recomputed: {}\n",
        claimed_eval == recomputed_eval
    ));
    out.push_str("verify: success (claimed evaluation accepted)\n");
    out.push_str(
        "meaning: opened columns are Merkle-authenticated and consistent with collapsed checks\n",
    );
    out.push_str("\n[format]\n");
    out.push_str("- leaf hash input: H(zero_digest || column values serialized as LE u64)\n");
    out.push_str("- internal hash input: H(left_hash || right_hash)\n");
    out.push_str("- opening payload: (column index, column values, merkle sibling path)\n");

    Ok(out)
}

pub fn run_brakedown_trace() -> Result<()> {
    let report = build_brakedown_demo_report()?;
    println!("\n{}", report);
    Ok(())
}

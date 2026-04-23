use merlin::Transcript;
use zk_linear::{
    core::field::{Fp, MODULUS},
    pcs::{
        brakedown::{
            merkle::merkle_root,
            types::BrakedownParams,
            wire::{
                deserialize_eval_proof, deserialize_verifier_commitment, serialize_eval_proof,
                serialize_verifier_commitment,
            },
            BrakedownPcs,
        },
        traits::PolynomialCommitmentScheme,
    },
    protocol::spec_v1::{append_spec_domain, append_u64_le, PCS_DEMO_TRANSCRIPT_LABEL},
};

fn build_tensors(n_rows: usize, n_per_row: usize) -> (Vec<Fp>, Vec<Fp>) {
    let x = Fp::new(7);

    let mut inner = Vec::with_capacity(n_per_row);
    let mut p = Fp::new(1);
    for _ in 0..n_per_row {
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

    (outer, inner)
}

fn fixture() -> (BrakedownPcs, Vec<Fp>) {
    let params = BrakedownParams::new(8);
    let pcs = BrakedownPcs::new(params.clone());
    let n_rows = 4;
    let coeffs: Vec<Fp> = (0..(n_rows * params.n_per_row))
        .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
        .collect();
    (pcs, coeffs)
}

#[test]
fn brakedown_wire_roundtrip_verify_succeeds() {
    let (pcs, coeffs) = fixture();
    let prover_commitment = pcs.commit(&coeffs).expect("commit should succeed");
    let verifier_commitment = pcs.verifier_commitment(&prover_commitment);
    let (outer, inner) = build_tensors(prover_commitment.n_rows, prover_commitment.n_per_row);

    let root = merkle_root(&prover_commitment.merkle_nodes);
    let mut tr_p = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    tr_p.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let proof = pcs
        .open(&prover_commitment, &outer, &mut tr_p)
        .expect("open should succeed");

    let vc_bytes = serialize_verifier_commitment(&verifier_commitment);
    let pf_bytes = serialize_eval_proof(&proof);
    let vc2 = deserialize_verifier_commitment(&vc_bytes).expect("vc decode should succeed");
    let pf2 = deserialize_eval_proof(&pf_bytes).expect("proof decode should succeed");

    let claimed_eval = inner
        .iter()
        .zip(pf2.p_eval.iter())
        .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    let mut tr_v = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    tr_v.append_message(b"polycommit", &vc2.root);
    append_u64_le(&mut tr_v, b"ncols", pcs.encoding.n_cols as u64);

    pcs.verify(&vc2, &pf2, &outer, &inner, claimed_eval, &mut tr_v)
        .expect("verify should succeed after wire roundtrip");
}

#[test]
fn brakedown_wire_detects_tampered_payload() {
    let (pcs, coeffs) = fixture();
    let prover_commitment = pcs.commit(&coeffs).expect("commit should succeed");
    let verifier_commitment = pcs.verifier_commitment(&prover_commitment);
    let (outer, inner) = build_tensors(prover_commitment.n_rows, prover_commitment.n_per_row);

    let root = merkle_root(&prover_commitment.merkle_nodes);
    let mut tr_p = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    tr_p.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let proof = pcs
        .open(&prover_commitment, &outer, &mut tr_p)
        .expect("open should succeed");

    let vc_bytes = serialize_verifier_commitment(&verifier_commitment);
    let mut pf_bytes = serialize_eval_proof(&proof);
    let last = pf_bytes.len() - 1;
    pf_bytes[last] ^= 1;

    let vc2 = deserialize_verifier_commitment(&vc_bytes).expect("vc decode should succeed");
    let pf2 = deserialize_eval_proof(&pf_bytes).expect("proof decode should still parse");
    let claimed_eval = inner
        .iter()
        .zip(pf2.p_eval.iter())
        .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    let mut tr_v = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    tr_v.append_message(b"polycommit", &vc2.root);
    append_u64_le(&mut tr_v, b"ncols", pcs.encoding.n_cols as u64);

    let err = pcs
        .verify(&vc2, &pf2, &outer, &inner, claimed_eval, &mut tr_v)
        .expect_err("verify should fail for tampered wire payload");
    assert!(
        err.to_string().contains("merkle path")
            || err.to_string().contains("column")
            || err.to_string().contains("claimed evaluation mismatch")
    );
}

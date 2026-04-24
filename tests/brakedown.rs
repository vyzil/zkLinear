use merlin::Transcript;
use zk_linear::{
    core::field::{Fp, MODULUS},
    field_profiles::Mersenne61,
    pcs::{
        brakedown::{
            challenges::{sample_field_vec_t, sample_unique_cols, sample_unique_cols_from_start},
            merkle::merkle_root,
            types::{BrakedownEncoderKind, BrakedownParams},
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

fn fixture_coeffs(n_rows: usize, n_per_row: usize) -> Vec<Fp> {
    (0..(n_rows * n_per_row))
        .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
        .collect()
}

fn build_tensors(n_rows: usize, n_per_row: usize) -> (Vec<Fp>, Vec<Fp>) {
    let x = Fp::new(7);

    let mut inner = Vec::with_capacity(n_per_row);
    let mut p = Fp::new(1);
    for _ in 0..n_per_row {
        inner.push(p);
        p = p.mul(x);
    }

    let xr = x.mul(*inner.last().expect("inner tensor should not be empty"));
    let mut outer = Vec::with_capacity(n_rows);
    let mut q = Fp::new(1);
    for _ in 0..n_rows {
        outer.push(q);
        q = q.mul(xr);
    }

    (outer, inner)
}

#[test]
fn brakedown_001_spielman_encoding_is_deterministic_for_same_seed() {
    let mut params = BrakedownParams::new_toy(8);
    params.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    params.encoder_seed = 42;

    let pcs_a = BrakedownPcs::new(params.clone());
    let pcs_b = BrakedownPcs::new(params);
    let coeffs = fixture_coeffs(4, 8);

    let comm_a = pcs_a.commit(&coeffs).expect("commit A should succeed");
    let comm_b = pcs_b.commit(&coeffs).expect("commit B should succeed");

    assert_eq!(comm_a.encoded, comm_b.encoded);
    assert_eq!(comm_a.merkle_nodes, comm_b.merkle_nodes);
}

#[test]
fn brakedown_002_spielman_encoding_changes_with_seed() {
    let mut p0 = BrakedownParams::new_toy(8);
    p0.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    p0.encoder_seed = 1;

    let mut p1 = BrakedownParams::new_toy(8);
    p1.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    p1.encoder_seed = 2;

    let pcs_0 = BrakedownPcs::new(p0);
    let pcs_1 = BrakedownPcs::new(p1);
    let coeffs = fixture_coeffs(4, 8);

    let comm_0 = pcs_0.commit(&coeffs).expect("commit 0 should succeed");
    let comm_1 = pcs_1.commit(&coeffs).expect("commit 1 should succeed");

    assert_ne!(comm_0.encoded, comm_1.encoded);
}

#[test]
fn brakedown_003_pcs_open_verify_succeeds_and_wrong_claim_fails() {
    let mut params = BrakedownParams::new_toy(8);
    params.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    let pcs = BrakedownPcs::new(params);

    let coeffs = fixture_coeffs(4, 8);
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

    let claimed_eval = inner
        .iter()
        .zip(proof.p_eval.iter())
        .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    let mut tr_ok = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_ok);
    tr_ok.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_ok, b"ncols", pcs.encoding.n_cols as u64);
    pcs.verify(
        &verifier_commitment,
        &proof,
        &outer,
        &inner,
        claimed_eval,
        &mut tr_ok,
    )
    .expect("verify should succeed");

    let mut tr_bad = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_bad);
    tr_bad.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_bad, b"ncols", pcs.encoding.n_cols as u64);
    let err = pcs
        .verify(
            &verifier_commitment,
            &proof,
            &outer,
            &inner,
            claimed_eval.add(Fp::new(1)),
            &mut tr_bad,
        )
        .expect_err("verify should fail for wrong claimed value");
    assert!(err.to_string().contains("claimed evaluation mismatch"));
}

#[test]
fn brakedown_004_col_open_start_avoids_systematic_region() {
    let mut params = BrakedownParams::new_toy(8);
    params.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    params.col_open_start = 8;
    params.n_col_opens = 3;

    let pcs = BrakedownPcs::new(params);
    let coeffs = fixture_coeffs(4, 8);
    let prover_commitment = pcs.commit(&coeffs).expect("commit should succeed");
    let (outer, _) = build_tensors(prover_commitment.n_rows, prover_commitment.n_per_row);

    let root = merkle_root(&prover_commitment.merkle_nodes);
    let mut tr_p = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    tr_p.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let proof = pcs
        .open(&prover_commitment, &outer, &mut tr_p)
        .expect("open should succeed");

    assert!(
        proof.columns.iter().all(|c| c.col_idx >= 8),
        "opened columns should avoid systematic region when col_open_start is set"
    );
}

#[test]
fn brakedown_005_challenge_sampling_contract_for_col_start() {
    let mut t = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t);

    let err = sample_unique_cols_from_start(&mut t, 10, 1, 11)
        .expect_err("start beyond n_cols should fail");
    assert!(err.to_string().contains("must be <= n_cols"));

    let mut t2 = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t2);
    let empty = sample_unique_cols_from_start(&mut t2, 10, 0, 10)
        .expect("empty range with zero openings should succeed");
    assert!(empty.is_empty());

    let mut t3 = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t3);
    let err = sample_unique_cols_from_start(&mut t3, 10, 1, 10)
        .expect_err("empty range with openings should fail");
    assert!(err.to_string().contains("range is empty"));

    let mut t4 = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    let mut t5 = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t4);
    append_spec_domain(&mut t5);
    t4.append_message(b"ctx", b"same");
    t5.append_message(b"ctx", b"same");

    let c1 = sample_unique_cols(&mut t4, 64, 12).expect("sampling should succeed");
    let c2 = sample_unique_cols(&mut t5, 64, 12).expect("sampling should succeed");
    assert_eq!(c1, c2);

    let v_m61 = sample_field_vec_t::<Mersenne61>(&mut t5, b"deg-test", 32);
    for x in v_m61 {
        assert!(x.0 < Mersenne61::P);
    }
}

#[test]
fn brakedown_006_wire_roundtrip_succeeds_and_rejects_trailing_bytes() {
    let mut params = BrakedownParams::new_toy(8);
    params.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    let pcs = BrakedownPcs::new(params);

    let coeffs = fixture_coeffs(4, 8);
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
        .expect("verify after wire roundtrip should succeed");

    let mut bad_vc = vc_bytes.clone();
    bad_vc.push(0);
    let err = deserialize_verifier_commitment(&bad_vc)
        .expect_err("trailing bytes must be rejected for verifier commitment");
    assert!(err.to_string().contains("trailing bytes"));

    let mut bad_pf = pf_bytes.clone();
    bad_pf.push(0);
    let err = deserialize_eval_proof(&bad_pf)
        .expect_err("trailing bytes must be rejected for eval proof");
    assert!(err.to_string().contains("trailing bytes"));
}

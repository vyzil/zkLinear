use merlin::Transcript;
use sha2::{Digest, Sha256};
use zk_linear::{
    core::field::{Fp, MODULUS},
    field_profiles::{Goldilocks64, Mersenne61},
    pcs::{
        brakedown::{
            merkle::merkle_root,
            scalar::BrakedownField,
            types::BrakedownParams,
            wire::{serialize_eval_proof, serialize_eval_proof_t, serialize_verifier_commitment},
            BrakedownPcs, BrakedownPcsT,
        },
        BrakedownSecurityPreset,
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

fn build_tensors_t<F: BrakedownField>(n_rows: usize, n_per_row: usize) -> (Vec<F>, Vec<F>) {
    let x = F::new(7);
    let mut inner = Vec::with_capacity(n_per_row);
    let mut p = F::new(1);
    for _ in 0..n_per_row {
        inner.push(p);
        p = p.mul(x);
    }
    let xr = x.mul(*inner.last().unwrap());
    let mut outer = Vec::with_capacity(n_rows);
    let mut q = F::new(1);
    for _ in 0..n_rows {
        outer.push(q);
        q = q.mul(xr);
    }
    (outer, inner)
}

#[test]
fn brakedown_golden_consistency_toy_path() {
    let params = BrakedownParams::new_toy(8);
    let pcs = BrakedownPcs::new(params.clone());
    let n_rows = 4;
    let coeffs: Vec<Fp> = (0..(n_rows * params.n_per_row))
        .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
        .collect();

    let prover_commitment = pcs.commit(&coeffs).expect("commit should succeed");
    let verifier_commitment = pcs.verifier_commitment(&prover_commitment);
    let root = merkle_root(&prover_commitment.merkle_nodes);
    let (outer, inner) = build_tensors(prover_commitment.n_rows, prover_commitment.n_per_row);

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

    let opened_cols = proof.columns.iter().map(|c| c.col_idx).collect::<Vec<_>>();

    let vc_bytes = serialize_verifier_commitment(&verifier_commitment);
    let pf_bytes = serialize_eval_proof(&proof);
    let vc_hash = hex::encode(Sha256::digest(&vc_bytes));
    let pf_hash = hex::encode(Sha256::digest(&pf_bytes));
    let root_hex = hex::encode(root);

    assert_eq!(
        root_hex,
        "210504e5dda88a3dc54da773f8f1ea15b79a384c2659b075842aea249295dc75"
    );
    assert_eq!(opened_cols, vec![9, 6, 8]);
    assert_eq!(claimed_eval.0, 68);
    assert_eq!(
        vc_hash,
        "33fde17de1650e01793b225fda55f6ee17d5ffaf7331f1ecb1fb0e9205a621e9"
    );
    assert_eq!(
        pf_hash,
        "702bd31fff3367fe57ea14255fa83a01cffd64ce63d5f86f2192926297fce959"
    );
}

fn run_generic_golden<F: BrakedownField>(pcs: &BrakedownPcsT<F>) -> (String, Vec<usize>, u64, String, String) {
    let n_rows = 4usize;
    let coeffs: Vec<F> = (0..(n_rows * pcs.params.n_per_row))
        .map(|i| F::new((i as u64) * 13 + 5))
        .collect();

    let prover_commitment = pcs.commit_generic(&coeffs).expect("commit should succeed");
    let verifier_commitment = pcs.verifier_commitment_generic(&prover_commitment);
    let root = merkle_root(&prover_commitment.merkle_nodes);
    let (outer, inner) = build_tensors_t::<F>(prover_commitment.n_rows, prover_commitment.n_per_row);

    let mut tr_p = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    tr_p.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let proof = pcs
        .open_generic(&prover_commitment, &outer, &mut tr_p)
        .expect("open should succeed");

    let claimed_eval = inner
        .iter()
        .zip(proof.p_eval.iter())
        .fold(F::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    let mut tr_v = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    tr_v.append_message(b"polycommit", &root);
    append_u64_le(&mut tr_v, b"ncols", pcs.encoding.n_cols as u64);
    pcs.verify_generic(
        &verifier_commitment,
        &proof,
        &outer,
        &inner,
        claimed_eval,
        &mut tr_v,
    )
    .expect("verify should succeed");

    let opened_cols = proof.columns.iter().map(|c| c.col_idx).collect::<Vec<_>>();
    let vc_bytes = serialize_verifier_commitment(&verifier_commitment);
    let pf_bytes = serialize_eval_proof_t(&proof);
    let vc_hash = hex::encode(Sha256::digest(&vc_bytes));
    let pf_hash = hex::encode(Sha256::digest(&pf_bytes));
    let root_hex = hex::encode(root);

    (root_hex, opened_cols, claimed_eval.to_u64(), vc_hash, pf_hash)
}

#[test]
fn brakedown_golden_consistency_mersenne61_path() {
    let pcs: BrakedownPcsT<Mersenne61> =
        BrakedownPcsT::new(BrakedownSecurityPreset::LcpcLikeMersenne61Ext2.params(8));
    let (root_hex, opened_cols, claimed_eval, vc_hash, pf_hash) = run_generic_golden(&pcs);
    assert_eq!(
        root_hex,
        "02d601459138ca631e2912d2aa4c86ebf5226fed9b9d5a7d12b426e310438ffd"
    );
    assert_eq!(
        opened_cols,
        vec![6, 17, 3, 9, 12, 0, 2, 1, 5, 14, 10, 7, 19, 18, 8, 16, 20, 4, 11, 13, 15]
    );
    assert_eq!(claimed_eval, 665753899684855131);
    assert_eq!(
        vc_hash,
        "f789eda631a8db786b140639c275272319ed1aeb11b6d20141f4e8105e3fc77d"
    );
    assert_eq!(
        pf_hash,
        "b2c7b0756fd2e7a5cac93be0eff7c64e6c810f7c0f94c66e524d784f3325dd73"
    );
}

#[test]
fn brakedown_golden_consistency_goldilocks64_path() {
    let pcs: BrakedownPcsT<Goldilocks64> =
        BrakedownPcsT::new(BrakedownSecurityPreset::LcpcLikeGoldilocks64Ext2.params(8));
    let (root_hex, opened_cols, claimed_eval, vc_hash, pf_hash) = run_generic_golden(&pcs);
    assert_eq!(
        root_hex,
        "48979736e21d301ef069fc49003ab914193162b2e1ed02dbbf6045956c1d5da3"
    );
    assert_eq!(
        opened_cols,
        vec![17, 18, 1, 8, 3, 4, 15, 0, 11, 16, 9, 7, 12, 20, 19, 2, 14, 13, 5, 10, 6]
    );
    assert_eq!(claimed_eval, 6529514271123546666);
    assert_eq!(
        vc_hash,
        "a2c88a251fa69389a4be55ada5657abc79537a2804a23746a635f40837810afb"
    );
    assert_eq!(
        pf_hash,
        "718d6e08a2484ec4d8f84c923e27ca5fb8bf96f8a3a690908a3b2556909ac51d"
    );
}

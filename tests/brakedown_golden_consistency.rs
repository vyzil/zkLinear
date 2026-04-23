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
    let params = BrakedownParams::new(8);
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
        "aa51e3d1f8d81542390af1bddb9d7a1efcdefdca38e5c7991f3e4544ec6813f2"
    );
    assert_eq!(opened_cols, vec![12, 18, 4]);
    assert_eq!(claimed_eval.0, 68);
    assert_eq!(
        vc_hash,
        "996140733dea6bb4dfb7d3aea06067b36e9dd575d15f0cec40d6c4de195bbce2"
    );
    assert_eq!(
        pf_hash,
        "aaa2d22c5aa0ebc50fe6c58f66c888e12e8c8b1a54b5d43804f6cc7b3293ce2b"
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
        "01ea861c00b23e0d5814748612356ac0dd0414a913929f0179153e42ed712e89"
    );
    assert_eq!(
        opened_cols,
        vec![7, 3, 8, 13, 10, 14, 11, 9, 15, 18, 2, 19, 6, 5, 0, 12, 1, 4, 20, 16, 17]
    );
    assert_eq!(claimed_eval, 665753899684855131);
    assert_eq!(
        vc_hash,
        "44971d5d1fd55d74fde4d339327790fe482abe364b47643c871ad65f7c1778dc"
    );
    assert_eq!(
        pf_hash,
        "e372e425fdd3119f83e9743a3c240a20e5d41099b5d769f026059f563ac3b0c3"
    );
}

#[test]
fn brakedown_golden_consistency_goldilocks64_path() {
    let pcs: BrakedownPcsT<Goldilocks64> =
        BrakedownPcsT::new(BrakedownSecurityPreset::LcpcLikeGoldilocks64Ext2.params(8));
    let (root_hex, opened_cols, claimed_eval, vc_hash, pf_hash) = run_generic_golden(&pcs);
    assert_eq!(
        root_hex,
        "01ea861c00b23e0d5814748612356ac0dd0414a913929f0179153e42ed712e89"
    );
    assert_eq!(
        opened_cols,
        vec![14, 4, 1, 11, 7, 18, 8, 15, 9, 17, 20, 10, 5, 16, 3, 13, 12, 2, 0, 19, 6]
    );
    assert_eq!(claimed_eval, 6529514271123546666);
    assert_eq!(
        vc_hash,
        "e4b8905a6246f33fa2ef4598cfb168853f0c77370c6db0c4d41907a72b984673"
    );
    assert_eq!(
        pf_hash,
        "c691481ad5ece71037e6254d0e9607c1fa603d11ab60afee5a3bf6f73e7609bb"
    );
}

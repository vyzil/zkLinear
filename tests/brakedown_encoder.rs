use zk_linear::{
    core::field::{Fp, MODULUS},
    pcs::{
        brakedown::types::{BrakedownEncoderKind, BrakedownParams},
        traits::PolynomialCommitmentScheme,
        BrakedownPcs,
    },
};

fn fixture_coeffs(n_rows: usize, n_per_row: usize) -> Vec<Fp> {
    (0..(n_rows * n_per_row))
        .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
        .collect()
}

#[test]
fn spielman_like_encoding_is_deterministic_for_same_seed() {
    let mut params = BrakedownParams::new(8);
    params.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    params.encoder_seed = 42;

    let pcs_a = BrakedownPcs::new(params.clone());
    let pcs_b = BrakedownPcs::new(params);
    let coeffs = fixture_coeffs(4, 8);

    let comm_a = pcs_a.commit(&coeffs).expect("commit A should succeed");
    let comm_b = pcs_b.commit(&coeffs).expect("commit B should succeed");

    assert_eq!(comm_a.encoded, comm_b.encoded);
    assert_eq!(comm_a.leaf_hashes, comm_b.leaf_hashes);
    assert_eq!(comm_a.merkle_nodes, comm_b.merkle_nodes);
}

#[test]
fn spielman_like_encoding_changes_with_seed() {
    let mut p0 = BrakedownParams::new(8);
    p0.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    p0.encoder_seed = 1;

    let mut p1 = BrakedownParams::new(8);
    p1.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    p1.encoder_seed = 2;

    let pcs_0 = BrakedownPcs::new(p0);
    let pcs_1 = BrakedownPcs::new(p1);
    let coeffs = fixture_coeffs(4, 8);

    let comm_0 = pcs_0.commit(&coeffs).expect("commit seed1 should succeed");
    let comm_1 = pcs_1.commit(&coeffs).expect("commit seed2 should succeed");

    assert_ne!(comm_0.encoded, comm_1.encoded);
    assert_ne!(comm_0.merkle_nodes.last(), comm_1.merkle_nodes.last());
}


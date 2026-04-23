use merlin::Transcript;
use zk_linear::{
    core::transcript::{derive_round_challenge_merlin_t, derive_round_challenge_t},
    field_profiles::{BaseField64, Mersenne61, Mersenne61Ext2},
    sumcheck::{
        inner::{
            inner_product_t, prove_inner_sumcheck_with_label_and_transcript_t,
            verify_inner_sumcheck_trace_t,
        },
        outer::{prove_outer_sumcheck_with_transcript_t, verify_outer_sumcheck_trace_t},
    },
};

#[test]
fn generic_transcript_challenge_works_for_ext2() {
    let h0 = Mersenne61Ext2::new(Mersenne61::new(3), Mersenne61::new(5));
    let h1 = Mersenne61Ext2::new(Mersenne61::new(7), Mersenne61::new(11));
    let h2 = Mersenne61Ext2::new(Mersenne61::new(13), Mersenne61::new(17));

    let c_sha = derive_round_challenge_t::<Mersenne61Ext2>(b"label", 0, h0, h1, h2);

    let mut tr = Transcript::new(b"zklinear/test/generic");
    let c_merlin = derive_round_challenge_merlin_t::<Mersenne61Ext2>(&mut tr, b"label", 0, h0, h1, h2);

    assert_ne!(c_sha, Mersenne61Ext2::zero());
    assert_ne!(c_merlin, Mersenne61Ext2::zero());
}

#[test]
fn generic_inner_outer_sumcheck_verify_for_ext2() {
    let row: Vec<Mersenne61Ext2> = (0..8)
        .map(|i| Mersenne61Ext2::new(Mersenne61::new((i as u64) + 1), Mersenne61::new((i as u64) * 2 + 3)))
        .collect();
    let y: Vec<Mersenne61Ext2> = (0..8)
        .map(|i| Mersenne61Ext2::new(Mersenne61::new((i as u64) * 3 + 2), Mersenne61::new((i as u64) + 9)))
        .collect();

    let mut tr_in = Transcript::new(b"zklinear/test/inner-ext2");
    let inner = prove_inner_sumcheck_with_label_and_transcript_t(
        &row,
        &y,
        b"inner-ext2",
        &mut tr_in,
    );
    let iv = verify_inner_sumcheck_trace_t(&inner);
    assert!(iv.final_consistent);

    let values: Vec<Mersenne61Ext2> = vec![
        Mersenne61Ext2::new(Mersenne61::new(5), Mersenne61::new(1)),
        Mersenne61Ext2::new(Mersenne61::new(9), Mersenne61::new(2)),
        Mersenne61Ext2::new(Mersenne61::new(4), Mersenne61::new(7)),
        Mersenne61Ext2::new(Mersenne61::new(8), Mersenne61::new(6)),
    ];
    let mut tr_out = Transcript::new(b"zklinear/test/outer-ext2");
    let outer = prove_outer_sumcheck_with_transcript_t(&values, &mut tr_out);
    let ov = verify_outer_sumcheck_trace_t(&outer);
    assert!(ov.final_consistent);

    let direct = inner_product_t(&row, &y);
    assert_eq!(direct, inner.claim_initial);
}

use merlin::Transcript;
use zk_linear::{
    field_profiles::Mersenne61,
    pcs::brakedown::challenges::{sample_field_vec, sample_field_vec_t, sample_unique_cols},
    protocol::spec_v1::{append_spec_domain, PCS_DEMO_TRANSCRIPT_LABEL},
};

#[test]
fn challenge_sampling_is_deterministic_for_same_transcript() {
    let mut t1 = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    let mut t2 = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t1);
    append_spec_domain(&mut t2);
    t1.append_message(b"ctx", b"same");
    t2.append_message(b"ctx", b"same");

    let v1 = sample_field_vec(&mut t1, b"deg-test", 16);
    let v2 = sample_field_vec(&mut t2, b"deg-test", 16);
    assert_eq!(v1, v2);

    let c1 = sample_unique_cols(&mut t1, 64, 12).expect("cols sample should work");
    let c2 = sample_unique_cols(&mut t2, 64, 12).expect("cols sample should work");
    assert_eq!(c1, c2);
}

#[test]
fn unique_col_sampling_is_in_range_and_unique() {
    let mut t = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t);
    t.append_message(b"ctx", b"range-unique");

    let cols = sample_unique_cols(&mut t, 128, 32).expect("cols sample should work");
    assert_eq!(cols.len(), 32);
    for c in &cols {
        assert!(*c < 128);
    }
    let mut sorted = cols.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 32);
}

#[test]
fn generic_field_sampling_stays_within_modulus() {
    let mut t = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t);
    t.append_message(b"ctx", b"m61");

    let v_m61 = sample_field_vec_t::<Mersenne61>(&mut t, b"deg-test", 64);
    for x in v_m61 {
        assert!(x.0 < Mersenne61::P);
    }

    let mut t_fp = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut t_fp);
    t_fp.append_message(b"ctx", b"fp");
    let v_fp = sample_field_vec(&mut t_fp, b"deg-test", 64);
    for x in v_fp {
        assert!(x.0 < 97);
    }
}

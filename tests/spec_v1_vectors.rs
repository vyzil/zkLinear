use merlin::Transcript;
use zk_linear::{
    core::{
        field::{Fp, MODULUS},
        transcript::{derive_round_challenge, derive_round_challenge_merlin},
    },
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
        spec_v1::{append_spec_domain, BRIDGE_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL},
    },
};

#[test]
fn spec_v1_round_challenge_vectors_are_stable() {
    let g0 = Fp::new(25);
    let g2 = Fp::new(61);
    let g3 = Fp::new(72);

    let sha_chal = derive_round_challenge(OUTER_SUMCHECK_LABEL, 0, g0, g2, g3);

    let mut tr = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr);
    append_reference_profile_to_transcript(&mut tr, &DUAL_REFERENCE_PROFILE);
    let merlin_chal = derive_round_challenge_merlin(&mut tr, OUTER_SUMCHECK_LABEL, 0, g0, g2, g3);

    assert_eq!(sha_chal.0, 76);
    assert_eq!(merlin_chal.0, 31);
    assert!(sha_chal.0 < MODULUS);
    assert!(merlin_chal.0 < MODULUS);
}

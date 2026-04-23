use std::{path::Path, time::Instant};

use anyhow::{anyhow, Result};
use merlin::Transcript;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{
    core::{
        field::{Fp, ModulusScope},
        transcript::derive_round_challenge_merlin,
    },
    io::case_format::{load_spartan_like_case_from_dir, SpartanLikeCase},
    pcs::{
        brakedown::{
            profiles::params_for_field_profile,
            types::BrakedownFieldProfile,
            BrakedownPcs,
        },
        traits::PolynomialCommitmentScheme,
    },
    protocol::reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
    protocol::spec_v1::{
        append_fp_le, append_spec_domain, append_u64_le, INNER_SUMCHECK_JOINT_LABEL,
        NIZK_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL,
    },
    protocol::shared::{
        append_case_digest_to_transcript, bind_rows, build_eq_weights_from_challenges,
        compute_case_digest, derive_outer_tau_sha, flatten_rows, matrix_vec_mul,
        sample_blind_mix_alpha_from_transcript, sample_gamma_from_transcript_light,
    },
    sumcheck::{
        inner::{
            inner_product, prove_inner_sumcheck_with_label_and_transcript,
            verify_inner_sumcheck_trace,
        },
        outer::{
            prove_outer_sumcheck_with_transcript, verify_outer_sumcheck_trace,
        },
    },
};
use super::report::format_pipeline_report;
use super::types::{
    KernelTimingMs, SpartanBrakedownPipelineResult, SpartanBrakedownProof, SpartanBrakedownPublic,
    SpartanBrakedownCompiledCircuit, SpartanBrakedownProver, SpartanBrakedownVerifier, VerifyMode,
};

fn default_profile() -> BrakedownFieldProfile {
    BrakedownFieldProfile::default_nizk_profile()
}

fn sample_blind_vec_from_rng(rng: &mut ChaCha20Rng, n: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Fp::new(rng.next_u64()));
    }
    out
}

pub fn parse_field_profile(s: &str) -> Option<BrakedownFieldProfile> {
    BrakedownFieldProfile::parse(s)
}

pub fn compile_from_dir(case_dir: &Path) -> Result<SpartanBrakedownCompiledCircuit> {
    compile_from_dir_with_profile(case_dir, default_profile())
}

pub fn compile_from_dir_with_profile(
    case_dir: &Path,
    profile: BrakedownFieldProfile,
) -> Result<SpartanBrakedownCompiledCircuit> {
    let _mod_scope = ModulusScope::enter(profile.base_modulus());
    let case = load_spartan_like_case_from_dir(case_dir)?;
    Ok(SpartanBrakedownCompiledCircuit {
        rows: case.a.len(),
        cols: case.a[0].len(),
        case_digest: compute_case_digest(&case),
        field_profile: profile,
        reference_profile: DUAL_REFERENCE_PROFILE,
    })
}

pub fn prove_with_compiled_from_dir(
    compiled: &SpartanBrakedownCompiledCircuit,
    case_dir: &Path,
) -> Result<SpartanBrakedownPipelineResult> {
    let _mod_scope = ModulusScope::enter(compiled.field_profile.base_modulus());
    let case = load_spartan_like_case_from_dir(case_dir)?;
    validate_compiled_case(compiled, &case)?;
    prove_from_dir_impl(case_dir, compiled.field_profile)
}

pub fn prove_from_dir(case_dir: &Path) -> Result<SpartanBrakedownPipelineResult> {
    SpartanBrakedownProver::new(default_profile()).prove_from_dir(case_dir)
}

pub fn prove_from_dir_with_profile(
    case_dir: &Path,
    profile: BrakedownFieldProfile,
) -> Result<SpartanBrakedownPipelineResult> {
    SpartanBrakedownProver::new(profile).prove_from_dir(case_dir)
}

impl SpartanBrakedownProver {
    pub fn prove_from_dir(self, case_dir: &Path) -> Result<SpartanBrakedownPipelineResult> {
        prove_from_dir_impl(case_dir, self.profile)
    }
}

fn prove_from_dir_impl(
    case_dir: &Path,
    profile: BrakedownFieldProfile,
) -> Result<SpartanBrakedownPipelineResult> {
    let _mod_scope = ModulusScope::enter(profile.base_modulus());
    let t0 = Instant::now();
    let case = load_spartan_like_case_from_dir(case_dir)?;
    let k0_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = Instant::now();
    let az = matrix_vec_mul(&case.a, &case.z);
    let bz = matrix_vec_mul(&case.b, &case.z);
    let cz = matrix_vec_mul(&case.c, &case.z);

    let residual: Vec<Fp> = az
        .iter()
        .zip(bz.iter())
        .zip(cz.iter())
        .map(|((a, b), c)| a.mul(*b).sub(*c))
        .collect();

    let row_vars = case.a.len().trailing_zeros() as usize;
    let tau = derive_outer_tau_sha(row_vars, &az, &bz, &cz, &case.z);
    let eq_tau = build_eq_weights_from_challenges(&tau);
    let weighted_residual: Vec<Fp> = residual
        .iter()
        .zip(eq_tau.iter())
        .map(|(r, w)| r.mul(*w))
        .collect();
    let case_digest = compute_case_digest(&case);

    let mut tr_p = Transcript::new(NIZK_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    append_reference_profile_to_transcript(&mut tr_p, &DUAL_REFERENCE_PROFILE);
    append_case_digest_to_transcript(&mut tr_p, case.a.len(), case.a[0].len(), case_digest);

    let outer_trace = prove_outer_sumcheck_with_transcript(&weighted_residual, &mut tr_p);
    let r_x = outer_trace
        .rounds
        .iter()
        .map(|rr| rr.challenge_r)
        .collect::<Vec<_>>();
    let row_weights = build_eq_weights_from_challenges(&r_x);

    let gamma = sample_gamma_from_transcript_light(&mut tr_p);
    let gamma_sq = gamma.mul(gamma);

    let a_bound = bind_rows(&case.a, &row_weights);
    let b_bound = bind_rows(&case.b, &row_weights);
    let c_bound = bind_rows(&case.c, &row_weights);

    let joint_bound: Vec<Fp> = a_bound
        .iter()
        .zip(b_bound.iter())
        .zip(c_bound.iter())
        .map(|((a, b), c)| a.add(gamma.mul(*b)).add(gamma_sq.mul(*c)))
        .collect();

    let inner_trace = prove_inner_sumcheck_with_label_and_transcript(
        &joint_bound,
        &case.z,
        INNER_SUMCHECK_JOINT_LABEL,
        &mut tr_p,
    );

    let claimed_value_unblinded = inner_product(&joint_bound, &case.z);
    let mut blind_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut blind_seed);
    let mut blind_rng = ChaCha20Rng::from_seed(blind_seed);
    let blind_vec_1 = sample_blind_vec_from_rng(&mut blind_rng, case.z.len());
    let blind_eval_1 = inner_product(&blind_vec_1, &case.z);
    let blind_vec_2 = sample_blind_vec_from_rng(&mut blind_rng, case.z.len());
    let blind_eval_2 = inner_product(&blind_vec_2, &case.z);

    let k1_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let coeff_rows = vec![
        a_bound,
        b_bound,
        c_bound,
        blind_vec_1,
        blind_vec_2,
        case.z.clone(),
    ];
    let coeffs = flatten_rows(&coeff_rows);

    let params = params_for_field_profile(case.a[0].len(), profile);
    let pcs = BrakedownPcs::new(params);
    let prover_commitment = pcs.commit(&coeffs)?;
    let verifier_commitment = pcs.verifier_commitment(&prover_commitment);

    tr_p.append_message(b"nizk_opening_label", b"masked_main_opening");
    tr_p.append_message(b"polycommit", &verifier_commitment.root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let blind_mix_alpha = sample_blind_mix_alpha_from_transcript(&mut tr_p);
    let claimed_value_masked = claimed_value_unblinded
        .add(blind_eval_1)
        .add(blind_mix_alpha.mul(blind_eval_2));
    append_fp_le(&mut tr_p, b"claimed_value_unblinded", claimed_value_unblinded);
    append_fp_le(&mut tr_p, b"blind_eval_1", blind_eval_1);
    append_fp_le(&mut tr_p, b"blind_eval_2", blind_eval_2);
    append_fp_le(&mut tr_p, b"blind_mix_alpha", blind_mix_alpha);
    append_fp_le(&mut tr_p, b"claimed_value_masked", claimed_value_masked);

    let outer_tensor_main = vec![
        Fp::new(1),
        gamma,
        gamma_sq,
        Fp::new(1),
        blind_mix_alpha,
        Fp::zero(),
    ];
    let outer_tensor_blind_1 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
        Fp::zero(),
    ];
    let outer_tensor_blind_2 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
    ];
    let outer_tensor_joint_eval_at_r = vec![
        Fp::new(1),
        gamma,
        gamma_sq,
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
    ];
    let outer_tensor_z_eval_at_r = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
    ];

    let pcs_proof_main = pcs.open(&prover_commitment, &outer_tensor_main, &mut tr_p)?;
    tr_p.append_message(b"nizk_opening_label", b"blind_component_opening_1");
    let pcs_proof_blind_1 = pcs.open(&prover_commitment, &outer_tensor_blind_1, &mut tr_p)?;
    tr_p.append_message(b"nizk_opening_label", b"blind_component_opening_2");
    let pcs_proof_blind_2 = pcs.open(&prover_commitment, &outer_tensor_blind_2, &mut tr_p)?;
    tr_p.append_message(b"nizk_opening_label", b"joint_eval_at_r");
    let pcs_proof_joint_eval_at_r =
        pcs.open(&prover_commitment, &outer_tensor_joint_eval_at_r, &mut tr_p)?;
    tr_p.append_message(b"nizk_opening_label", b"z_eval_at_r");
    let pcs_proof_z_eval_at_r =
        pcs.open(&prover_commitment, &outer_tensor_z_eval_at_r, &mut tr_p)?;
    let k2_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let proof = SpartanBrakedownProof {
        outer_trace,
        inner_trace,
        gamma,
        claimed_value_unblinded,
        claimed_value: claimed_value_masked,
        blind_eval_1,
        blind_eval_2,
        blind_mix_alpha,
        reference_profile: DUAL_REFERENCE_PROFILE,
        verifier_commitment,
        pcs_proof_main,
        pcs_proof_blind_1,
        pcs_proof_blind_2,
        pcs_proof_joint_eval_at_r,
        pcs_proof_z_eval_at_r,
    };

    let public = SpartanBrakedownPublic {
        rows: case.a.len(),
        cols: case.a[0].len(),
        case_digest,
        claimed_value_masked,
        reference_profile: DUAL_REFERENCE_PROFILE,
    };

    let t3 = Instant::now();
    verify_public(&proof, &public)?;
    let k3_ms = t3.elapsed().as_secs_f64() * 1000.0;

    Ok(SpartanBrakedownPipelineResult {
        proof,
        public,
        timings: KernelTimingMs {
            k0_input_parse_ms: k0_ms,
            k1_spartan_prove_ms: k1_ms,
            k2_pcs_prove_ms: k2_ms,
            k3_verify_ms: k3_ms,
        },
    })
}

pub fn verify_from_dir(case_dir: &Path, proof: &SpartanBrakedownProof) -> Result<()> {
    // Backward-compatible wrapper: strict replay is debug-only.
    // Default verifier path for deployment-facing call-sites is `verify_public`.
    verify_from_dir_strict(case_dir, proof)
}

pub fn verify_from_dir_strict(case_dir: &Path, proof: &SpartanBrakedownProof) -> Result<()> {
    verify_from_dir_strict_impl(case_dir, proof)
}

pub fn verify_public(proof: &SpartanBrakedownProof, public: &SpartanBrakedownPublic) -> Result<()> {
    SpartanBrakedownVerifier::new(VerifyMode::Succinct).verify_public(proof, public)
}

pub fn verify_with_compiled(
    compiled: &SpartanBrakedownCompiledCircuit,
    proof: &SpartanBrakedownProof,
    public: &SpartanBrakedownPublic,
) -> Result<()> {
    validate_compiled_public(compiled, proof, public)?;
    verify_public(proof, public)
}

impl SpartanBrakedownVerifier {
    pub fn verify_from_dir(self, case_dir: &Path, proof: &SpartanBrakedownProof) -> Result<()> {
        match self.mode {
            VerifyMode::StrictReplay => verify_from_dir_strict_impl(case_dir, proof),
            VerifyMode::Succinct => Err(anyhow!(
                "succinct verifier requires explicit public input; use verify_public(proof, public)"
            )),
        }
    }

    pub fn verify_public(
        self,
        proof: &SpartanBrakedownProof,
        public: &SpartanBrakedownPublic,
    ) -> Result<()> {
        let _ = self;
        verify_public_succinct(proof, public)
    }
}

fn verify_from_dir_strict_impl(case_dir: &Path, proof: &SpartanBrakedownProof) -> Result<()> {
    let _mod_scope = ModulusScope::enter(proof.verifier_commitment.field_profile.base_modulus());
    let case = load_spartan_like_case_from_dir(case_dir)?;
    let rows = case.a.len();
    let cols = case.a[0].len();
    if rows == 0 || cols == 0 || !rows.is_power_of_two() || !cols.is_power_of_two() {
        return Err(anyhow!("case shape must be non-zero powers of two"));
    }

    if proof.outer_trace.rounds.len() != rows.trailing_zeros() as usize {
        return Err(anyhow!("outer rounds do not match row count"));
    }
    if proof.inner_trace.rounds.len() != cols.trailing_zeros() as usize {
        return Err(anyhow!("inner rounds do not match column count"));
    }

    if proof.verifier_commitment.n_rows != 6 || proof.verifier_commitment.n_per_row != cols {
        return Err(anyhow!(
            "verifier commitment dimensions mismatch for blinded layout"
        ));
    }
    if proof.reference_profile != DUAL_REFERENCE_PROFILE {
        return Err(anyhow!("unsupported reference profile for this NIZK flow"));
    }
    let az = matrix_vec_mul(&case.a, &case.z);
    let bz = matrix_vec_mul(&case.b, &case.z);
    let cz = matrix_vec_mul(&case.c, &case.z);
    let residual = az
        .iter()
        .zip(bz.iter())
        .zip(cz.iter())
        .map(|((a, b), c)| a.mul(*b).sub(*c))
        .collect::<Vec<_>>();

    let tau = derive_outer_tau_sha(rows.trailing_zeros() as usize, &az, &bz, &cz, &case.z);
    let eq_tau = build_eq_weights_from_challenges(&tau);
    let weighted_residual = residual
        .iter()
        .zip(eq_tau.iter())
        .map(|(r, w)| r.mul(*w))
        .collect::<Vec<_>>();
    let expected_outer_claim = weighted_residual
        .iter()
        .fold(Fp::zero(), |acc, v| acc.add(*v));
    if expected_outer_claim != proof.outer_trace.claim_initial {
        return Err(anyhow!("outer claim does not match A/B/C/z-derived claim"));
    }

    let mut tr_v = Transcript::new(NIZK_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    append_reference_profile_to_transcript(&mut tr_v, &proof.reference_profile);
    let case_digest = compute_case_digest(&case);
    append_case_digest_to_transcript(&mut tr_v, rows, cols, case_digest);

    for r in &proof.outer_trace.rounds {
        let expected_r = derive_round_challenge_merlin(
            &mut tr_v,
            OUTER_SUMCHECK_LABEL,
            r.round,
            r.g_at_0,
            r.g_at_2,
            r.g_at_3,
        );
        if expected_r != r.challenge_r {
            return Err(anyhow!("outer challenge mismatch at round {}", r.round));
        }
    }

    let outer_v = verify_outer_sumcheck_trace(&proof.outer_trace);
    if !outer_v.final_consistent {
        return Err(anyhow!("outer sumcheck verification failed"));
    }

    let expected_gamma = sample_gamma_from_transcript_light(&mut tr_v);
    if expected_gamma != proof.gamma {
        return Err(anyhow!("gamma mismatch vs transcript-derived challenge"));
    }

    for r in &proof.inner_trace.rounds {
        let expected_r = derive_round_challenge_merlin(
            &mut tr_v,
            INNER_SUMCHECK_JOINT_LABEL,
            r.round,
            r.h_at_0,
            r.h_at_1,
            r.h_at_2,
        );
        if expected_r != r.challenge_r {
            return Err(anyhow!("inner challenge mismatch at round {}", r.round));
        }
    }

    let inner_v = verify_inner_sumcheck_trace(&proof.inner_trace);
    if !inner_v.final_consistent {
        return Err(anyhow!("inner sumcheck verification failed"));
    }

    let r_x = proof
        .outer_trace
        .rounds
        .iter()
        .map(|r| r.challenge_r)
        .collect::<Vec<_>>();
    let row_weights = build_eq_weights_from_challenges(&r_x);
    let a_bound = bind_rows(&case.a, &row_weights);
    let b_bound = bind_rows(&case.b, &row_weights);
    let c_bound = bind_rows(&case.c, &row_weights);

    let gamma_sq = proof.gamma.mul(proof.gamma);
    let joint_bound = a_bound
        .iter()
        .zip(b_bound.iter())
        .zip(c_bound.iter())
        .map(|((a, b), c)| a.add(proof.gamma.mul(*b)).add(gamma_sq.mul(*c)))
        .collect::<Vec<_>>();

    let expected_claimed_unblinded = inner_product(&joint_bound, &case.z);
    if proof.claimed_value_unblinded != expected_claimed_unblinded {
        return Err(anyhow!(
            "proof unblinded claim mismatch vs A/B/C/z-derived claim"
        ));
    }
    if proof.inner_trace.claim_initial != proof.claimed_value_unblinded {
        return Err(anyhow!("inner initial claim mismatch vs bound/input"));
    }

    tr_v.append_message(b"nizk_opening_label", b"masked_main_opening");
    tr_v.append_message(b"polycommit", &proof.verifier_commitment.root);
    append_u64_le(&mut tr_v, b"ncols", proof.verifier_commitment.n_cols as u64);
    let expected_blind_mix_alpha = sample_blind_mix_alpha_from_transcript(&mut tr_v);
    if expected_blind_mix_alpha != proof.blind_mix_alpha {
        return Err(anyhow!(
            "blind mix alpha mismatch vs transcript-derived challenge"
        ));
    }

    let expected_masked = proof
        .claimed_value_unblinded
        .add(proof.blind_eval_1)
        .add(expected_blind_mix_alpha.mul(proof.blind_eval_2));
    if proof.claimed_value != expected_masked {
        return Err(anyhow!("masked claimed value mismatch"));
    }

    append_fp_le(&mut tr_v, b"claimed_value_unblinded", proof.claimed_value_unblinded);
    append_fp_le(&mut tr_v, b"blind_eval_1", proof.blind_eval_1);
    append_fp_le(&mut tr_v, b"blind_eval_2", proof.blind_eval_2);
    append_fp_le(&mut tr_v, b"blind_mix_alpha", proof.blind_mix_alpha);
    append_fp_le(&mut tr_v, b"claimed_value_masked", proof.claimed_value);

    let params = params_for_field_profile(cols, proof.verifier_commitment.field_profile);
    if params.field_profile != proof.verifier_commitment.field_profile {
        return Err(anyhow!(
            "PCS parameter/commitment field profile mismatch in verify"
        ));
    }
    let pcs = BrakedownPcs::new(params);
    let inner_tensor = case.z;
    let outer_tensor_main = vec![
        Fp::new(1),
        proof.gamma,
        gamma_sq,
        Fp::new(1),
        proof.blind_mix_alpha,
        Fp::zero(),
    ];
    let outer_tensor_blind_1 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
        Fp::zero(),
    ];
    let outer_tensor_blind_2 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
    ];
    let outer_tensor_joint_eval_at_r = vec![
        Fp::new(1),
        proof.gamma,
        gamma_sq,
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
    ];
    let outer_tensor_z_eval_at_r = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
    ];

    pcs.verify(
        &proof.verifier_commitment,
        &proof.pcs_proof_main,
        &outer_tensor_main,
        &inner_tensor,
        proof.claimed_value,
        &mut tr_v,
    )?;

    tr_v.append_message(b"nizk_opening_label", b"blind_component_opening_1");
    pcs.verify(
        &proof.verifier_commitment,
        &proof.pcs_proof_blind_1,
        &outer_tensor_blind_1,
        &inner_tensor,
        proof.blind_eval_1,
        &mut tr_v,
    )?;
    tr_v.append_message(b"nizk_opening_label", b"blind_component_opening_2");
    pcs.verify(
        &proof.verifier_commitment,
        &proof.pcs_proof_blind_2,
        &outer_tensor_blind_2,
        &inner_tensor,
        proof.blind_eval_2,
        &mut tr_v,
    )?;
    tr_v.append_message(b"nizk_opening_label", b"joint_eval_at_r");
    let inner_chals = proof
        .inner_trace
        .rounds
        .iter()
        .map(|r| r.challenge_r)
        .collect::<Vec<_>>();
    let eq_r = build_eq_weights_from_challenges(&inner_chals);
    pcs.verify(
        &proof.verifier_commitment,
        &proof.pcs_proof_joint_eval_at_r,
        &outer_tensor_joint_eval_at_r,
        &eq_r,
        proof.inner_trace.final_f,
        &mut tr_v,
    )?;
    tr_v.append_message(b"nizk_opening_label", b"z_eval_at_r");
    pcs.verify(
        &proof.verifier_commitment,
        &proof.pcs_proof_z_eval_at_r,
        &outer_tensor_z_eval_at_r,
        &eq_r,
        proof.inner_trace.final_g,
        &mut tr_v,
    )?;
    let expected_final_claim = proof.inner_trace.final_f.mul(proof.inner_trace.final_g);
    if proof.inner_trace.final_claim != expected_final_claim {
        return Err(anyhow!("inner final claim mismatch vs final_f*final_g"));
    }

    Ok(())
}

fn validate_compiled_case(
    compiled: &SpartanBrakedownCompiledCircuit,
    case: &SpartanLikeCase,
) -> Result<()> {
    if compiled.reference_profile != DUAL_REFERENCE_PROFILE {
        return Err(anyhow!("unsupported reference profile in compiled circuit"));
    }
    if case.a.len() != compiled.rows || case.a[0].len() != compiled.cols {
        return Err(anyhow!("compiled circuit shape mismatch"));
    }
    if compute_case_digest(case) != compiled.case_digest {
        return Err(anyhow!("compiled circuit digest mismatch"));
    }
    Ok(())
}

fn validate_compiled_public(
    compiled: &SpartanBrakedownCompiledCircuit,
    proof: &SpartanBrakedownProof,
    public: &SpartanBrakedownPublic,
) -> Result<()> {
    if compiled.reference_profile != public.reference_profile
        || compiled.reference_profile != proof.reference_profile
    {
        return Err(anyhow!("compiled/reference profile mismatch"));
    }
    if public.rows != compiled.rows || public.cols != compiled.cols {
        return Err(anyhow!("compiled/public shape mismatch"));
    }
    if public.case_digest != compiled.case_digest {
        return Err(anyhow!("compiled/public case digest mismatch"));
    }
    if proof.verifier_commitment.field_profile != compiled.field_profile {
        return Err(anyhow!("compiled/proof field profile mismatch"));
    }
    Ok(())
}

fn verify_public_succinct(proof: &SpartanBrakedownProof, public: &SpartanBrakedownPublic) -> Result<()> {
    let _mod_scope = ModulusScope::enter(proof.verifier_commitment.field_profile.base_modulus());
    if public.rows == 0
        || public.cols == 0
        || !public.rows.is_power_of_two()
        || !public.cols.is_power_of_two()
    {
        return Err(anyhow!("public shape must be non-zero powers of two"));
    }

    if public.reference_profile != proof.reference_profile {
        return Err(anyhow!("reference profile mismatch"));
    }
    if proof.verifier_commitment.n_rows != 6 || proof.verifier_commitment.n_per_row != public.cols {
        return Err(anyhow!(
            "verifier commitment dimensions mismatch for blinded layout"
        ));
    }
    if proof.outer_trace.rounds.len() != public.rows.trailing_zeros() as usize {
        return Err(anyhow!("outer rounds do not match row count"));
    }
    if proof.inner_trace.rounds.len() != public.cols.trailing_zeros() as usize {
        return Err(anyhow!("inner rounds do not match column count"));
    }

    let mut tr_v = Transcript::new(NIZK_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    append_reference_profile_to_transcript(&mut tr_v, &proof.reference_profile);
    append_case_digest_to_transcript(&mut tr_v, public.rows, public.cols, public.case_digest);

    for r in &proof.outer_trace.rounds {
        let expected_r = derive_round_challenge_merlin(
            &mut tr_v,
            OUTER_SUMCHECK_LABEL,
            r.round,
            r.g_at_0,
            r.g_at_2,
            r.g_at_3,
        );
        if expected_r != r.challenge_r {
            return Err(anyhow!("outer challenge mismatch at round {}", r.round));
        }
    }

    let outer_v = verify_outer_sumcheck_trace(&proof.outer_trace);
    if !outer_v.final_consistent {
        return Err(anyhow!("outer sumcheck verification failed"));
    }

    let expected_gamma = sample_gamma_from_transcript_light(&mut tr_v);
    if expected_gamma != proof.gamma {
        return Err(anyhow!("gamma mismatch vs transcript-derived challenge"));
    }

    for r in &proof.inner_trace.rounds {
        let expected_r = derive_round_challenge_merlin(
            &mut tr_v,
            INNER_SUMCHECK_JOINT_LABEL,
            r.round,
            r.h_at_0,
            r.h_at_1,
            r.h_at_2,
        );
        if expected_r != r.challenge_r {
            return Err(anyhow!("inner challenge mismatch at round {}", r.round));
        }
    }

    let inner_v = verify_inner_sumcheck_trace(&proof.inner_trace);
    if !inner_v.final_consistent {
        return Err(anyhow!("inner sumcheck verification failed"));
    }

    tr_v.append_message(b"nizk_opening_label", b"masked_main_opening");
    tr_v.append_message(b"polycommit", &proof.verifier_commitment.root);
    append_u64_le(&mut tr_v, b"ncols", proof.verifier_commitment.n_cols as u64);
    let expected_blind_mix_alpha = sample_blind_mix_alpha_from_transcript(&mut tr_v);
    if expected_blind_mix_alpha != proof.blind_mix_alpha {
        return Err(anyhow!(
            "blind mix alpha mismatch vs transcript-derived challenge"
        ));
    }
    if proof.claimed_value_unblinded != proof.inner_trace.claim_initial {
        return Err(anyhow!(
            "proof unblinded claim mismatch vs transcript-bound inner claim"
        ));
    }
    let expected_masked = proof
        .claimed_value_unblinded
        .add(proof.blind_eval_1)
        .add(proof.blind_mix_alpha.mul(proof.blind_eval_2));
    if expected_masked != public.claimed_value_masked || expected_masked != proof.claimed_value {
        return Err(anyhow!("masked claimed value mismatch"));
    }
    append_fp_le(
        &mut tr_v,
        b"claimed_value_unblinded",
        proof.claimed_value_unblinded,
    );
    append_fp_le(&mut tr_v, b"blind_eval_1", proof.blind_eval_1);
    append_fp_le(&mut tr_v, b"blind_eval_2", proof.blind_eval_2);
    append_fp_le(&mut tr_v, b"blind_mix_alpha", proof.blind_mix_alpha);
    append_fp_le(&mut tr_v, b"claimed_value_masked", proof.claimed_value);

    let params = params_for_field_profile(public.cols, proof.verifier_commitment.field_profile);
    let pcs = BrakedownPcs::new(params);
    let outer_tensor_main = vec![
        Fp::new(1),
        proof.gamma,
        proof.gamma.mul(proof.gamma),
        Fp::new(1),
        proof.blind_mix_alpha,
        Fp::zero(),
    ];
    let outer_tensor_blind_1 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
        Fp::zero(),
    ];
    let outer_tensor_blind_2 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
    ];
    let outer_tensor_joint_eval_at_r = vec![
        Fp::new(1),
        proof.gamma,
        proof.gamma.mul(proof.gamma),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
    ];
    let outer_tensor_z_eval_at_r = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
    ];

    // Default succinct path intentionally avoids witness-like inner tensor inputs.
    // It validates transcript/challenge flow and PCS opening structure only.
    pcs.verify_structure_generic(
        &proof.verifier_commitment,
        &proof.pcs_proof_main,
        &outer_tensor_main,
        &mut tr_v,
    )?;

    tr_v.append_message(b"nizk_opening_label", b"blind_component_opening_1");
    pcs.verify_structure_generic(
        &proof.verifier_commitment,
        &proof.pcs_proof_blind_1,
        &outer_tensor_blind_1,
        &mut tr_v,
    )?;

    tr_v.append_message(b"nizk_opening_label", b"blind_component_opening_2");
    pcs.verify_structure_generic(
        &proof.verifier_commitment,
        &proof.pcs_proof_blind_2,
        &outer_tensor_blind_2,
        &mut tr_v,
    )?;
    tr_v.append_message(b"nizk_opening_label", b"joint_eval_at_r");
    let inner_chals = proof
        .inner_trace
        .rounds
        .iter()
        .map(|r| r.challenge_r)
        .collect::<Vec<_>>();
    let eq_r = build_eq_weights_from_challenges(&inner_chals);
    pcs.verify(
        &proof.verifier_commitment,
        &proof.pcs_proof_joint_eval_at_r,
        &outer_tensor_joint_eval_at_r,
        &eq_r,
        proof.inner_trace.final_f,
        &mut tr_v,
    )?;
    tr_v.append_message(b"nizk_opening_label", b"z_eval_at_r");
    pcs.verify(
        &proof.verifier_commitment,
        &proof.pcs_proof_z_eval_at_r,
        &outer_tensor_z_eval_at_r,
        &eq_r,
        proof.inner_trace.final_g,
        &mut tr_v,
    )?;
    let expected_final_claim = proof.inner_trace.final_f.mul(proof.inner_trace.final_g);
    if proof.inner_trace.final_claim != expected_final_claim {
        return Err(anyhow!("inner final claim mismatch vs final_f*final_g"));
    }

    Ok(())
}

pub fn build_pipeline_report_from_dir(case_dir: &Path) -> Result<String> {
    build_pipeline_report_from_dir_with_profile(case_dir, default_profile())
}

pub fn build_pipeline_report_from_dir_with_profile(
    case_dir: &Path,
    profile: BrakedownFieldProfile,
) -> Result<String> {
    let result = prove_from_dir_with_profile(case_dir, profile)?;
    Ok(format_pipeline_report(case_dir, &result))
}

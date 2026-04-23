use std::{path::Path, time::Instant};

use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::{
    core::{
        field::{current_modulus, Fp, ModulusScope},
        transcript::derive_round_challenge_merlin,
    },
    io::case_format::load_spartan_like_case_from_dir,
    pcs::{
        brakedown::{
            profiles::BrakedownSecurityPreset,
            types::{
                BrakedownEvalProof, BrakedownFieldProfile, BrakedownParams,
                BrakedownVerifierCommitment,
            },
            BrakedownPcs,
        },
        traits::PolynomialCommitmentScheme,
    },
    protocol::reference::{
        append_reference_profile_to_transcript, ReferenceProfile, DUAL_REFERENCE_PROFILE,
    },
    protocol::spec_v1::{
        append_fp_le, append_spec_domain, append_u64_le, INNER_SUMCHECK_JOINT_LABEL,
        NIZK_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL,
    },
    protocol::shared::{
        append_case_to_transcript, bind_rows, build_eq_weights_from_challenges,
        derive_outer_tau_sha, flatten_rows, matrix_vec_mul, sample_blind_mix_alpha_from_transcript,
        sample_blind_vec_from_transcript, sample_gamma_from_transcript,
    },
    sumcheck::{
        inner::{
            inner_product, prove_inner_sumcheck_with_label_and_transcript,
            verify_inner_sumcheck_trace, SumcheckTrace,
        },
        outer::{
            prove_outer_sumcheck_with_transcript, verify_outer_sumcheck_trace, OuterSumcheckTrace,
        },
    },
};

fn params_for_profile(n_per_row: usize, profile: BrakedownFieldProfile) -> BrakedownParams {
    match profile {
        BrakedownFieldProfile::ToyF97 => BrakedownSecurityPreset::DemoToy.params(n_per_row),
        BrakedownFieldProfile::Mersenne61Ext2 => {
            BrakedownSecurityPreset::ProductionMersenne61Ext2.params(n_per_row)
        }
        BrakedownFieldProfile::Goldilocks64Ext2 => {
            BrakedownSecurityPreset::ProductionGoldilocks64Ext2.params(n_per_row)
        }
    }
}

fn field_modulus_for_profile(profile: BrakedownFieldProfile) -> u64 {
    match profile {
        BrakedownFieldProfile::ToyF97 => 97,
        BrakedownFieldProfile::Mersenne61Ext2 => (1u64 << 61) - 1,
        BrakedownFieldProfile::Goldilocks64Ext2 => 18446744069414584321,
    }
}

fn default_profile() -> BrakedownFieldProfile {
    BrakedownFieldProfile::Mersenne61Ext2
}

pub fn parse_field_profile(s: &str) -> Option<BrakedownFieldProfile> {
    match s.to_ascii_lowercase().as_str() {
        "toy" | "toyf97" | "f97" => Some(BrakedownFieldProfile::ToyF97),
        "m61" | "mersenne61" | "mersenne61ext2" | "ext2-m61" => {
            Some(BrakedownFieldProfile::Mersenne61Ext2)
        }
        "gold" | "goldilocks" | "goldilocks64ext2" | "ext2-gold" => {
            Some(BrakedownFieldProfile::Goldilocks64Ext2)
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownProof {
    pub outer_trace: OuterSumcheckTrace,
    pub inner_trace: SumcheckTrace,
    pub gamma: Fp,
    pub claimed_value: Fp,
    pub blind_eval_1: Fp,
    pub blind_eval_2: Fp,
    pub blind_mix_alpha: Fp,
    pub reference_profile: ReferenceProfile,
    pub verifier_commitment: BrakedownVerifierCommitment,
    pub pcs_proof_main: BrakedownEvalProof,
    pub pcs_proof_blind_1: BrakedownEvalProof,
    pub pcs_proof_blind_2: BrakedownEvalProof,
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPublic {
    pub outer_tensor_main: Vec<Fp>,
    pub outer_tensor_blind_1: Vec<Fp>,
    pub outer_tensor_blind_2: Vec<Fp>,
    pub inner_tensor: Vec<Fp>,
    pub claimed_value_unblinded: Fp,
    pub claimed_value_masked: Fp,
    pub reference_profile: ReferenceProfile,
}

#[derive(Debug, Clone)]
pub struct KernelTimingMs {
    pub k0_input_parse_ms: f64,
    pub k1_spartan_prove_ms: f64,
    pub k2_pcs_prove_ms: f64,
    pub k3_verify_ms: f64,
}

impl KernelTimingMs {
    pub fn total_ms(&self) -> f64 {
        self.k0_input_parse_ms + self.k1_spartan_prove_ms + self.k2_pcs_prove_ms + self.k3_verify_ms
    }

    pub fn pct(&self, v: f64) -> f64 {
        let total = self.total_ms();
        if total <= 0.0 {
            0.0
        } else {
            (v / total) * 100.0
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPipelineResult {
    pub proof: SpartanBrakedownProof,
    pub public: SpartanBrakedownPublic,
    pub timings: KernelTimingMs,
}

pub fn prove_from_dir(case_dir: &Path) -> Result<SpartanBrakedownPipelineResult> {
    prove_from_dir_with_profile(case_dir, default_profile())
}

pub fn prove_from_dir_with_profile(
    case_dir: &Path,
    profile: BrakedownFieldProfile,
) -> Result<SpartanBrakedownPipelineResult> {
    let _mod_scope = ModulusScope::enter(field_modulus_for_profile(profile));
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

    let mut tr_p = Transcript::new(NIZK_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    append_reference_profile_to_transcript(&mut tr_p, &DUAL_REFERENCE_PROFILE);
    append_case_to_transcript(&mut tr_p, &case);

    let outer_trace = prove_outer_sumcheck_with_transcript(&weighted_residual, &mut tr_p);
    let r_x = outer_trace
        .rounds
        .iter()
        .map(|rr| rr.challenge_r)
        .collect::<Vec<_>>();
    let row_weights = build_eq_weights_from_challenges(&r_x);

    let gamma = sample_gamma_from_transcript(&mut tr_p, &az, &bz, &cz);
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
    let blind_vec_1 = sample_blind_vec_from_transcript(&mut tr_p, case.z.len());
    let blind_eval_1 = inner_product(&blind_vec_1, &case.z);
    let blind_vec_2 = sample_blind_vec_from_transcript(&mut tr_p, case.z.len());
    let blind_eval_2 = inner_product(&blind_vec_2, &case.z);
    let blind_mix_alpha = sample_blind_mix_alpha_from_transcript(&mut tr_p);
    let claimed_value_masked = claimed_value_unblinded
        .add(blind_eval_1)
        .add(blind_mix_alpha.mul(blind_eval_2));

    append_fp_le(&mut tr_p, b"claimed_value_unblinded", claimed_value_unblinded);
    append_fp_le(&mut tr_p, b"blind_eval_1", blind_eval_1);
    append_fp_le(&mut tr_p, b"blind_eval_2", blind_eval_2);
    append_fp_le(&mut tr_p, b"blind_mix_alpha", blind_mix_alpha);
    append_fp_le(&mut tr_p, b"claimed_value_masked", claimed_value_masked);

    let k1_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let coeff_rows = vec![a_bound, b_bound, c_bound, blind_vec_1, blind_vec_2];
    let coeffs = flatten_rows(&coeff_rows);

    let params = params_for_profile(case.a[0].len(), profile);
    let pcs = BrakedownPcs::new(params);
    let prover_commitment = pcs.commit(&coeffs)?;
    let verifier_commitment = pcs.verifier_commitment(&prover_commitment);

    tr_p.append_message(b"nizk_opening_label", b"masked_main_opening");
    tr_p.append_message(b"polycommit", &verifier_commitment.root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);

    let outer_tensor_main = vec![Fp::new(1), gamma, gamma_sq, Fp::new(1), blind_mix_alpha];
    let outer_tensor_blind_1 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
    ];
    let outer_tensor_blind_2 = vec![
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
    let k2_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let proof = SpartanBrakedownProof {
        outer_trace,
        inner_trace,
        gamma,
        claimed_value: claimed_value_masked,
        blind_eval_1,
        blind_eval_2,
        blind_mix_alpha,
        reference_profile: DUAL_REFERENCE_PROFILE,
        verifier_commitment,
        pcs_proof_main,
        pcs_proof_blind_1,
        pcs_proof_blind_2,
    };

    let public = SpartanBrakedownPublic {
        outer_tensor_main,
        outer_tensor_blind_1,
        outer_tensor_blind_2,
        inner_tensor: case.z,
        claimed_value_unblinded,
        claimed_value_masked,
        reference_profile: DUAL_REFERENCE_PROFILE,
    };

    let t3 = Instant::now();
    verify_from_dir(case_dir, &proof)?;
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
    let _mod_scope = ModulusScope::enter(field_modulus_for_profile(
        proof.verifier_commitment.field_profile,
    ));
    let case = load_spartan_like_case_from_dir(case_dir)?;
    let rows = case.a.len();
    let cols = case.a[0].len();

    if proof.outer_trace.rounds.len() != rows.trailing_zeros() as usize {
        return Err(anyhow!("outer rounds do not match row count"));
    }
    if proof.inner_trace.rounds.len() != cols.trailing_zeros() as usize {
        return Err(anyhow!("inner rounds do not match column count"));
    }

    if proof.verifier_commitment.n_rows != 5 || proof.verifier_commitment.n_per_row != cols {
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
    append_case_to_transcript(&mut tr_v, &case);

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

    let expected_gamma = sample_gamma_from_transcript(&mut tr_v, &az, &bz, &cz);
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

    let blind_vec_1 = sample_blind_vec_from_transcript(&mut tr_v, case.z.len());
    let expected_blind_eval_1 = inner_product(&blind_vec_1, &case.z);
    if expected_blind_eval_1 != proof.blind_eval_1 {
        return Err(anyhow!(
            "blind evaluation 1 mismatch vs transcript-derived blind vector"
        ));
    }
    let blind_vec_2 = sample_blind_vec_from_transcript(&mut tr_v, case.z.len());
    let expected_blind_eval_2 = inner_product(&blind_vec_2, &case.z);
    if expected_blind_eval_2 != proof.blind_eval_2 {
        return Err(anyhow!(
            "blind evaluation 2 mismatch vs transcript-derived blind vector"
        ));
    }
    let expected_blind_mix_alpha = sample_blind_mix_alpha_from_transcript(&mut tr_v);
    if expected_blind_mix_alpha != proof.blind_mix_alpha {
        return Err(anyhow!(
            "blind mix alpha mismatch vs transcript-derived challenge"
        ));
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
    if proof.inner_trace.claim_initial != expected_claimed_unblinded {
        return Err(anyhow!("inner initial claim mismatch vs bound/input"));
    }

    let expected_masked = expected_claimed_unblinded
        .add(expected_blind_eval_1)
        .add(expected_blind_mix_alpha.mul(expected_blind_eval_2));
    if proof.claimed_value != expected_masked {
        return Err(anyhow!("masked claimed value mismatch"));
    }

    append_fp_le(&mut tr_v, b"claimed_value_unblinded", expected_claimed_unblinded);
    append_fp_le(&mut tr_v, b"blind_eval_1", proof.blind_eval_1);
    append_fp_le(&mut tr_v, b"blind_eval_2", proof.blind_eval_2);
    append_fp_le(&mut tr_v, b"blind_mix_alpha", proof.blind_mix_alpha);
    append_fp_le(&mut tr_v, b"claimed_value_masked", proof.claimed_value);
    tr_v.append_message(b"nizk_opening_label", b"masked_main_opening");
    tr_v.append_message(b"polycommit", &proof.verifier_commitment.root);
    append_u64_le(&mut tr_v, b"ncols", proof.verifier_commitment.n_cols as u64);

    let params = params_for_profile(cols, proof.verifier_commitment.field_profile);
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
    ];
    let outer_tensor_blind_1 = vec![
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        Fp::new(1),
        Fp::zero(),
    ];
    let outer_tensor_blind_2 = vec![
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
    let proof = &result.proof;
    let public = &result.public;
    let t = &result.timings;

    let mut out = String::new();
    out.push_str("=== Spartan + Brakedown Full-Style NIZK Report (Research) ===\n");
    out.push_str("\n[Scope]\n");
    out.push_str("- modular/unit tests keep SHA path for local arithmetic isolation\n");
    out.push_str("- integrated NIZK path uses single merlin transcript across outer/inner/pcs\n");
    out.push_str("- includes transcript-bound two-component ZK masking at PCS boundary\n");
    out.push_str("- NOTE: this is research/demo code, not production-hardened NIZK\n");

    out.push_str("\n[Prove/Kernels]\n");
    out.push_str("input_parse:\n");
    out.push_str(&format!("  source: {}\n", case_dir.display()));
    out.push_str(&format!("  time_ms: {:.3}\n", t.k0_input_parse_ms));

    out.push_str("spartan_prove_core:\n");
    out.push_str(&format!(
        "  output: outer_rounds={}, inner_rounds={}, gamma={}\n",
        proof.outer_trace.rounds.len(),
        proof.inner_trace.rounds.len(),
        proof.gamma.0
    ));
    out.push_str(&format!(
        "  unblinded_claim(inner sumcheck)={}\n",
        public.claimed_value_unblinded.0
    ));
    out.push_str(&format!("  blind_eval_1={}\n", proof.blind_eval_1.0));
    out.push_str(&format!("  blind_eval_2={}\n", proof.blind_eval_2.0));
    out.push_str(&format!("  blind_mix_alpha={}\n", proof.blind_mix_alpha.0));
    out.push_str(&format!("  masked_claim={}\n", proof.claimed_value.0));
    out.push_str(&format!("  time_ms: {:.3}\n", t.k1_spartan_prove_ms));

    out.push_str("pcs_commit_open_prove:\n");
    out.push_str(&format!(
        "  output: root={}\n",
        hex::encode(proof.verifier_commitment.root)
    ));
    out.push_str(&format!(
        "  main payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
        proof.pcs_proof_main.p_eval.len(),
        proof.pcs_proof_main.p_random_vec.len(),
        proof.pcs_proof_main.columns.len()
    ));
    out.push_str(&format!(
        "  blind1 payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
        proof.pcs_proof_blind_1.p_eval.len(),
        proof.pcs_proof_blind_1.p_random_vec.len(),
        proof.pcs_proof_blind_1.columns.len()
    ));
    out.push_str(&format!(
        "  blind2 payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
        proof.pcs_proof_blind_2.p_eval.len(),
        proof.pcs_proof_blind_2.p_random_vec.len(),
        proof.pcs_proof_blind_2.columns.len()
    ));
    out.push_str(&format!("  time_ms: {:.3}\n", t.k2_pcs_prove_ms));

    out.push_str("\n[Payload Prove -> Verify]\n");
    out.push_str("from spartan_prove_core:\n");
    out.push_str("  - outer_trace messages (g0,g2,g3 per round)\n");
    out.push_str("  - inner_trace messages (h0,h1,h2 per round)\n");
    out.push_str(&format!("  - gamma={}\n", proof.gamma.0));
    out.push_str(&format!(
        "  - unblinded_claim={}\n",
        public.claimed_value_unblinded.0
    ));
    out.push_str(&format!("  - blind_eval_1={}\n", proof.blind_eval_1.0));
    out.push_str(&format!("  - blind_eval_2={}\n", proof.blind_eval_2.0));
    out.push_str(&format!("  - blind_mix_alpha={}\n", proof.blind_mix_alpha.0));
    out.push_str(&format!("  - masked_claim={}\n", proof.claimed_value.0));
    out.push_str("from pcs_commit_open_prove:\n");
    out.push_str(&format!(
        "  - verifier commitment root={}\n",
        hex::encode(proof.verifier_commitment.root)
    ));
    out.push_str("  - pcs main opening proof (masked claim)\n");
    out.push_str("  - pcs blind opening proof #1 (blind component 1)\n");
    out.push_str("  - pcs blind opening proof #2 (blind component 2)\n");
    out.push_str("public verifier input:\n");
    out.push_str("  - (A,B,C,z) loaded from case_dir\n");
    out.push_str(&format!(
        "  - outer_tensor_main=[1,gamma,gamma^2,1,alpha]=[1,{},{},1,{}]\n",
        proof.gamma.0,
        proof.gamma.mul(proof.gamma).0,
        proof.blind_mix_alpha.0
    ));
    out.push_str("  - outer_tensor_blind_1=[0,0,0,1,0]\n");
    out.push_str("  - outer_tensor_blind_2=[0,0,0,0,1]\n");
    out.push_str(&format!(
        "  - inner_tensor(z) len={} (from input)\n",
        public.inner_tensor.len()
    ));

    out.push_str("\n[Verify]\n");
    out.push_str("step 1: replay transcript on (A,B,C,z) + outer rounds and check r_x\n");
    out.push_str("step 2: derive gamma from same transcript and check equality\n");
    out.push_str("step 3: replay transcript on inner rounds and check inner challenges\n");
    out.push_str("step 4: check masked_claim = unblinded_claim + blind_eval_1 + alpha*blind_eval_2\n");
    out.push_str("step 5: verify PCS main opening for masked_claim\n");
    out.push_str("step 6: verify PCS blind opening #1 for blind_eval_1\n");
    out.push_str("step 7: verify PCS blind opening #2 for blind_eval_2\n");
    out.push_str(&format!(
        "verify_result: success, masked_claim={}\n",
        public.claimed_value_masked.0
    ));
    out.push_str(&format!("verify time_ms: {:.3}\n", t.k3_verify_ms));

    out.push_str("\n[Timing Summary]\n");
    out.push_str(&format!(
        "input_parse: {:.3} ms ({:.1}%)\n",
        t.k0_input_parse_ms,
        t.pct(t.k0_input_parse_ms)
    ));
    out.push_str(&format!(
        "spartan_prove_core: {:.3} ms ({:.1}%)\n",
        t.k1_spartan_prove_ms,
        t.pct(t.k1_spartan_prove_ms)
    ));
    out.push_str(&format!(
        "pcs_commit_open_prove: {:.3} ms ({:.1}%)\n",
        t.k2_pcs_prove_ms,
        t.pct(t.k2_pcs_prove_ms)
    ));
    out.push_str(&format!(
        "verify: {:.3} ms ({:.1}%)\n",
        t.k3_verify_ms,
        t.pct(t.k3_verify_ms)
    ));
    out.push_str(&format!("total: {:.3} ms\n", t.total_ms()));
    out.push_str(&format!("\nfield: F_{}\n", current_modulus()));
    out.push_str(&format!(
        "pcs_profile: {:?}\n",
        proof.verifier_commitment.field_profile
    ));

    Ok(out)
}

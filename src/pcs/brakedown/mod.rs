pub mod challenges;
pub mod commit;
pub mod demo;
pub mod encoding;
pub mod merkle;
pub mod profiles;
pub mod prove;
pub mod scalar;
pub mod types;
pub mod verify;
pub mod wire;

use anyhow::Result;
use merlin::Transcript;
use std::marker::PhantomData;

use crate::{
    core::field::{Fp, ModulusScope},
    pcs::traits::PolynomialCommitmentScheme,
};

use self::{
    commit::commit_t,
    prove::prove_eval_t,
    scalar::BrakedownField,
    types::{
        BrakedownEncoding, BrakedownEncoderKind, BrakedownEvalProof, BrakedownFieldProfile,
        BrakedownParams, BrakedownProverCommitment, BrakedownProverCommitmentT,
        BrakedownVerifierCommitment, BrakedownEvalProofT,
    },
    verify::verify_eval_t,
};

#[derive(Clone, Debug)]
pub struct BrakedownPcsT<F = Fp> {
    pub params: BrakedownParams,
    pub encoding: BrakedownEncoding,
    _field: PhantomData<F>,
}

pub type BrakedownPcs = BrakedownPcsT<Fp>;

impl<F> BrakedownPcsT<F> {
    pub fn new(params: BrakedownParams) -> Self {
        let mut tuned = params.clone();
        let encoding = BrakedownEncoding::from_params(&tuned);
        if tuned.auto_tune_security {
            tuned.n_degree_tests = calc_n_degree_tests(
                tuned.security_bits,
                encoding.n_cols,
                tuned.field_profile.flog2(),
            );
            let delta_hint = code_distance_hint(tuned.encoder_kind.clone());
            tuned.n_col_opens = calc_n_col_opens(tuned.security_bits, delta_hint).min(encoding.n_cols);
        }
        Self {
            params: tuned,
            encoding,
            _field: PhantomData,
        }
    }

    fn active_modulus(&self) -> u64 {
        match self.params.field_profile {
            BrakedownFieldProfile::ToyF97 => 97,
            BrakedownFieldProfile::Mersenne61Ext2 => (1u64 << 61) - 1,
            BrakedownFieldProfile::Goldilocks64Ext2 => 18446744069414584321,
        }
    }
}

impl<F: BrakedownField> BrakedownPcsT<F> {
    pub fn commit_generic(&self, coeffs: &[F]) -> Result<BrakedownProverCommitmentT<F>> {
        commit_t(coeffs, &self.encoding)
    }

    pub fn verifier_commitment_generic(
        &self,
        prover_commitment: &BrakedownProverCommitmentT<F>,
    ) -> BrakedownVerifierCommitment {
        prover_commitment.verifier_view(&self.encoding, self.params.field_profile)
    }

    pub fn open_generic(
        &self,
        prover_commitment: &BrakedownProverCommitmentT<F>,
        outer_tensor: &[F],
        transcript: &mut Transcript,
    ) -> Result<BrakedownEvalProofT<F>> {
        prove_eval_t(
            prover_commitment,
            outer_tensor,
            &self.encoding,
            &self.params,
            transcript,
        )
    }

    pub fn verify_generic(
        &self,
        verifier_commitment: &BrakedownVerifierCommitment,
        proof: &BrakedownEvalProofT<F>,
        outer_tensor: &[F],
        inner_tensor: &[F],
        claimed_value: F,
        transcript: &mut Transcript,
    ) -> Result<()> {
        verify_eval_t(
            verifier_commitment,
            proof,
            outer_tensor,
            inner_tensor,
            claimed_value,
            &self.encoding,
            &self.params,
            transcript,
        )
    }
}

fn calc_n_degree_tests(lambda: usize, n_cols: usize, flog2: usize) -> usize {
    let lg_n = (usize::BITS - (n_cols.max(1)).leading_zeros() - 1) as usize;
    let den = flog2.saturating_sub(lg_n).max(1);
    (lambda + den - 1) / den
}

fn calc_n_col_opens(lambda: usize, rel_distance: f64) -> usize {
    // lcpc/brakedown style estimate: ceil(-lambda / log2(1 - dist/3))
    let den = (1.0f64 - rel_distance / 3.0f64).log2();
    (-(lambda as f64) / den).ceil() as usize
}

fn code_distance_hint(kind: BrakedownEncoderKind) -> f64 {
    match kind {
        // SDIG line-3 style hint from lcpc-brakedown default (beta/r ~= 0.0401)
        BrakedownEncoderKind::SpielmanLike => 0.040105193951347796,
        // Toy path is not reference-faithful; keep a looser placeholder distance.
        BrakedownEncoderKind::ToyHybrid => 0.08,
    }
}

impl PolynomialCommitmentScheme for BrakedownPcsT<Fp> {
    type Field = Fp;
    type ProverCommitment = BrakedownProverCommitment;
    type VerifierCommitment = BrakedownVerifierCommitment;
    type OpeningProof = BrakedownEvalProof;

    fn commit(&self, coeffs: &[Self::Field]) -> Result<Self::ProverCommitment> {
        let _scope = ModulusScope::enter(self.active_modulus());
        self.commit_generic(coeffs)
    }

    fn verifier_commitment(
        &self,
        prover_commitment: &Self::ProverCommitment,
    ) -> Self::VerifierCommitment {
        prover_commitment.verifier_view(&self.encoding, self.params.field_profile)
    }

    fn open(
        &self,
        prover_commitment: &Self::ProverCommitment,
        outer_tensor: &[Self::Field],
        transcript: &mut Transcript,
    ) -> Result<Self::OpeningProof> {
        let _scope = ModulusScope::enter(self.active_modulus());
        self.open_generic(prover_commitment, outer_tensor, transcript)
    }

    fn verify(
        &self,
        verifier_commitment: &Self::VerifierCommitment,
        proof: &Self::OpeningProof,
        outer_tensor: &[Self::Field],
        inner_tensor: &[Self::Field],
        claimed_value: Self::Field,
        transcript: &mut Transcript,
    ) -> Result<()> {
        let _scope = ModulusScope::enter(self.active_modulus());
        self.verify_generic(
            verifier_commitment,
            proof,
            outer_tensor,
            inner_tensor,
            claimed_value,
            transcript,
        )
    }
}

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
    profiles::auto_tuned_counts,
    prove::prove_eval_t,
    scalar::BrakedownField,
    types::{
        BrakedownEncoding, BrakedownEvalProof, BrakedownEvalProofT, BrakedownParams,
        BrakedownProverCommitment, BrakedownProverCommitmentT, BrakedownVerifierCommitment,
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
            let (deg, opens) = auto_tuned_counts(
                tuned.security_bits,
                encoding.n_cols,
                tuned.field_profile,
                tuned.encoder_kind.clone(),
            );
            tuned.n_degree_tests = deg;
            tuned.n_col_opens = opens;
        }
        Self {
            params: tuned,
            encoding,
            _field: PhantomData,
        }
    }

    fn active_modulus(&self) -> u64 {
        self.params.field_profile.base_modulus()
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

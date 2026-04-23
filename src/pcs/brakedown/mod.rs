pub mod challenges;
pub mod commit;
pub mod demo;
pub mod encoding;
pub mod merkle;
pub mod prove;
pub mod types;
pub mod verify;

use anyhow::Result;
use merlin::Transcript;

use crate::{core::field::Fp, pcs::traits::PolynomialCommitmentScheme};

use self::{
    commit::commit,
    prove::prove_eval,
    types::{
        BrakedownEncoding, BrakedownEvalProof, BrakedownParams, BrakedownProverCommitment,
        BrakedownVerifierCommitment,
    },
    verify::verify_eval,
};

#[derive(Clone, Debug)]
pub struct BrakedownPcs {
    pub params: BrakedownParams,
    pub encoding: BrakedownEncoding,
}

impl BrakedownPcs {
    pub fn new(params: BrakedownParams) -> Self {
        let encoding = BrakedownEncoding::from_params(&params);
        Self { params, encoding }
    }
}

impl PolynomialCommitmentScheme for BrakedownPcs {
    type Field = Fp;
    type ProverCommitment = BrakedownProverCommitment;
    type VerifierCommitment = BrakedownVerifierCommitment;
    type OpeningProof = BrakedownEvalProof;

    fn commit(&self, coeffs: &[Self::Field]) -> Result<Self::ProverCommitment> {
        commit(coeffs, &self.encoding)
    }

    fn verifier_commitment(
        &self,
        prover_commitment: &Self::ProverCommitment,
    ) -> Self::VerifierCommitment {
        prover_commitment.verifier_view(&self.encoding)
    }

    fn open(
        &self,
        prover_commitment: &Self::ProverCommitment,
        outer_tensor: &[Self::Field],
        transcript: &mut Transcript,
    ) -> Result<Self::OpeningProof> {
        prove_eval(
            prover_commitment,
            outer_tensor,
            &self.encoding,
            &self.params,
            transcript,
        )
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
        verify_eval(
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

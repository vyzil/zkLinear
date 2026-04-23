use anyhow::Result;
use merlin::Transcript;

pub trait PolynomialCommitmentScheme {
    type Field;
    type ProverCommitment;
    type VerifierCommitment;
    type OpeningProof;

    fn commit(&self, coeffs: &[Self::Field]) -> Result<Self::ProverCommitment>;

    fn verifier_commitment(
        &self,
        prover_commitment: &Self::ProverCommitment,
    ) -> Self::VerifierCommitment;

    fn open(
        &self,
        prover_commitment: &Self::ProverCommitment,
        outer_tensor: &[Self::Field],
        transcript: &mut Transcript,
    ) -> Result<Self::OpeningProof>;

    fn verify(
        &self,
        verifier_commitment: &Self::VerifierCommitment,
        proof: &Self::OpeningProof,
        outer_tensor: &[Self::Field],
        inner_tensor: &[Self::Field],
        claimed_value: Self::Field,
        transcript: &mut Transcript,
    ) -> Result<()>;
}

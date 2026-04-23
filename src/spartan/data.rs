use crate::{
    core::field::Fp,
    sumcheck::inner::{inner_product, prove_matrix_vector_inner_sumcheck as prove_matrix_vector_inner_sumcheck_core, SumcheckTrace},
};

#[derive(Debug, Clone)]
pub struct MatrixVectorInnerSumcheckReport {
    pub a: Vec<Vec<Fp>>,
    pub y: Vec<Fp>,
    pub direct_ay: Vec<Fp>,
    pub traces: Vec<SumcheckTrace>,
}

pub fn prove_matrix_vector_inner_sumcheck(
    a: &[Vec<Fp>],
    y: &[Fp],
) -> MatrixVectorInnerSumcheckReport {
    let direct_ay: Vec<Fp> = a.iter().map(|row| inner_product(row, y)).collect();
    let traces = prove_matrix_vector_inner_sumcheck_core(a, y);
    MatrixVectorInnerSumcheckReport {
        a: a.to_vec(),
        y: y.to_vec(),
        direct_ay,
        traces,
    }
}

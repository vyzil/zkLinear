use merlin::Transcript;

use super::scalar::BrakedownField;

pub(crate) fn append_field_elem_t<F: BrakedownField>(
    tr: &mut Transcript,
    label: &'static [u8],
    value: F,
) {
    let mut bytes = Vec::new();
    value.append_le_bytes(&mut bytes);
    tr.append_message(label, &bytes);
}

pub(crate) fn append_field_vec_t<F: BrakedownField>(
    tr: &mut Transcript,
    label: &'static [u8],
    values: &[F],
) {
    for value in values {
        append_field_elem_t(tr, label, *value);
    }
}

pub(crate) fn dot_product_t<F: BrakedownField>(lhs: &[F], rhs: &[F]) -> F {
    lhs.iter()
        .zip(rhs.iter())
        .fold(F::zero(), |acc, (a, b)| acc.add((*a).mul(*b)))
}

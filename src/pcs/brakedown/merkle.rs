use sha2::{Digest, Sha256};

use crate::core::field::Fp;

use super::{scalar::BrakedownField, types::ColumnOpeningT};

pub fn digest_list_t<F: BrakedownField>(values: &[F]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8; 32]);
    let mut buf = Vec::new();
    for v in values {
        buf.clear();
        v.append_le_bytes(&mut buf);
        h.update(&buf);
    }
    h.finalize().into()
}

pub fn digest_fp_list(values: &[Fp]) -> [u8; 32] {
    digest_list_t(values)
}

pub fn merkle_tree(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len().next_power_of_two();
    let mut full = vec![[0u8; 32]; 2 * n - 1];
    full[..leaves.len()].copy_from_slice(leaves);
    for leaf in full.iter_mut().take(n).skip(leaves.len()) {
        *leaf = [0u8; 32];
    }

    let mut layer_start = 0;
    let mut width = n;
    let mut out_start = n;
    while width > 1 {
        for i in 0..(width / 2) {
            let l = full[layer_start + 2 * i];
            let r = full[layer_start + 2 * i + 1];
            let mut h = Sha256::new();
            h.update(l);
            h.update(r);
            full[out_start + i] = h.finalize().into();
        }
        layer_start = out_start;
        out_start += width / 2;
        width /= 2;
    }
    full
}

pub fn merkle_root(nodes: &[[u8; 32]]) -> [u8; 32] {
    *nodes.last().unwrap_or(&[0u8; 32])
}

pub fn verify_column_path_t<F: BrakedownField>(root: [u8; 32], opening: &ColumnOpeningT<F>) -> bool {
    let mut cur = digest_list_t(&opening.values);
    let mut idx = opening.col_idx;
    for s in &opening.merkle_path {
        let mut h = Sha256::new();
        if idx.is_multiple_of(2) {
            h.update(cur);
            h.update(*s);
        } else {
            h.update(*s);
            h.update(cur);
        }
        cur = h.finalize().into();
        idx >>= 1;
    }
    cur == root
}

pub fn verify_column_path(root: [u8; 32], opening: &ColumnOpeningT<Fp>) -> bool {
    verify_column_path_t(root, opening)
}

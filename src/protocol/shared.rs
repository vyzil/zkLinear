use merlin::Transcript;
use sha2::{Digest, Sha256};

use crate::{
    core::field::Fp, io::case_format::SpartanLikeCase, pcs::brakedown::challenges::sample_field_vec,
};

pub fn append_case_to_transcript(tr: &mut Transcript, case: &SpartanLikeCase) {
    tr.append_message(b"rows", &(case.a.len() as u64).to_be_bytes());
    tr.append_message(b"cols", &(case.a[0].len() as u64).to_be_bytes());

    for row in &case.a {
        for v in row {
            tr.append_message(b"A", &v.0.to_be_bytes());
        }
    }
    for row in &case.b {
        for v in row {
            tr.append_message(b"B", &v.0.to_be_bytes());
        }
    }
    for row in &case.c {
        for v in row {
            tr.append_message(b"C", &v.0.to_be_bytes());
        }
    }
    for v in &case.z {
        tr.append_message(b"z", &v.0.to_be_bytes());
    }
}

pub fn compute_case_digest(case: &SpartanLikeCase) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((case.a.len() as u64).to_be_bytes());
    h.update((case.a[0].len() as u64).to_be_bytes());
    for row in &case.a {
        for v in row {
            h.update(v.0.to_be_bytes());
        }
    }
    for row in &case.b {
        for v in row {
            h.update(v.0.to_be_bytes());
        }
    }
    for row in &case.c {
        for v in row {
            h.update(v.0.to_be_bytes());
        }
    }
    for z in &case.z {
        h.update(z.0.to_be_bytes());
    }
    h.finalize().into()
}

pub fn sample_gamma_from_transcript(tr: &mut Transcript, az: &[Fp], bz: &[Fp], cz: &[Fp]) -> Fp {
    tr.append_message(b"gamma_domain", b"spartan-like-joint-challenge");
    for v in az {
        tr.append_message(b"Az", &v.0.to_be_bytes());
    }
    for v in bz {
        tr.append_message(b"Bz", &v.0.to_be_bytes());
    }
    for v in cz {
        tr.append_message(b"Cz", &v.0.to_be_bytes());
    }
    let mut out = [0u8; 32];
    tr.challenge_bytes(b"gamma", &mut out);
    Fp::from_challenge(out)
}

pub fn sample_blind_vec_from_transcript(tr: &mut Transcript, n: usize) -> Vec<Fp> {
    sample_field_vec(tr, b"spartan_nizk_blind_vec", n)
}

pub fn derive_outer_tau_sha(num_vars: usize, az: &[Fp], bz: &[Fp], cz: &[Fp], z: &[Fp]) -> Vec<Fp> {
    let mut tau = Vec::with_capacity(num_vars);
    for i in 0..num_vars {
        let mut h = Sha256::new();
        h.update(b"spartan-outer-tau");
        h.update((i as u64).to_be_bytes());
        for v in az.iter().chain(bz.iter()).chain(cz.iter()).chain(z.iter()) {
            h.update(v.0.to_be_bytes());
        }
        let out: [u8; 32] = h.finalize().into();
        tau.push(Fp::from_challenge(out));
    }
    tau
}

pub fn build_eq_weights_from_challenges(chals: &[Fp]) -> Vec<Fp> {
    let mut w = vec![Fp::new(1)];
    for r in chals {
        let one_minus_r = Fp::new(1).sub(*r);
        let mut nxt = Vec::with_capacity(w.len() * 2);
        for wi in &w {
            nxt.push(wi.mul(one_minus_r));
            nxt.push(wi.mul(*r));
        }
        w = nxt;
    }
    w
}

pub fn bind_rows(matrix: &[Vec<Fp>], weights: &[Fp]) -> Vec<Fp> {
    let cols = matrix[0].len();
    let mut out = vec![Fp::zero(); cols];
    for (row, w) in matrix.iter().zip(weights.iter()) {
        for j in 0..cols {
            out[j] = out[j].add(row[j].mul(*w));
        }
    }
    out
}

pub fn flatten_rows(rows: &[Vec<Fp>]) -> Vec<Fp> {
    let total = rows.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(total);
    for row in rows {
        out.extend_from_slice(row);
    }
    out
}

pub fn matrix_vec_mul(m: &[Vec<Fp>], z: &[Fp]) -> Vec<Fp> {
    m.iter()
        .map(|row| {
            row.iter()
                .zip(z.iter())
                .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)))
        })
        .collect()
}

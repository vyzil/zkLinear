use merlin::Transcript;
use sha2::{Digest, Sha256};

use crate::pcs::brakedown::types::BrakedownFieldProfile;
use crate::protocol::spec_v1::{
    append_fp_le, append_u64_le, BLIND_MIX_LABEL, GAMMA_DOMAIN, GAMMA_LABEL, OUTER_TAU_LABEL,
};
use crate::{core::field::Fp, io::case_format::SpartanLikeCase};

pub fn append_case_to_transcript(tr: &mut Transcript, case: &SpartanLikeCase) {
    append_u64_le(tr, b"rows", case.a.len() as u64);
    append_u64_le(tr, b"cols", case.a[0].len() as u64);

    for row in &case.a {
        for v in row {
            append_fp_le(tr, b"A", *v);
        }
    }
    for row in &case.b {
        for v in row {
            append_fp_le(tr, b"B", *v);
        }
    }
    for row in &case.c {
        for v in row {
            append_fp_le(tr, b"C", *v);
        }
    }
    for v in &case.z {
        append_fp_le(tr, b"z", *v);
    }
}

pub fn append_case_digest_to_transcript(
    tr: &mut Transcript,
    rows: usize,
    cols: usize,
    digest: [u8; 32],
) {
    append_u64_le(tr, b"rows", rows as u64);
    append_u64_le(tr, b"cols", cols as u64);
    tr.append_message(b"case_digest", &digest);
}

pub fn append_field_profile_to_transcript(
    tr: &mut Transcript,
    field_profile: BrakedownFieldProfile,
) {
    let field_tag: &[u8] = match field_profile {
        BrakedownFieldProfile::ToyF97 => b"field:toy-f97",
        BrakedownFieldProfile::Mersenne61Ext2 => b"field:mersenne61-ext2",
        BrakedownFieldProfile::Goldilocks64Ext2 => b"field:goldilocks64-ext2",
    };
    tr.append_message(b"field_profile", field_tag);
}

pub fn compute_case_digest(case: &SpartanLikeCase) -> [u8; 32] {
    // Circuit digest binds only fixed circuit shape/content (A,B,C + dims).
    // Witness-dependent values (z) are intentionally excluded so the digest
    // can be used as a compile-time artifact boundary.
    let mut h = Sha256::new();
    h.update((case.a.len() as u64).to_le_bytes());
    h.update((case.a[0].len() as u64).to_le_bytes());
    for row in &case.a {
        for v in row {
            h.update(v.0.to_le_bytes());
        }
    }
    for row in &case.b {
        for v in row {
            h.update(v.0.to_le_bytes());
        }
    }
    for row in &case.c {
        for v in row {
            h.update(v.0.to_le_bytes());
        }
    }
    h.finalize().into()
}

pub fn sample_gamma_from_transcript(tr: &mut Transcript, az: &[Fp], bz: &[Fp], cz: &[Fp]) -> Fp {
    tr.append_message(b"gamma_domain", GAMMA_DOMAIN);
    for v in az {
        append_fp_le(tr, b"Az", *v);
    }
    for v in bz {
        append_fp_le(tr, b"Bz", *v);
    }
    for v in cz {
        append_fp_le(tr, b"Cz", *v);
    }
    let mut out = [0u8; 32];
    tr.challenge_bytes(GAMMA_LABEL, &mut out);
    Fp::from_challenge(out)
}

pub fn sample_gamma_from_transcript_light(tr: &mut Transcript) -> Fp {
    tr.append_message(b"gamma_domain", GAMMA_DOMAIN);
    let mut out = [0u8; 32];
    tr.challenge_bytes(GAMMA_LABEL, &mut out);
    Fp::from_challenge(out)
}

pub fn sample_blind_mix_alpha_from_transcript(tr: &mut Transcript) -> Fp {
    let mut out = [0u8; 32];
    tr.challenge_bytes(BLIND_MIX_LABEL, &mut out);
    Fp::from_challenge(out)
}

pub fn sample_outer_tau_from_transcript(tr: &mut Transcript, num_vars: usize) -> Vec<Fp> {
    let mut tau = Vec::with_capacity(num_vars);
    for i in 0..num_vars {
        append_u64_le(tr, b"outer_tau_idx", i as u64);
        let mut out = [0u8; 32];
        tr.challenge_bytes(OUTER_TAU_LABEL, &mut out);
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

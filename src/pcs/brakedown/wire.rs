use anyhow::{anyhow, Result};

use crate::core::field::Fp;

use super::types::{
    BrakedownEncoderKind, BrakedownEvalProof, BrakedownEvalProofT, BrakedownFieldProfile,
    BrakedownVerifierCommitment, ColumnOpeningT,
};
use super::scalar::BrakedownField;

const VC_TAG: &[u8; 8] = b"ZKVCB001";
const PF_TAG: &[u8; 8] = b"ZKPFB001";

fn push_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

struct Reader<'a> {
    bytes: &'a [u8],
    idx: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, idx: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.idx)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(anyhow!("wire: truncated input"));
        }
        let s = &self.bytes[self.idx..self.idx + n];
        self.idx += n;
        Ok(s)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let b = self.read_exact(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn read_arr32(&mut self) -> Result<[u8; 32]> {
        let b = self.read_exact(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
}

fn encode_encoder_kind(kind: &BrakedownEncoderKind) -> u8 {
    match kind {
        BrakedownEncoderKind::ToyHybrid => 0,
        BrakedownEncoderKind::SpielmanLike => 1,
    }
}

fn decode_encoder_kind(v: u8) -> Result<BrakedownEncoderKind> {
    match v {
        0 => Ok(BrakedownEncoderKind::ToyHybrid),
        1 => Ok(BrakedownEncoderKind::SpielmanLike),
        _ => Err(anyhow!("wire: unknown encoder kind tag")),
    }
}

fn encode_field_profile(p: BrakedownFieldProfile) -> u8 {
    match p {
        BrakedownFieldProfile::ToyF97 => 0,
        BrakedownFieldProfile::Mersenne61Ext2 => 1,
        BrakedownFieldProfile::Goldilocks64Ext2 => 2,
    }
}

fn decode_field_profile(v: u8) -> Result<BrakedownFieldProfile> {
    match v {
        0 => Ok(BrakedownFieldProfile::ToyF97),
        1 => Ok(BrakedownFieldProfile::Mersenne61Ext2),
        2 => Ok(BrakedownFieldProfile::Goldilocks64Ext2),
        _ => Err(anyhow!("wire: unknown field profile tag")),
    }
}

fn encode_field_t<F: BrakedownField>(out: &mut Vec<u8>, v: F) {
    push_u64_le(out, v.to_u64());
}

fn decode_field_t<F: BrakedownField>(r: &mut Reader<'_>) -> Result<F> {
    let v = r.read_u64_le()?;
    if v >= F::modulus() {
        return Err(anyhow!("wire: invalid field element encoding"));
    }
    Ok(F::new(v))
}

pub fn serialize_verifier_commitment(vc: &BrakedownVerifierCommitment) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 32 + 8 * 8 + 2);
    out.extend_from_slice(VC_TAG);
    out.extend_from_slice(&vc.root);
    push_u64_le(&mut out, vc.n_rows as u64);
    push_u64_le(&mut out, vc.n_per_row as u64);
    push_u64_le(&mut out, vc.n_cols as u64);
    push_u8(&mut out, encode_field_profile(vc.field_profile));
    push_u8(&mut out, encode_encoder_kind(&vc.encoder_kind));
    push_u64_le(&mut out, vc.encoder_seed);
    push_u64_le(&mut out, vc.spel_layers as u64);
    push_u64_le(&mut out, vc.spel_pre_density as u64);
    push_u64_le(&mut out, vc.spel_post_density as u64);
    push_u64_le(&mut out, vc.spel_base_rs_parity as u64);
    out
}

pub fn deserialize_verifier_commitment(bytes: &[u8]) -> Result<BrakedownVerifierCommitment> {
    let mut r = Reader::new(bytes);
    if r.read_exact(8)? != VC_TAG {
        return Err(anyhow!("wire: wrong verifier commitment tag"));
    }
    let root = r.read_arr32()?;
    let n_rows = r.read_u64_le()? as usize;
    let n_per_row = r.read_u64_le()? as usize;
    let n_cols = r.read_u64_le()? as usize;
    let field_profile = decode_field_profile(r.read_u8()?)?;
    let encoder_kind = decode_encoder_kind(r.read_u8()?)?;
    let encoder_seed = r.read_u64_le()?;
    let spel_layers = r.read_u64_le()? as usize;
    let spel_pre_density = r.read_u64_le()? as usize;
    let spel_post_density = r.read_u64_le()? as usize;
    let spel_base_rs_parity = r.read_u64_le()? as usize;
    if r.remaining() != 0 {
        return Err(anyhow!("wire: trailing bytes in verifier commitment"));
    }

    Ok(BrakedownVerifierCommitment {
        root,
        n_rows,
        n_per_row,
        n_cols,
        field_profile,
        encoder_kind,
        encoder_seed,
        spel_layers,
        spel_pre_density,
        spel_post_density,
        spel_base_rs_parity,
    })
}

pub fn serialize_eval_proof(pf: &BrakedownEvalProof) -> Vec<u8> {
    serialize_eval_proof_t::<Fp>(pf)
}

pub fn serialize_eval_proof_t<F: BrakedownField>(pf: &BrakedownEvalProofT<F>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PF_TAG);

    push_u64_le(&mut out, pf.p_eval.len() as u64);
    for v in &pf.p_eval {
        encode_field_t(&mut out, *v);
    }

    push_u64_le(&mut out, pf.p_random_vec.len() as u64);
    for vec in &pf.p_random_vec {
        push_u64_le(&mut out, vec.len() as u64);
        for v in vec {
            encode_field_t(&mut out, *v);
        }
    }

    push_u64_le(&mut out, pf.columns.len() as u64);
    for c in &pf.columns {
        push_u64_le(&mut out, c.col_idx as u64);
        push_u64_le(&mut out, c.values.len() as u64);
        for v in &c.values {
            encode_field_t(&mut out, *v);
        }
        push_u64_le(&mut out, c.merkle_path.len() as u64);
        for s in &c.merkle_path {
            out.extend_from_slice(s);
        }
    }

    out
}

pub fn deserialize_eval_proof(bytes: &[u8]) -> Result<BrakedownEvalProof> {
    deserialize_eval_proof_t::<Fp>(bytes)
}

pub fn deserialize_eval_proof_t<F: BrakedownField>(bytes: &[u8]) -> Result<BrakedownEvalProofT<F>> {
    let mut r = Reader::new(bytes);
    if r.read_exact(8)? != PF_TAG {
        return Err(anyhow!("wire: wrong eval-proof tag"));
    }

    let p_eval_len = r.read_u64_le()? as usize;
    let mut p_eval = Vec::with_capacity(p_eval_len);
    for _ in 0..p_eval_len {
        p_eval.push(decode_field_t::<F>(&mut r)?);
    }

    let rand_count = r.read_u64_le()? as usize;
    let mut p_random_vec = Vec::with_capacity(rand_count);
    for _ in 0..rand_count {
        let len = r.read_u64_le()? as usize;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(decode_field_t::<F>(&mut r)?);
        }
        p_random_vec.push(v);
    }

    let col_count = r.read_u64_le()? as usize;
    let mut columns = Vec::with_capacity(col_count);
    for _ in 0..col_count {
        let col_idx = r.read_u64_le()? as usize;
        let values_len = r.read_u64_le()? as usize;
        let mut values = Vec::with_capacity(values_len);
        for _ in 0..values_len {
            values.push(decode_field_t::<F>(&mut r)?);
        }
        let path_len = r.read_u64_le()? as usize;
        let mut merkle_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            merkle_path.push(r.read_arr32()?);
        }
        columns.push(ColumnOpeningT {
            col_idx,
            values,
            merkle_path,
        });
    }

    if r.remaining() != 0 {
        return Err(anyhow!("wire: trailing bytes in eval proof"));
    }

    Ok(BrakedownEvalProofT {
        p_eval,
        p_random_vec,
        columns,
    })
}

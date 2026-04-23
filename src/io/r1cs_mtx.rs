use std::{fs, path::Path};

use anyhow::{anyhow, bail, Result};

use crate::core::field::Fp;

use super::case_format::{write_spartan_like_case_to_dir, SpartanLikeCase};

#[derive(Debug, Clone)]
struct MtxData {
    rows: usize,
    cols: usize,
    entries: Vec<(usize, usize, u64)>, // zero-based (r, c, value)
}

fn parse_matrix_market(path: &Path) -> Result<MtxData> {
    let text = fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read matrix market file {}: {}", path.display(), e))?;
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| !l.starts_with('%'));

    let dims = lines
        .next()
        .ok_or_else(|| anyhow!("missing dimensions line in {}", path.display()))?;
    let dim_tokens = dims.split_whitespace().collect::<Vec<_>>();
    if dim_tokens.len() != 3 {
        bail!(
            "invalid matrix market dims in {} (expected: rows cols nnz)",
            path.display()
        );
    }
    let rows = dim_tokens[0]
        .parse::<usize>()
        .map_err(|e| anyhow!("invalid rows in {}: {}", path.display(), e))?;
    let cols = dim_tokens[1]
        .parse::<usize>()
        .map_err(|e| anyhow!("invalid cols in {}: {}", path.display(), e))?;
    let nnz = dim_tokens[2]
        .parse::<usize>()
        .map_err(|e| anyhow!("invalid nnz in {}: {}", path.display(), e))?;

    let mut entries = Vec::with_capacity(nnz);
    for line in lines {
        let t = line.split_whitespace().collect::<Vec<_>>();
        if t.len() < 3 {
            bail!("invalid matrix market entry line '{}'", line);
        }
        let r1 = t[0]
            .parse::<usize>()
            .map_err(|e| anyhow!("invalid row index '{}': {}", t[0], e))?;
        let c1 = t[1]
            .parse::<usize>()
            .map_err(|e| anyhow!("invalid col index '{}': {}", t[1], e))?;
        let v = t[2]
            .parse::<u64>()
            .map_err(|e| anyhow!("invalid field value '{}': {}", t[2], e))?;
        if r1 == 0 || c1 == 0 || r1 > rows || c1 > cols {
            bail!("matrix market entry out of range in {}", path.display());
        }
        entries.push((r1 - 1, c1 - 1, v));
    }

    if entries.len() != nnz {
        bail!(
            "nnz mismatch in {} (header {}, parsed {})",
            path.display(),
            nnz,
            entries.len()
        );
    }

    Ok(MtxData { rows, cols, entries })
}

fn parse_vec_values(path: &Path) -> Result<Vec<Fp>> {
    let text = fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read vector file {}: {}", path.display(), e))?;
    let mut vals = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            let v = cur
                .parse::<u64>()
                .map_err(|e| anyhow!("invalid vector value '{}': {}", cur, e))?;
            vals.push(Fp::new(v));
            cur.clear();
        }
    }
    if !cur.is_empty() {
        let v = cur
            .parse::<u64>()
            .map_err(|e| anyhow!("invalid vector value '{}': {}", cur, e))?;
        vals.push(Fp::new(v));
    }
    Ok(vals)
}

fn dense_from_mtx(m: &MtxData) -> Vec<Vec<Fp>> {
    let mut out = vec![vec![Fp::zero(); m.cols]; m.rows];
    for (r, c, v) in &m.entries {
        out[*r][*c] = Fp::new(*v);
    }
    out
}

pub fn load_spartan_like_case_from_mtx_dir(src_dir: &Path) -> Result<SpartanLikeCase> {
    let a = parse_matrix_market(&src_dir.join("A.mtx"))?;
    let b = parse_matrix_market(&src_dir.join("B.mtx"))?;
    let c = parse_matrix_market(&src_dir.join("C.mtx"))?;
    let z = parse_vec_values(&src_dir.join("z.vec"))?;

    if a.rows == 0 || a.cols == 0 {
        bail!("A matrix must not be empty");
    }
    if a.rows != b.rows || a.rows != c.rows || a.cols != b.cols || a.cols != c.cols {
        bail!("A/B/C dimensions must match");
    }
    if z.len() != a.cols {
        bail!(
            "z length must match matrix cols (z={}, cols={})",
            z.len(),
            a.cols
        );
    }
    if !a.cols.is_power_of_two() || !a.rows.is_power_of_two() {
        bail!("rows and cols must be power-of-two for current sumcheck path");
    }

    Ok(SpartanLikeCase {
        a: dense_from_mtx(&a),
        b: dense_from_mtx(&b),
        c: dense_from_mtx(&c),
        z,
    })
}

pub fn import_spartan_like_case_from_mtx_dir(src_dir: &Path, dst_case_dir: &Path) -> Result<()> {
    let case = load_spartan_like_case_from_mtx_dir(src_dir)?;
    write_spartan_like_case_to_dir(dst_case_dir, &case)
}

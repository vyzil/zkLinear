use std::{fs, path::Path};

use anyhow::{anyhow, bail, Result};
use serde_json::Value;

use crate::core::field::{current_modulus, Fp};

use super::case_format::{write_spartan_like_case_to_dir, SpartanLikeCase};

fn next_pow2(x: usize) -> usize {
    if x <= 1 {
        1
    } else {
        x.next_power_of_two()
    }
}

fn dec_str_mod_u64(s: &str, m: u64) -> Result<u64> {
    if s.is_empty() {
        bail!("empty decimal string");
    }
    let mut acc = 0u64;
    for ch in s.chars() {
        let d = ch
            .to_digit(10)
            .ok_or_else(|| anyhow!("invalid decimal character '{}' in '{}'", ch, s))?
            as u64;
        acc = (acc * 10 + d) % m;
    }
    Ok(acc)
}

fn parse_constraint_term_obj(obj: &serde_json::Map<String, Value>, cols: usize) -> Result<Vec<Fp>> {
    let mut row = vec![Fp::zero(); cols];
    for (k, v) in obj {
        let col = k
            .parse::<usize>()
            .map_err(|e| anyhow!("invalid wire index key '{}': {}", k, e))?;
        if col >= cols {
            bail!("wire index {} out of range cols={}", col, cols);
        }
        let coeff_s = v
            .as_str()
            .ok_or_else(|| anyhow!("coefficient must be decimal string"))?;
        let coeff = dec_str_mod_u64(coeff_s, current_modulus())?;
        row[col] = Fp::new(coeff);
    }
    Ok(row)
}

pub fn load_spartan_like_case_from_circom_json(
    r1cs_json_path: &Path,
    witness_json_path: &Path,
) -> Result<SpartanLikeCase> {
    let r1cs_text = fs::read_to_string(r1cs_json_path)
        .map_err(|e| anyhow!("failed reading {}: {}", r1cs_json_path.display(), e))?;
    let wtns_text = fs::read_to_string(witness_json_path)
        .map_err(|e| anyhow!("failed reading {}: {}", witness_json_path.display(), e))?;

    let r1cs: Value = serde_json::from_str(&r1cs_text)
        .map_err(|e| anyhow!("invalid r1cs json {}: {}", r1cs_json_path.display(), e))?;
    let witness: Value = serde_json::from_str(&wtns_text)
        .map_err(|e| anyhow!("invalid witness json {}: {}", witness_json_path.display(), e))?;

    let n_vars = r1cs
        .get("nVars")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("r1cs json missing nVars"))? as usize;
    let constraints = r1cs
        .get("constraints")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("r1cs json missing constraints array"))?;
    let witness_arr = witness
        .as_array()
        .ok_or_else(|| anyhow!("witness json should be an array"))?;

    if witness_arr.len() != n_vars {
        bail!(
            "witness length {} does not match nVars {}",
            witness_arr.len(),
            n_vars
        );
    }

    let rows = constraints.len();
    let cols = n_vars;

    let mut a = vec![vec![Fp::zero(); cols]; rows];
    let mut b = vec![vec![Fp::zero(); cols]; rows];
    let mut c = vec![vec![Fp::zero(); cols]; rows];

    for (r, cons) in constraints.iter().enumerate() {
        let triplet = cons
            .as_array()
            .ok_or_else(|| anyhow!("constraint row must be [A,B,C]"))?;
        if triplet.len() != 3 {
            bail!("constraint row must have 3 terms");
        }
        let ao = triplet[0]
            .as_object()
            .ok_or_else(|| anyhow!("A term must be object"))?;
        let bo = triplet[1]
            .as_object()
            .ok_or_else(|| anyhow!("B term must be object"))?;
        let co = triplet[2]
            .as_object()
            .ok_or_else(|| anyhow!("C term must be object"))?;
        a[r] = parse_constraint_term_obj(ao, cols)?;
        b[r] = parse_constraint_term_obj(bo, cols)?;
        c[r] = parse_constraint_term_obj(co, cols)?;
    }

    let mut z = Vec::with_capacity(cols);
    for w in witness_arr {
        let s = w
            .as_str()
            .ok_or_else(|| anyhow!("witness element must be decimal string"))?;
        z.push(Fp::new(dec_str_mod_u64(s, current_modulus())?));
    }

    // keep variable 0 as constant-1.
    if let Some(first) = z.first_mut() {
        *first = Fp::new(1);
    }

    let target_rows = next_pow2(rows);
    let target_cols = next_pow2(cols);

    if target_cols > cols {
        for m in [&mut a, &mut b, &mut c] {
            for row in m.iter_mut() {
                row.resize(target_cols, Fp::zero());
            }
        }
        z.resize(target_cols, Fp::zero());
    }
    if target_rows > rows {
        let zero_row = vec![Fp::zero(); target_cols];
        for m in [&mut a, &mut b, &mut c] {
            while m.len() < target_rows {
                m.push(zero_row.clone());
            }
        }
    }

    Ok(SpartanLikeCase { a, b, c, z })
}

pub fn import_spartan_like_case_from_circom_json(
    r1cs_json_path: &Path,
    witness_json_path: &Path,
    dst_case_dir: &Path,
) -> Result<()> {
    let case = load_spartan_like_case_from_circom_json(r1cs_json_path, witness_json_path)?;
    write_spartan_like_case_to_dir(dst_case_dir, &case)
}

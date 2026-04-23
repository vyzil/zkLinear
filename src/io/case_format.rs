use std::{fs, path::Path};

use anyhow::{anyhow, bail, Result};

use crate::core::field::Fp;

#[derive(Debug, Clone)]
pub struct MatrixVectorCase {
    pub a: Vec<Vec<Fp>>,
    pub y: Vec<Fp>,
}

#[derive(Debug, Clone)]
pub struct SpartanLikeCase {
    pub a: Vec<Vec<Fp>>,
    pub b: Vec<Vec<Fp>>,
    pub c: Vec<Vec<Fp>>,
    pub z: Vec<Fp>,
}

fn load_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| anyhow!("failed to read {}: {}", path.display(), e))
}

fn parse_usize_list_from_size_line(line: &str) -> Result<Vec<usize>> {
    let (_, rhs) = line
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid size line (missing ':'): {line}"))?;
    rhs.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<usize>()
                .map_err(|e| anyhow!("invalid size token '{s}': {e}"))
        })
        .collect()
}

fn extract_u64_values(text: &str) -> Result<Vec<u64>> {
    let mut values = Vec::new();
    let mut cur = String::new();

    for ch in text.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            let v = cur
                .parse::<u64>()
                .map_err(|e| anyhow!("invalid integer '{}': {}", cur, e))?;
            values.push(v);
            cur.clear();
        }
    }

    if !cur.is_empty() {
        let v = cur
            .parse::<u64>()
            .map_err(|e| anyhow!("invalid integer '{}': {}", cur, e))?;
        values.push(v);
    }

    Ok(values)
}

fn extract_data_section(text: &str) -> Result<String> {
    let lines: Vec<&str> = text.lines().collect();
    let data_line_idx = lines
        .iter()
        .position(|l| l.trim_start().starts_with("data:"))
        .ok_or_else(|| anyhow!("missing data section"))?;
    Ok(lines[data_line_idx + 1..].join("\n"))
}

fn parse_matrix_data(path: &Path) -> Result<Vec<Vec<Fp>>> {
    let text = load_text(path)?;
    let size_line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("size:"))
        .ok_or_else(|| anyhow!("missing size line in {}", path.display()))?;

    let dims = parse_usize_list_from_size_line(size_line)?;
    if dims.len() != 2 {
        bail!("matrix size must be rows,cols in {}", path.display());
    }
    let rows = dims[0];
    let cols = dims[1];

    let raw = extract_data_section(&text)?;
    let vals = extract_u64_values(&raw)?;

    if vals.len() != rows * cols {
        bail!(
            "matrix data length mismatch in {} (expected {}, got {})",
            path.display(),
            rows * cols,
            vals.len()
        );
    }

    Ok(vals
        .chunks(cols)
        .map(|row| row.iter().copied().map(Fp::new).collect::<Vec<_>>())
        .collect())
}

fn parse_vector_data(path: &Path) -> Result<Vec<Fp>> {
    let text = load_text(path)?;
    let size_line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("size:"))
        .ok_or_else(|| anyhow!("missing size line in {}", path.display()))?;

    let dims = parse_usize_list_from_size_line(size_line)?;
    if dims.len() != 1 {
        bail!("vector size must be len in {}", path.display());
    }
    let len = dims[0];

    let raw = extract_data_section(&text)?;
    let vals = extract_u64_values(&raw)?;

    if vals.len() != len {
        bail!(
            "vector data length mismatch in {} (expected {}, got {})",
            path.display(),
            len,
            vals.len()
        );
    }

    Ok(vals.into_iter().map(Fp::new).collect())
}

pub fn load_matrix_vector_case_from_dir(case_dir: &Path) -> Result<MatrixVectorCase> {
    let a = parse_matrix_data(&case_dir.join("_A.data"))?;
    let y = parse_vector_data(&case_dir.join("_y.data"))?;

    if a.is_empty() {
        bail!("A must not be empty");
    }
    if a[0].len() != y.len() {
        bail!("A cols must match y length");
    }
    for row in &a {
        if row.len() != y.len() {
            bail!("all rows in A must have the same length");
        }
        if !row.len().is_power_of_two() {
            bail!("A column length must be power-of-two for this sumcheck demo");
        }
    }

    Ok(MatrixVectorCase { a, y })
}

pub fn load_spartan_like_case_from_dir(case_dir: &Path) -> Result<SpartanLikeCase> {
    let a = parse_matrix_data(&case_dir.join("_A.data"))?;
    let b = parse_matrix_data(&case_dir.join("_B.data"))?;
    let c = parse_matrix_data(&case_dir.join("_C.data"))?;
    let z = parse_vector_data(&case_dir.join("_z.data"))?;

    if a.is_empty() || b.is_empty() || c.is_empty() {
        bail!("A/B/C must not be empty");
    }

    let rows = a.len();
    let cols = a[0].len();
    if b.len() != rows || c.len() != rows {
        bail!("A/B/C must have the same number of rows");
    }
    if z.len() != cols {
        bail!("z length must match matrix column count");
    }

    for m in [&a, &b, &c] {
        for row in m {
            if row.len() != cols {
                bail!("A/B/C must be rectangular and share the same column count");
            }
            if !row.len().is_power_of_two() {
                bail!("matrix column length must be power-of-two for sumcheck demo");
            }
        }
    }

    Ok(SpartanLikeCase { a, b, c, z })
}

fn write_matrix_data(path: &Path, m: &[Vec<Fp>]) -> Result<()> {
    if m.is_empty() {
        bail!("cannot write empty matrix to {}", path.display());
    }
    let rows = m.len();
    let cols = m[0].len();
    for row in m {
        if row.len() != cols {
            bail!("matrix must be rectangular for {}", path.display());
        }
    }

    let mut out = String::new();
    out.push_str("# auto-generated by zkLinear\n");
    out.push_str(&format!("size: {},{}\n", rows, cols));
    out.push_str("data:\n");
    for row in m {
        let line = row
            .iter()
            .map(|v| v.0.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&line);
        out.push('\n');
    }
    fs::write(path, out)
        .map_err(|e| anyhow!("failed to write matrix file {}: {}", path.display(), e))
}

fn write_vector_data(path: &Path, v: &[Fp]) -> Result<()> {
    let mut out = String::new();
    out.push_str("# auto-generated by zkLinear\n");
    out.push_str(&format!("size: {}\n", v.len()));
    out.push_str("data:\n");
    out.push_str(
        &v.iter()
            .map(|x| x.0.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.push('\n');
    fs::write(path, out)
        .map_err(|e| anyhow!("failed to write vector file {}: {}", path.display(), e))
}

pub fn write_spartan_like_case_to_dir(case_dir: &Path, case: &SpartanLikeCase) -> Result<()> {
    fs::create_dir_all(case_dir)
        .map_err(|e| anyhow!("failed to create {}: {}", case_dir.display(), e))?;

    write_matrix_data(&case_dir.join("_A.data"), &case.a)?;
    write_matrix_data(&case_dir.join("_B.data"), &case.b)?;
    write_matrix_data(&case_dir.join("_C.data"), &case.c)?;
    write_vector_data(&case_dir.join("_z.data"), &case.z)?;
    Ok(())
}

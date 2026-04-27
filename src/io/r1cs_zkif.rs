use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use anyhow::{anyhow, bail, Result};
use zkinterface::{
    structs::{constraints::BilinearConstraint, message::Message, variables::Variables},
    Workspace,
};

use crate::core::field::Fp;

use super::instance_format::{write_spartan_like_instance_to_dir, SpartanLikeInstance};

fn decode_le_u64(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(out)
}

fn parse_assignment(vars: &Variables) -> Result<Vec<(u64, Fp)>> {
    let stride = vars.value_size();
    if stride == 0 {
        return Ok(Vec::new());
    }
    let values = vars
        .values
        .as_ref()
        .ok_or_else(|| anyhow!("assignment variables missing value bytes"))?;
    if values.len() != vars.variable_ids.len() * stride {
        bail!("assignment value bytes length mismatch");
    }
    Ok(vars
        .variable_ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let start = i * stride;
            let end = start + stride;
            (*id, Fp::new(decode_le_u64(&values[start..end])))
        })
        .collect())
}

fn add_linear_combination_to_row(
    row: &mut [Fp],
    vars: &Variables,
    col_of: &HashMap<u64, usize>,
) -> Result<()> {
    let stride = vars.value_size();
    let values = vars
        .values
        .as_ref()
        .ok_or_else(|| anyhow!("constraint linear combination is missing coefficient bytes"))?;
    if stride == 0 || values.len() != vars.variable_ids.len() * stride {
        bail!("invalid constraint linear-combination encoding");
    }
    for (i, id) in vars.variable_ids.iter().enumerate() {
        let cidx = *col_of
            .get(id)
            .ok_or_else(|| anyhow!("unknown variable id in constraint: {}", id))?;
        let start = i * stride;
        let end = start + stride;
        let coeff = Fp::new(decode_le_u64(&values[start..end]));
        row[cidx] = row[cidx].add(coeff);
    }
    Ok(())
}

fn next_pow2(x: usize) -> usize {
    if x <= 1 {
        1
    } else {
        x.next_power_of_two()
    }
}

fn pad_instance_pow2(instance: &mut SpartanLikeInstance) {
    let rows = instance.a.len();
    let cols = instance.z.len();
    let target_rows = next_pow2(rows);
    let target_cols = next_pow2(cols);

    if target_cols > cols {
        for m in [&mut instance.a, &mut instance.b, &mut instance.c] {
            for row in m.iter_mut() {
                row.resize(target_cols, Fp::zero());
            }
        }
        instance.z.resize(target_cols, Fp::zero());
    }
    if target_rows > rows {
        let zero_row = vec![Fp::zero(); target_cols];
        for m in [&mut instance.a, &mut instance.b, &mut instance.c] {
            while m.len() < target_rows {
                m.push(zero_row.clone());
            }
        }
    }
}

pub fn load_spartan_like_instance_from_zkif_workspace(
    workspace_dir: &Path,
) -> Result<SpartanLikeInstance> {
    let ws = Workspace::from_dir(workspace_dir).map_err(|e| {
        anyhow!(
            "failed to open zkif workspace {}: {}",
            workspace_dir.display(),
            e
        )
    })?;

    let mut constraints = Vec::<BilinearConstraint>::new();
    let mut assign = HashMap::<u64, Fp>::new();
    let mut var_ids = BTreeSet::<u64>::new();
    var_ids.insert(0); // constant-one slot

    for msg in ws.iter_messages() {
        match msg {
            Message::Header(h) => {
                for (id, v) in parse_assignment(&h.instance_variables)? {
                    assign.insert(id, v);
                    var_ids.insert(id);
                }
            }
            Message::Witness(w) => {
                for (id, v) in parse_assignment(&w.assigned_variables)? {
                    assign.insert(id, v);
                    var_ids.insert(id);
                }
            }
            Message::ConstraintSystem(cs) => {
                for c in cs.constraints {
                    for id in &c.linear_combination_a.variable_ids {
                        var_ids.insert(*id);
                    }
                    for id in &c.linear_combination_b.variable_ids {
                        var_ids.insert(*id);
                    }
                    for id in &c.linear_combination_c.variable_ids {
                        var_ids.insert(*id);
                    }
                    constraints.push(c);
                }
            }
            _ => {}
        }
    }

    if constraints.is_empty() {
        bail!(
            "no constraints found in zkif workspace {}",
            workspace_dir.display()
        );
    }

    let ordered_ids = var_ids.into_iter().collect::<Vec<_>>();
    let cols = ordered_ids.len();
    let rows = constraints.len();
    let col_of = ordered_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, i))
        .collect::<HashMap<_, _>>();

    let mut a = vec![vec![Fp::zero(); cols]; rows];
    let mut b = vec![vec![Fp::zero(); cols]; rows];
    let mut c = vec![vec![Fp::zero(); cols]; rows];

    for (r, cons) in constraints.iter().enumerate() {
        add_linear_combination_to_row(&mut a[r], &cons.linear_combination_a, &col_of)?;
        add_linear_combination_to_row(&mut b[r], &cons.linear_combination_b, &col_of)?;
        add_linear_combination_to_row(&mut c[r], &cons.linear_combination_c, &col_of)?;
    }

    let mut z = ordered_ids
        .iter()
        .map(|id| {
            if *id == 0 {
                Fp::new(1)
            } else {
                *assign.get(id).unwrap_or(&Fp::zero())
            }
        })
        .collect::<Vec<_>>();

    // keep first column as constant-1 variable.
    if z.first().map(|x| x.0) != Some(1) {
        z[0] = Fp::new(1);
    }

    let mut instance = SpartanLikeInstance { a, b, c, z };
    pad_instance_pow2(&mut instance);
    Ok(instance)
}

pub fn import_spartan_like_instance_from_zkif_workspace(
    workspace_dir: &Path,
    dst_instance_dir: &Path,
) -> Result<()> {
    let instance = load_spartan_like_instance_from_zkif_workspace(workspace_dir)?;
    write_spartan_like_instance_to_dir(dst_instance_dir, &instance)
}

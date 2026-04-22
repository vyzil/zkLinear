use anyhow::{Result, anyhow};
use merlin::Transcript;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

const MODULUS: u64 = 97;
const N_DEGREE_TESTS: usize = 2;
const N_COL_OPENS: usize = 3;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Fp(u64);

impl Fp {
  fn new(v: u64) -> Self {
    Self(v % MODULUS)
  }

  fn zero() -> Self {
    Self(0)
  }

  fn add(self, rhs: Self) -> Self {
    Self::new(self.0 + rhs.0)
  }

  fn sub(self, rhs: Self) -> Self {
    Self::new((MODULUS + self.0 - rhs.0) % MODULUS)
  }

  fn mul(self, rhs: Self) -> Self {
    Self::new(self.0 * rhs.0)
  }

  fn from_challenge(bytes: &[u8]) -> Self {
    let mut acc = 0u128;
    for b in bytes {
      acc = ((acc << 8) + *b as u128) % MODULUS as u128;
    }
    Self(acc as u64)
  }
}

#[derive(Clone, Debug)]
struct MiniEncoding {
  n_per_row: usize,
  n_cols: usize,
}

impl MiniEncoding {
  fn new(n_per_row: usize) -> Self {
    // systematic n_per_row + rs(4) + parity(4)
    Self {
      n_per_row,
      n_cols: n_per_row + 8,
    }
  }

  fn encode_row(&self, row: &[Fp]) -> Vec<Fp> {
    let k = self.n_per_row;
    assert_eq!(row.len(), k);

    let mut out = vec![Fp::zero(); self.n_cols];

    // systematic part
    out[..k].copy_from_slice(row);

    // RS-like parity: evaluate polynomial at x = 1..4
    for t in 0..4 {
      let x = Fp::new((t + 1) as u64);
      let mut eval = Fp::zero();
      for c in row.iter().rev() {
        eval = eval.mul(x).add(*c);
      }
      out[k + t] = eval;
    }

    // sparse linear-code parity (deterministic)
    let idx = [
      [0usize, 2, 5],
      [1usize, 3, 6],
      [0usize, 4, 7],
      [2usize, 3, 7],
    ];
    for (j, triple) in idx.iter().enumerate() {
      out[k + 4 + j] = row[triple[0]].add(row[triple[1]].mul(Fp::new(2))).add(row[triple[2]].mul(Fp::new(3)));
    }

    out
  }
}

#[derive(Clone, Debug)]
struct Commitment {
  coeffs: Vec<Fp>,
  encoded: Vec<Fp>,
  n_rows: usize,
  n_per_row: usize,
  n_cols: usize,
  leaf_hashes: Vec<[u8; 32]>,
  merkle_nodes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct ColumnOpening {
  col_idx: usize,
  values: Vec<Fp>,
  merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct EvalProof {
  p_eval: Vec<Fp>,
  p_random_vec: Vec<Vec<Fp>>,
  columns: Vec<ColumnOpening>,
}

fn digest_fp_list(values: &[Fp]) -> [u8; 32] {
  let mut h = Sha256::new();
  h.update([0u8; 32]);
  for v in values {
    h.update(v.0.to_le_bytes());
  }
  h.finalize().into()
}

fn merkle_tree(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
  let n = leaves.len().next_power_of_two();
  let mut full = vec![[0u8; 32]; 2 * n - 1];
  full[..leaves.len()].copy_from_slice(leaves);
  for i in leaves.len()..n {
    full[i] = [0u8; 32];
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

fn merkle_root(nodes: &[[u8; 32]]) -> [u8; 32] {
  *nodes.last().unwrap()
}

fn open_column(comm: &Commitment, col_idx: usize) -> ColumnOpening {
  let mut values = Vec::with_capacity(comm.n_rows);
  for r in 0..comm.n_rows {
    values.push(comm.encoded[r * comm.n_cols + col_idx]);
  }

  let n = comm.n_cols.next_power_of_two();
  let mut path = Vec::new();
  let mut idx = col_idx;
  let mut layer_start = 0usize;
  let mut width = n;
  while width > 1 {
    let sib = idx ^ 1;
    let sib_hash = comm.merkle_nodes[layer_start + sib];
    path.push(sib_hash);
    idx >>= 1;
    layer_start += width;
    width >>= 1;
  }

  ColumnOpening {
    col_idx,
    values,
    merkle_path: path,
  }
}

fn verify_column_path(root: [u8; 32], opening: &ColumnOpening) -> bool {
  let mut cur = digest_fp_list(&opening.values);
  let mut idx = opening.col_idx;
  for s in &opening.merkle_path {
    let mut h = Sha256::new();
    if idx % 2 == 0 {
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

fn collapse_rows(coeffs: &[Fp], tensor: &[Fp], n_rows: usize, n_per_row: usize) -> Vec<Fp> {
  assert_eq!(tensor.len(), n_rows);
  let mut out = vec![Fp::zero(); n_per_row];
  for r in 0..n_rows {
    for c in 0..n_per_row {
      out[c] = out[c].add(coeffs[r * n_per_row + c].mul(tensor[r]));
    }
  }
  out
}

fn sample_field_vec(tr: &mut Transcript, label: &'static [u8], n: usize) -> Vec<Fp> {
  let mut seed = [0u8; 32];
  tr.challenge_bytes(label, &mut seed);
  let mut rng = ChaCha20Rng::from_seed(seed);
  (0..n).map(|_| Fp::new(rng.gen::<u64>())).collect()
}

fn sample_cols(tr: &mut Transcript, n_cols: usize, n_open: usize) -> Vec<usize> {
  let mut seed = [0u8; 32];
  tr.challenge_bytes(b"lcpc_col_open", &mut seed);
  let mut rng = ChaCha20Rng::from_seed(seed);
  (0..n_open).map(|_| rng.gen_range(0..n_cols)).collect()
}

fn commit(coeffs_in: &[Fp], enc: &MiniEncoding) -> Commitment {
  assert_eq!(coeffs_in.len() % enc.n_per_row, 0);
  let n_rows = coeffs_in.len() / enc.n_per_row;

  let mut encoded = vec![Fp::zero(); n_rows * enc.n_cols];
  for r in 0..n_rows {
    let row = &coeffs_in[r * enc.n_per_row..(r + 1) * enc.n_per_row];
    let enc_row = enc.encode_row(row);
    encoded[r * enc.n_cols..(r + 1) * enc.n_cols].copy_from_slice(&enc_row);
  }

  let mut leaf_hashes = Vec::with_capacity(enc.n_cols);
  for c in 0..enc.n_cols {
    let mut col = Vec::with_capacity(n_rows);
    for r in 0..n_rows {
      col.push(encoded[r * enc.n_cols + c]);
    }
    leaf_hashes.push(digest_fp_list(&col));
  }

  let merkle_nodes = merkle_tree(&leaf_hashes);

  Commitment {
    coeffs: coeffs_in.to_vec(),
    encoded,
    n_rows,
    n_per_row: enc.n_per_row,
    n_cols: enc.n_cols,
    leaf_hashes,
    merkle_nodes,
  }
}

fn prove(comm: &Commitment, outer_tensor: &[Fp], enc: &MiniEncoding, tr: &mut Transcript) -> EvalProof {
  let mut p_random_vec = Vec::new();
  for _ in 0..N_DEGREE_TESTS {
    let rand_tensor = sample_field_vec(tr, b"lcpc_deg_test", comm.n_rows);
    let p_rand = collapse_rows(&comm.coeffs, &rand_tensor, comm.n_rows, comm.n_per_row);
    for v in &p_rand {
      let mut b = [0u8; 8];
      b.copy_from_slice(&v.0.to_le_bytes());
      tr.append_message(b"p_random", &b);
    }
    p_random_vec.push(p_rand);
  }

  let p_eval = collapse_rows(&comm.coeffs, outer_tensor, comm.n_rows, comm.n_per_row);
  for v in &p_eval {
    tr.append_message(b"p_eval", &v.0.to_le_bytes());
  }

  let cols = sample_cols(tr, comm.n_cols, N_COL_OPENS)
    .into_iter()
    .map(|c| open_column(comm, c))
    .collect();

  let _ = enc;
  EvalProof {
    p_eval,
    p_random_vec,
    columns: cols,
  }
}

fn verify(
  root: [u8; 32],
  proof: &EvalProof,
  outer_tensor: &[Fp],
  inner_tensor: &[Fp],
  enc: &MiniEncoding,
  n_rows: usize,
  tr: &mut Transcript,
) -> Result<Fp> {
  if outer_tensor.len() != n_rows {
    return Err(anyhow!("outer tensor size mismatch"));
  }
  if inner_tensor.len() != enc.n_per_row {
    return Err(anyhow!("inner tensor size mismatch"));
  }
  if proof.columns.len() != N_COL_OPENS {
    return Err(anyhow!("num openings mismatch"));
  }

  let mut rand_tensors = Vec::new();
  for p_rand in &proof.p_random_vec {
    let t = sample_field_vec(tr, b"lcpc_deg_test", n_rows);
    rand_tensors.push(t);
    for v in p_rand {
      tr.append_message(b"p_random", &v.0.to_le_bytes());
    }
  }
  for v in &proof.p_eval {
    tr.append_message(b"p_eval", &v.0.to_le_bytes());
  }
  let cols_expected = sample_cols(tr, enc.n_cols, N_COL_OPENS);

  let p_eval_enc = enc.encode_row(&proof.p_eval);
  let p_rand_enc: Vec<Vec<Fp>> = proof.p_random_vec.iter().map(|v| enc.encode_row(v)).collect();

  for (i, op) in proof.columns.iter().enumerate() {
    if op.col_idx != cols_expected[i] {
      return Err(anyhow!("opened column index mismatch"));
    }

    // degree tests and eval consistency
    for j in 0..proof.p_random_vec.len() {
      let dot = rand_tensors[j]
        .iter()
        .zip(op.values.iter())
        .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
      if dot != p_rand_enc[j][op.col_idx] {
        return Err(anyhow!("degree-test column check failed"));
      }
    }

    let dot_eval = outer_tensor
      .iter()
      .zip(op.values.iter())
      .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
    if dot_eval != p_eval_enc[op.col_idx] {
      return Err(anyhow!("eval column check failed"));
    }

    if !verify_column_path(root, op) {
      return Err(anyhow!("merkle path failed"));
    }
  }

  let eval = inner_tensor
    .iter()
    .zip(proof.p_eval.iter())
    .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
  Ok(eval)
}

pub fn run_lcpc_brakedown_trace() -> Result<()> {
  println!("\n=== Independent Mini Brakedown-style Trace ===");

  let enc = MiniEncoding::new(8);
  let n_rows = 4;
  let coeffs: Vec<Fp> = (0..(n_rows * enc.n_per_row))
    .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
    .collect();

  let comm = commit(&coeffs, &enc);
  let root = merkle_root(&comm.merkle_nodes);

  println!(
    "dims: n_rows={}, n_per_row={}, n_cols={}",
    comm.n_rows, comm.n_per_row, comm.n_cols
  );
  println!(
    "security params (demo): n_col_opens={}, n_degree_tests={}",
    N_COL_OPENS, N_DEGREE_TESTS
  );
  println!("Merkle root(hex): {}", hex::encode(root));
  println!("leaf count: {}", comm.leaf_hashes.len());

  // univariate-style tensors (same shape idea as lcpc tests)
  let x = Fp::new(7);
  let mut inner = Vec::with_capacity(enc.n_per_row);
  let mut p = Fp::new(1);
  for _ in 0..enc.n_per_row {
    inner.push(p);
    p = p.mul(x);
  }

  let xr = x.mul(*inner.last().unwrap());
  let mut outer = Vec::with_capacity(n_rows);
  let mut q = Fp::new(1);
  for _ in 0..n_rows {
    outer.push(q);
    q = q.mul(xr);
  }

  let mut tr_p = Transcript::new(b"mini-brakedown-demo");
  tr_p.append_message(b"polycommit", &root);
  tr_p.append_message(b"ncols", &(enc.n_cols as u64).to_be_bytes());
  let pf = prove(&comm, &outer, &enc, &mut tr_p);

  println!(
    "proof payload: p_eval_len={}, p_random_count={}, opened_cols={}",
    pf.p_eval.len(),
    pf.p_random_vec.len(),
    pf.columns.len()
  );
  println!(
    "opened col indices: {:?}",
    pf.columns.iter().map(|c| c.col_idx).collect::<Vec<_>>()
  );

  let mut tr_v = Transcript::new(b"mini-brakedown-demo");
  tr_v.append_message(b"polycommit", &root);
  tr_v.append_message(b"ncols", &(enc.n_cols as u64).to_be_bytes());
  let eval = verify(root, &pf, &outer, &inner, &enc, n_rows, &mut tr_v)?;

  println!("verify: success, eval={}", eval.0);
  println!("\n[format]");
  println!("- leaf hash input: H(zero_digest || column values serialized as LE u64)");
  println!("- internal hash input: H(left_hash || right_hash)");
  println!("- opening payload: (column index, column values, merkle sibling path)");

  let ch_sample = Fp::from_challenge(&root);
  let _ = ch_sample.sub(Fp::zero());
  Ok(())
}

use crate::core::field::Fp;

use super::types::MiniEncoding;

impl MiniEncoding {
  pub fn new(n_per_row: usize) -> Self {
    // Demo-only hybrid layout:
    // systematic n_per_row + RS-like parity(4) + fixed sparse linear parity(4).
    // This is intentionally inspection-friendly and not a production Brakedown code choice.
    Self {
      n_per_row,
      n_cols: n_per_row + 8,
    }
  }

  pub fn encode_row(&self, row: &[Fp]) -> Vec<Fp> {
    let k = self.n_per_row;
    assert_eq!(row.len(), k);
    assert!(k >= 8, "demo encoder requires at least 8 coefficients per row");

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
      out[k + 4 + j] = row[triple[0]]
        .add(row[triple[1]].mul(Fp::new(2)))
        .add(row[triple[2]].mul(Fp::new(3)));
    }

    out
  }
}

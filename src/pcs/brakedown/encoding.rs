use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::core::field::Fp;

use super::{
    scalar::BrakedownField,
    types::{BrakedownEncoderKind, BrakedownEncoding, BrakedownParams},
};

impl BrakedownEncoding {
    pub fn from_params(params: &BrakedownParams) -> Self {
        let n_cols = match params.encoder_kind {
            BrakedownEncoderKind::ToyHybrid => params.n_per_row + 8,
            BrakedownEncoderKind::SpielmanLike => {
                // SDIG-inspired demo sizing:
                // input + precode layers + base RS parity + postcode layers.
                let mut cur = params.n_per_row;
                let mut total = cur;
                let mut pre_sizes = Vec::with_capacity(params.spel_layers);
                for _ in 0..params.spel_layers {
                    cur = ceil_div(cur, 2);
                    pre_sizes.push(cur);
                    total += cur;
                }
                total += params.spel_base_rs_parity;
                for sz in pre_sizes.into_iter().rev() {
                    total += ceil_div(sz, 2);
                }
                total
            }
        };

        Self {
            n_per_row: params.n_per_row,
            n_cols,
            kind: params.encoder_kind.clone(),
            seed: params.encoder_seed,
            spel_layers: params.spel_layers,
            spel_pre_density: params.spel_pre_density,
            spel_post_density: params.spel_post_density,
            spel_base_rs_parity: params.spel_base_rs_parity,
        }
    }

    pub fn encode_row(&self, row: &[Fp]) -> Vec<Fp> {
        self.encode_row_t::<Fp>(row)
    }

    pub fn encode_row_t<F: BrakedownField>(&self, row: &[F]) -> Vec<F> {
        match self.kind {
            BrakedownEncoderKind::ToyHybrid => self.encode_row_toy_hybrid_t(row),
            BrakedownEncoderKind::SpielmanLike => self.encode_row_spielman_like_t(row),
        }
    }

    fn encode_row_toy_hybrid_t<F: BrakedownField>(&self, row: &[F]) -> Vec<F> {
        let k = self.n_per_row;
        assert_eq!(row.len(), k);
        assert!(
            k >= 8,
            "demo encoder requires at least 8 coefficients per row"
        );

        let mut out = vec![F::zero(); self.n_cols];

        // systematic part
        out[..k].copy_from_slice(row);

        // RS-like parity: evaluate polynomial at x = 1..4
        for t in 0..4 {
            let x = F::new((t + 1) as u64);
            let mut eval = F::zero();
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
                .add(row[triple[1]].mul(F::new(2)))
                .add(row[triple[2]].mul(F::new(3)));
        }
        out
    }

    fn encode_row_spielman_like_t<F: BrakedownField>(&self, row: &[F]) -> Vec<F> {
        assert_eq!(row.len(), self.n_per_row);
        assert!(
            self.spel_layers > 0,
            "spielman-like encoder needs >=1 layer"
        );
        assert!(self.spel_pre_density > 0, "precode density must be >0");
        assert!(self.spel_post_density > 0, "postcode density must be >0");
        assert!(
            self.spel_base_rs_parity > 0,
            "base RS parity count must be >0"
        );

        // codeword = [systematic | precodes... | base-rs | postcodes...]
        let mut out = Vec::with_capacity(self.n_cols);
        out.extend_from_slice(row);

        // Precode chain (sparse expander-style linear maps)
        let mut pre_layers = Vec::with_capacity(self.spel_layers);
        let mut cur = row.to_vec();
        for layer in 0..self.spel_layers {
            let next_len = ceil_div(cur.len(), 2);
            let next = sparse_layer_map(
                &cur,
                next_len,
                self.spel_pre_density,
                self.seed ^ ((layer as u64) << 32) ^ 0xA5A5_1111,
            );
            out.extend_from_slice(&next);
            pre_layers.push(next.clone());
            cur = next;
        }

        // Base-case RS-like expansion on deepest precode output
        for t in 0..self.spel_base_rs_parity {
            let x = F::new((t + 1) as u64);
            let mut eval = F::zero();
            for c in cur.iter().rev() {
                eval = eval.mul(x).add(*c);
            }
            out.push(eval);
        }

        // Postcode chain (reverse layers, sparse maps again)
        for (rev_idx, src) in pre_layers.iter().rev().enumerate() {
            let post_len = ceil_div(src.len(), 2);
            let post = sparse_layer_map(
                src,
                post_len,
                self.spel_post_density,
                self.seed ^ ((rev_idx as u64) << 32) ^ 0x5A5A_2222,
            );
            out.extend_from_slice(&post);
        }

        assert_eq!(
            out.len(),
            self.n_cols,
            "internal encoding length mismatch (got {}, expected {})",
            out.len(),
            self.n_cols
        );
        out
    }
}

fn ceil_div(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

fn sparse_layer_map<F: BrakedownField>(
    input: &[F],
    out_len: usize,
    density: usize,
    seed: u64,
) -> Vec<F> {
    let mut rng =
        ChaCha20Rng::seed_from_u64(seed ^ (input.len() as u64) ^ ((out_len as u64) << 16));
    let mut out = vec![F::zero(); out_len];
    let eff_density = density.min(input.len());

    for o in &mut out {
        let mut acc = F::zero();
        // Sample distinct neighbors so configured density is respected.
        let mut idx_pool: Vec<usize> = (0..input.len()).collect();
        for i in 0..eff_density {
            let j = i + rng.gen_range(0..(input.len() - i));
            idx_pool.swap(i, j);
            let idx = idx_pool[i];
            // Deterministic non-zero coefficient from PRG stream.
            let mut coeff = F::new(rng.r#gen::<u64>());
            if coeff == F::zero() {
                coeff = F::new(1);
            }
            acc = acc.add(input[idx].mul(coeff));
        }
        *o = acc;
    }

    out
}

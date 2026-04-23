use super::types::{BrakedownEncoderKind, BrakedownFieldProfile, BrakedownParams};

/// Small, explicit presets for staged experiments.
///
/// NOTE:
/// - These presets are for reproducible software profiling.
/// - They are not final cryptographic production claims.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BrakedownSecurityPreset {
    DemoToy,
    LcpcLikeMersenne61Ext2,
    LcpcLikeGoldilocks64Ext2,
    ProductionMersenne61Ext2,
    ProductionGoldilocks64Ext2,
}

impl BrakedownSecurityPreset {
    pub fn params(self, n_per_row: usize) -> BrakedownParams {
        match self {
            BrakedownSecurityPreset::DemoToy => BrakedownParams::new(n_per_row),
            BrakedownSecurityPreset::LcpcLikeMersenne61Ext2 => {
                BrakedownParams::new_with_field_profile(
                    n_per_row,
                    BrakedownFieldProfile::Mersenne61Ext2,
                )
            }
            BrakedownSecurityPreset::LcpcLikeGoldilocks64Ext2 => {
                BrakedownParams::new_with_field_profile(
                    n_per_row,
                    BrakedownFieldProfile::Goldilocks64Ext2,
                )
            }
            BrakedownSecurityPreset::ProductionMersenne61Ext2 => {
                production_params(n_per_row, BrakedownFieldProfile::Mersenne61Ext2)
            }
            BrakedownSecurityPreset::ProductionGoldilocks64Ext2 => {
                production_params(n_per_row, BrakedownFieldProfile::Goldilocks64Ext2)
            }
        }
    }
}

fn production_params(n_per_row: usize, field_profile: BrakedownFieldProfile) -> BrakedownParams {
    let mut p = BrakedownParams::new_with_field_profile(n_per_row, field_profile);
    p.encoder_kind = BrakedownEncoderKind::SpielmanLike;
    p.encoder_seed = 0;
    p.spel_layers = 3;
    p.spel_pre_density = 5;
    p.spel_post_density = 4;
    p.spel_base_rs_parity = 16;
    p
}

pub fn rel_distance_hint(kind: BrakedownEncoderKind) -> f64 {
    match kind {
        // SDIG line-3 style hint from lcpc-brakedown default (beta/r ~= 0.0401)
        BrakedownEncoderKind::SpielmanLike => 0.040105193951347796,
        // Toy path is not reference-faithful; keep a looser placeholder distance.
        BrakedownEncoderKind::ToyHybrid => 0.08,
    }
}

pub fn tuned_n_degree_tests(lambda: usize, n_cols: usize, flog2: usize) -> usize {
    let lg_n = (usize::BITS - (n_cols.max(1)).leading_zeros() - 1) as usize;
    let den = flog2.saturating_sub(lg_n).max(1);
    (lambda + den - 1) / den
}

pub fn tuned_n_col_opens(lambda: usize, rel_distance: f64, n_cols: usize) -> usize {
    // lcpc/brakedown style estimate: ceil(-lambda / log2(1 - dist/3))
    let den = (1.0f64 - rel_distance / 3.0f64).log2();
    ((-(lambda as f64) / den).ceil() as usize)
        .max(1)
        .min(n_cols.max(1))
}

pub fn auto_tuned_counts(
    lambda: usize,
    n_cols: usize,
    field_profile: BrakedownFieldProfile,
    encoder_kind: BrakedownEncoderKind,
) -> (usize, usize) {
    let deg = tuned_n_degree_tests(lambda, n_cols, field_profile.flog2());
    let opens = tuned_n_col_opens(lambda, rel_distance_hint(encoder_kind), n_cols);
    (deg, opens)
}

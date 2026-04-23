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

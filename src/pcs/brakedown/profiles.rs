use super::types::{BrakedownFieldProfile, BrakedownParams};

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
        }
    }
}


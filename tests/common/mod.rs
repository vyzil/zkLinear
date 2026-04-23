use zk_linear::pcs::{BrakedownPcs, BrakedownSecurityPreset};

pub const DEFAULT_TEST_N_PER_ROW: usize = 8;

pub fn pcs_from_preset(preset: BrakedownSecurityPreset) -> BrakedownPcs {
    BrakedownPcs::new(preset.params(DEFAULT_TEST_N_PER_ROW))
}


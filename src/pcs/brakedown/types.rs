use crate::core::field::Fp;

pub const DEFAULT_N_DEGREE_TESTS: usize = 2;
pub const DEFAULT_N_COL_OPENS: usize = 3;
pub const DEFAULT_SECURITY_BITS: usize = 128;
pub const DEFAULT_SPEL_LAYERS: usize = 2;
pub const DEFAULT_SPEL_PRE_DENSITY: usize = 3;
pub const DEFAULT_SPEL_POST_DENSITY: usize = 2;
pub const DEFAULT_SPEL_BASE_RS_PARITY: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrakedownEncoderKind {
    ToyHybrid,
    SpielmanLike,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum BrakedownFieldProfile {
    // Legacy toy path currently used by the existing F_97 pipeline.
    ToyF97,
    // Candidate production-oriented paths (base field + D=2 extension).
    Mersenne61Ext2,
    Goldilocks64Ext2,
}

impl BrakedownFieldProfile {
    /// Returns floor(log2(|F|)) used by lcpc's `n_degree_tests` formula.
    pub fn flog2(self) -> usize {
        match self {
            BrakedownFieldProfile::ToyF97 => 6,
            BrakedownFieldProfile::Mersenne61Ext2 => 122,
            BrakedownFieldProfile::Goldilocks64Ext2 => 128,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrakedownParams {
    pub n_per_row: usize,
    pub n_degree_tests: usize,
    pub n_col_opens: usize,
    pub security_bits: usize,
    pub field_profile: BrakedownFieldProfile,
    pub auto_tune_security: bool,
    pub encoder_kind: BrakedownEncoderKind,
    pub encoder_seed: u64,
    pub spel_layers: usize,
    pub spel_pre_density: usize,
    pub spel_post_density: usize,
    pub spel_base_rs_parity: usize,
}

impl BrakedownParams {
    pub fn new(n_per_row: usize) -> Self {
        Self {
            n_per_row,
            n_degree_tests: DEFAULT_N_DEGREE_TESTS,
            n_col_opens: DEFAULT_N_COL_OPENS,
            security_bits: DEFAULT_SECURITY_BITS,
            field_profile: BrakedownFieldProfile::ToyF97,
            auto_tune_security: false,
            encoder_kind: BrakedownEncoderKind::SpielmanLike,
            encoder_seed: 0,
            spel_layers: DEFAULT_SPEL_LAYERS,
            spel_pre_density: DEFAULT_SPEL_PRE_DENSITY,
            spel_post_density: DEFAULT_SPEL_POST_DENSITY,
            spel_base_rs_parity: DEFAULT_SPEL_BASE_RS_PARITY,
        }
    }

    /// Profile helper for staged migration:
    /// - keeps the same encoder path
    /// - enables security-parameter auto-tuning from field profile and encoded column count
    pub fn new_with_field_profile(n_per_row: usize, field_profile: BrakedownFieldProfile) -> Self {
        let mut p = Self::new(n_per_row);
        p.field_profile = field_profile;
        p.auto_tune_security = true;
        p
    }
}

#[derive(Clone, Debug)]
pub struct BrakedownEncoding {
    pub n_per_row: usize,
    pub n_cols: usize,
    pub kind: BrakedownEncoderKind,
    pub seed: u64,
    pub spel_layers: usize,
    pub spel_pre_density: usize,
    pub spel_post_density: usize,
    pub spel_base_rs_parity: usize,
}

#[derive(Clone, Debug)]
pub struct BrakedownProverCommitment {
    pub coeffs: Vec<Fp>,
    pub encoded: Vec<Fp>,
    pub n_rows: usize,
    pub n_per_row: usize,
    pub n_cols: usize,
    pub leaf_hashes: Vec<[u8; 32]>,
    pub merkle_nodes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct BrakedownVerifierCommitment {
    pub root: [u8; 32],
    pub n_rows: usize,
    pub n_per_row: usize,
    pub n_cols: usize,
    pub field_profile: BrakedownFieldProfile,
    pub encoder_kind: BrakedownEncoderKind,
    pub encoder_seed: u64,
    pub spel_layers: usize,
    pub spel_pre_density: usize,
    pub spel_post_density: usize,
    pub spel_base_rs_parity: usize,
}

impl BrakedownProverCommitment {
    pub fn verifier_view(
        &self,
        enc: &BrakedownEncoding,
        field_profile: BrakedownFieldProfile,
    ) -> BrakedownVerifierCommitment {
        BrakedownVerifierCommitment {
            root: *self.merkle_nodes.last().unwrap_or(&[0u8; 32]),
            n_rows: self.n_rows,
            n_per_row: self.n_per_row,
            n_cols: self.n_cols,
            field_profile,
            encoder_kind: enc.kind.clone(),
            encoder_seed: enc.seed,
            spel_layers: enc.spel_layers,
            spel_pre_density: enc.spel_pre_density,
            spel_post_density: enc.spel_post_density,
            spel_base_rs_parity: enc.spel_base_rs_parity,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ColumnOpening {
    pub col_idx: usize,
    pub values: Vec<Fp>,
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct BrakedownEvalProof {
    pub p_eval: Vec<Fp>,
    pub p_random_vec: Vec<Vec<Fp>>,
    pub columns: Vec<ColumnOpening>,
}

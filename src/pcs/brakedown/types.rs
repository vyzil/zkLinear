use crate::core::field::Fp;

pub const DEFAULT_N_DEGREE_TESTS: usize = 2;
pub const DEFAULT_N_COL_OPENS: usize = 3;
pub const DEFAULT_SECURITY_BITS: usize = 128;
pub const DEFAULT_SPEL_LAYERS: usize = 2;
pub const DEFAULT_SPEL_PRE_DENSITY: usize = 3;
pub const DEFAULT_SPEL_POST_DENSITY: usize = 2;
pub const DEFAULT_SPEL_BASE_RS_PARITY: usize = 4;
pub const DEFAULT_PROD_SPEL_LAYERS: usize = 3;
pub const DEFAULT_PROD_SPEL_PRE_DENSITY: usize = 5;
pub const DEFAULT_PROD_SPEL_POST_DENSITY: usize = 4;
pub const DEFAULT_PROD_SPEL_BASE_RS_PARITY: usize = 16;

#[repr(u8)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrakedownEncoderKind {
    ToyHybrid = 1,
    SpielmanLike = 2,
}

impl BrakedownEncoderKind {
    pub fn wire_tag(&self) -> u8 {
        match self {
            BrakedownEncoderKind::ToyHybrid => 0,
            BrakedownEncoderKind::SpielmanLike => 1,
        }
    }

    pub fn from_wire_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(BrakedownEncoderKind::ToyHybrid),
            1 => Some(BrakedownEncoderKind::SpielmanLike),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum BrakedownFieldProfile {
    // Legacy toy path currently used by the existing F_97 pipeline.
    ToyF97 = 1,
    // Candidate production-oriented paths (base field + D=2 extension).
    Mersenne61Ext2 = 2,
    Goldilocks64Ext2 = 3,
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

    pub fn base_modulus(self) -> u64 {
        match self {
            BrakedownFieldProfile::ToyF97 => 97,
            BrakedownFieldProfile::Mersenne61Ext2 => (1u64 << 61) - 1,
            BrakedownFieldProfile::Goldilocks64Ext2 => 18446744069414584321,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "toy" | "toyf97" | "f97" => Some(Self::ToyF97),
            "m61" | "mersenne61" | "mersenne61ext2" | "ext2-m61" => Some(Self::Mersenne61Ext2),
            "gold" | "goldilocks" | "goldilocks64ext2" | "ext2-gold" => {
                Some(Self::Goldilocks64Ext2)
            }
            _ => None,
        }
    }

    pub fn default_nizk_profile() -> Self {
        Self::Mersenne61Ext2
    }

    pub fn wire_tag(self) -> u8 {
        match self {
            BrakedownFieldProfile::ToyF97 => 0,
            BrakedownFieldProfile::Mersenne61Ext2 => 1,
            BrakedownFieldProfile::Goldilocks64Ext2 => 2,
        }
    }

    pub fn from_wire_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(BrakedownFieldProfile::ToyF97),
            1 => Some(BrakedownFieldProfile::Mersenne61Ext2),
            2 => Some(BrakedownFieldProfile::Goldilocks64Ext2),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrakedownParams {
    pub n_per_row: usize,
    pub n_degree_tests: usize,
    pub n_col_opens: usize,
    // Open columns are sampled from [col_open_start, n_cols).
    // Default 0 keeps legacy behavior (full-range sampling).
    pub col_open_start: usize,
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
    fn with_profile_defaults(
        n_per_row: usize,
        field_profile: BrakedownFieldProfile,
        auto_tune_security: bool,
        spel_layers: usize,
        spel_pre_density: usize,
        spel_post_density: usize,
        spel_base_rs_parity: usize,
    ) -> Self {
        Self {
            n_per_row,
            n_degree_tests: DEFAULT_N_DEGREE_TESTS,
            n_col_opens: DEFAULT_N_COL_OPENS,
            col_open_start: 0,
            security_bits: DEFAULT_SECURITY_BITS,
            field_profile,
            auto_tune_security,
            encoder_kind: BrakedownEncoderKind::SpielmanLike,
            encoder_seed: 0,
            spel_layers,
            spel_pre_density,
            spel_post_density,
            spel_base_rs_parity,
        }
    }

    pub fn new(n_per_row: usize) -> Self {
        // Production-oriented default profile for end-to-end runs.
        // Toy profile remains available via `new_toy`.
        Self::with_profile_defaults(
            n_per_row,
            BrakedownFieldProfile::Mersenne61Ext2,
            true,
            DEFAULT_PROD_SPEL_LAYERS,
            DEFAULT_PROD_SPEL_PRE_DENSITY,
            DEFAULT_PROD_SPEL_POST_DENSITY,
            DEFAULT_PROD_SPEL_BASE_RS_PARITY,
        )
    }

    pub fn new_toy(n_per_row: usize) -> Self {
        Self::with_profile_defaults(
            n_per_row,
            BrakedownFieldProfile::ToyF97,
            false,
            DEFAULT_SPEL_LAYERS,
            DEFAULT_SPEL_PRE_DENSITY,
            DEFAULT_SPEL_POST_DENSITY,
            DEFAULT_SPEL_BASE_RS_PARITY,
        )
    }

    /// Profile helper for staged migration:
    /// - keeps the same encoder path
    /// - enables security-parameter auto-tuning from field profile and encoded column count
    pub fn new_with_field_profile(n_per_row: usize, field_profile: BrakedownFieldProfile) -> Self {
        // Keep lcpc-like migration profile distinct from production-pinned defaults.
        Self::with_profile_defaults(
            n_per_row,
            field_profile,
            true,
            DEFAULT_SPEL_LAYERS,
            DEFAULT_SPEL_PRE_DENSITY,
            DEFAULT_SPEL_POST_DENSITY,
            DEFAULT_SPEL_BASE_RS_PARITY,
        )
    }

    /// Spec-v1 production-candidate profile for the current staged codebase.
    ///
    /// This is not a cryptographic proof of security by itself; it is a
    /// deterministic parameter contract used to keep research/profiling runs
    /// aligned and comparable.
    pub fn is_spec_v1_production_candidate(&self) -> bool {
        self.field_profile != BrakedownFieldProfile::ToyF97
            && self.encoder_kind == BrakedownEncoderKind::SpielmanLike
            && self.encoder_seed == 0
            && self.spel_layers == 3
            && self.spel_pre_density == 5
            && self.spel_post_density == 4
            && self.spel_base_rs_parity == 16
            && self.n_degree_tests >= 1
            && self.n_col_opens >= 1
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
pub struct BrakedownProverCommitmentT<F> {
    pub coeffs: Vec<F>,
    pub encoded: Vec<F>,
    pub n_rows: usize,
    pub n_per_row: usize,
    pub n_cols: usize,
    pub leaf_hashes: Vec<[u8; 32]>,
    pub merkle_nodes: Vec<[u8; 32]>,
}

pub type BrakedownProverCommitment = BrakedownProverCommitmentT<Fp>;

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

impl<F> BrakedownProverCommitmentT<F> {
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
pub struct ColumnOpeningT<F> {
    pub col_idx: usize,
    pub values: Vec<F>,
    pub merkle_path: Vec<[u8; 32]>,
}

pub type ColumnOpening = ColumnOpeningT<Fp>;

#[derive(Clone, Debug)]
pub struct BrakedownEvalProofT<F> {
    pub p_eval: Vec<F>,
    pub p_random_vec: Vec<Vec<F>>,
    pub columns: Vec<ColumnOpeningT<F>>,
}

pub type BrakedownEvalProof = BrakedownEvalProofT<Fp>;

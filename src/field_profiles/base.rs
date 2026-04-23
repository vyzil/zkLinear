use core::fmt::Debug;

/// Lightweight trait for 64-bit prime fields used by profile exploration.
///
/// This module is intentionally decoupled from the current `core::field::Fp`
/// path so we can stage field migration without breaking existing tests.
pub trait BaseField64: Copy + Clone + Debug + Eq + PartialEq {
    const MODULUS: u64;

    fn new(v: u64) -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    fn to_u64(self) -> u64;

    fn add(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;

    fn from_challenge(bytes: [u8; 32]) -> Self {
        let mut acc = 0u128;
        for b in bytes {
            acc = ((acc << 8) + b as u128) % (Self::MODULUS as u128);
        }
        Self::new(acc as u64)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Mersenne61(pub u64);

impl Mersenne61 {
    pub const P: u64 = (1u64 << 61) - 1;

    #[inline]
    fn reduce_u128(x: u128) -> u64 {
        // For p = 2^61 - 1, x mod p can be reduced by folding high bits.
        let p = Self::P as u128;
        let mut t = (x & p) + (x >> 61);
        t = (t & p) + (t >> 61);
        if t >= p {
            (t - p) as u64
        } else {
            t as u64
        }
    }
}

impl BaseField64 for Mersenne61 {
    const MODULUS: u64 = Self::P;

    fn new(v: u64) -> Self {
        Self(v % Self::P)
    }

    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn to_u64(self) -> u64 {
        self.0
    }

    fn add(self, rhs: Self) -> Self {
        let mut t = self.0 + rhs.0;
        if t >= Self::P {
            t -= Self::P;
        }
        Self(t)
    }

    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            Self(self.0 - rhs.0)
        } else {
            Self(Self::P - (rhs.0 - self.0))
        }
    }

    fn mul(self, rhs: Self) -> Self {
        Self(Self::reduce_u128((self.0 as u128) * (rhs.0 as u128)))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Goldilocks64(pub u64);

impl Goldilocks64 {
    // 2^64 - 2^32 + 1
    pub const P: u64 = 18446744069414584321;
}

impl BaseField64 for Goldilocks64 {
    const MODULUS: u64 = Self::P;

    fn new(v: u64) -> Self {
        Self((v as u128 % Self::P as u128) as u64)
    }

    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn to_u64(self) -> u64 {
        self.0
    }

    fn add(self, rhs: Self) -> Self {
        let t = self.0 as u128 + rhs.0 as u128;
        Self((t % Self::P as u128) as u64)
    }

    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            Self(self.0 - rhs.0)
        } else {
            Self((Self::P as u128 + self.0 as u128 - rhs.0 as u128) as u64)
        }
    }

    fn mul(self, rhs: Self) -> Self {
        let t = (self.0 as u128) * (rhs.0 as u128);
        Self((t % Self::P as u128) as u64)
    }
}


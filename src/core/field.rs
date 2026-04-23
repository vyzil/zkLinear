pub const MODULUS: u64 = 97;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fp(pub u64);

impl Fp {
    pub fn new(v: u64) -> Self {
        Self(v % MODULUS)
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn add(self, rhs: Self) -> Self {
        Self::new(self.0 + rhs.0)
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self::new((MODULUS + self.0 - rhs.0) % MODULUS)
    }

    pub fn mul(self, rhs: Self) -> Self {
        Self::new(self.0 * rhs.0)
    }

    pub fn from_challenge(bytes: [u8; 32]) -> Self {
        let mut acc = 0u128;
        for b in bytes {
            acc = ((acc << 8) + b as u128) % MODULUS as u128;
        }
        Self(acc as u64)
    }
}

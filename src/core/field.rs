use std::cell::Cell;

pub const MODULUS: u64 = 97;

thread_local! {
    static MODULUS_TL: Cell<u64> = const { Cell::new(MODULUS) };
}

pub fn current_modulus() -> u64 {
    MODULUS_TL.with(|m| m.get())
}

#[derive(Debug)]
pub struct ModulusScope {
    prev: u64,
}

impl ModulusScope {
    pub fn enter(new_modulus: u64) -> Self {
        let prev = MODULUS_TL.with(|m| {
            let old = m.get();
            m.set(new_modulus);
            old
        });
        Self { prev }
    }
}

impl Drop for ModulusScope {
    fn drop(&mut self) {
        MODULUS_TL.with(|m| m.set(self.prev));
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fp(pub u64);

impl Fp {
    pub fn new(v: u64) -> Self {
        let p = current_modulus();
        Self(v % p)
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn add(self, rhs: Self) -> Self {
        Self::new(self.0 + rhs.0)
    }

    pub fn sub(self, rhs: Self) -> Self {
        let p = current_modulus();
        Self::new((p + self.0 - rhs.0) % p)
    }

    pub fn mul(self, rhs: Self) -> Self {
        Self::new(self.0 * rhs.0)
    }

    pub fn from_challenge(bytes: [u8; 32]) -> Self {
        let p = current_modulus();
        let mut acc = 0u128;
        for b in bytes {
            acc = ((acc << 8) + b as u128) % p as u128;
        }
        Self(acc as u64)
    }
}

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
        let p = current_modulus() as u128;
        let v = ((self.0 as u128) + (rhs.0 as u128)) % p;
        Self(v as u64)
    }

    pub fn sub(self, rhs: Self) -> Self {
        let p = current_modulus() as u128;
        let v = ((self.0 as u128) + p - (rhs.0 as u128 % p)) % p;
        Self(v as u64)
    }

    pub fn mul(self, rhs: Self) -> Self {
        let p = current_modulus() as u128;
        let v = ((self.0 as u128) * (rhs.0 as u128)) % p;
        Self(v as u64)
    }

    pub fn inv(self) -> Option<Self> {
        let p = current_modulus() as i128;
        let a = self.0 as i128;
        if a == 0 {
            return None;
        }

        let (mut t, mut new_t) = (0i128, 1i128);
        let (mut r, mut new_r) = (p, a);
        while new_r != 0 {
            let q = r / new_r;
            (t, new_t) = (new_t, t - q * new_t);
            (r, new_r) = (new_r, r - q * new_r);
        }
        if r != 1 {
            return None;
        }
        if t < 0 {
            t += p;
        }
        Some(Self::new(t as u64))
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

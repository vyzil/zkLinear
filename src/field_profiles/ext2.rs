use core::marker::PhantomData;

use super::base::{BaseField64, Goldilocks64, Mersenne61};

pub trait Ext2Config {
    type Base: BaseField64;
    fn non_residue() -> Self::Base;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ext2<C: Ext2Config> {
    pub c0: C::Base,
    pub c1: C::Base,
    _cfg: PhantomData<C>,
}

impl<C: Ext2Config> Ext2<C> {
    pub fn new(c0: C::Base, c1: C::Base) -> Self {
        Self {
            c0,
            c1,
            _cfg: PhantomData,
        }
    }

    pub fn zero() -> Self {
        Self::new(C::Base::zero(), C::Base::zero())
    }

    pub fn one() -> Self {
        Self::new(C::Base::one(), C::Base::zero())
    }

    pub fn add(self, rhs: Self) -> Self {
        Self::new(self.c0.add(rhs.c0), self.c1.add(rhs.c1))
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0.sub(rhs.c0), self.c1.sub(rhs.c1))
    }

    pub fn mul(self, rhs: Self) -> Self {
        // (a + b u)(c + d u) where u^2 = nr
        let ac = self.c0.mul(rhs.c0);
        let bd = self.c1.mul(rhs.c1);
        let ad = self.c0.mul(rhs.c1);
        let bc = self.c1.mul(rhs.c0);
        let c0 = ac.add(bd.mul(C::non_residue()));
        let c1 = ad.add(bc);
        Self::new(c0, c1)
    }

    pub fn inv(self) -> Option<Self> {
        // (a + b u)^-1 = (a - b u) / (a^2 - nr * b^2)
        let a = self.c0;
        let b = self.c1;
        let denom = a.mul(a).sub(b.mul(b).mul(C::non_residue()));
        let denom_inv = denom.inv()?;
        let c0 = a.mul(denom_inv);
        let c1 = C::Base::zero().sub(b).mul(denom_inv);
        Some(Self::new(c0, c1))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Mersenne61Ext2Cfg;

impl Ext2Config for Mersenne61Ext2Cfg {
    type Base = Mersenne61;
    fn non_residue() -> Self::Base {
        // -1 in base field.
        Mersenne61::new(Mersenne61::P - 1)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Goldilocks64Ext2Cfg;

impl Ext2Config for Goldilocks64Ext2Cfg {
    type Base = Goldilocks64;
    fn non_residue() -> Self::Base {
        // -1 in base field.
        Goldilocks64::new(Goldilocks64::P - 1)
    }
}

pub type Mersenne61Ext2 = Ext2<Mersenne61Ext2Cfg>;
pub type Goldilocks64Ext2 = Ext2<Goldilocks64Ext2Cfg>;

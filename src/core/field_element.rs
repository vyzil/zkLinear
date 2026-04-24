use sha2::{Digest, Sha256};

use crate::{
    core::field::Fp,
    field_profiles::{BaseField64, Goldilocks64, Goldilocks64Ext2, Mersenne61, Mersenne61Ext2},
};

pub trait FieldElement: Copy + Clone + Eq + core::fmt::Debug {
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u64(v: u64) -> Self;
    fn add(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;
    fn inv(self) -> Option<Self>;
    fn from_challenge(bytes: [u8; 32]) -> Self;
    fn append_le_bytes(self, out: &mut Vec<u8>);
}

impl FieldElement for Fp {
    fn zero() -> Self {
        Fp::zero()
    }
    fn one() -> Self {
        Fp::new(1)
    }
    fn from_u64(v: u64) -> Self {
        Fp::new(v)
    }
    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }
    fn sub(self, rhs: Self) -> Self {
        self.sub(rhs)
    }
    fn mul(self, rhs: Self) -> Self {
        self.mul(rhs)
    }
    fn inv(self) -> Option<Self> {
        self.inv()
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        Fp::from_challenge(bytes)
    }
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
}

impl FieldElement for Mersenne61 {
    fn zero() -> Self {
        <Mersenne61 as BaseField64>::zero()
    }
    fn one() -> Self {
        <Mersenne61 as BaseField64>::one()
    }
    fn from_u64(v: u64) -> Self {
        <Mersenne61 as BaseField64>::new(v)
    }
    fn add(self, rhs: Self) -> Self {
        <Mersenne61 as BaseField64>::add(self, rhs)
    }
    fn sub(self, rhs: Self) -> Self {
        <Mersenne61 as BaseField64>::sub(self, rhs)
    }
    fn mul(self, rhs: Self) -> Self {
        <Mersenne61 as BaseField64>::mul(self, rhs)
    }
    fn inv(self) -> Option<Self> {
        <Mersenne61 as BaseField64>::inv(self)
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        <Mersenne61 as BaseField64>::from_challenge(bytes)
    }
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
}

impl FieldElement for Goldilocks64 {
    fn zero() -> Self {
        <Goldilocks64 as BaseField64>::zero()
    }
    fn one() -> Self {
        <Goldilocks64 as BaseField64>::one()
    }
    fn from_u64(v: u64) -> Self {
        <Goldilocks64 as BaseField64>::new(v)
    }
    fn add(self, rhs: Self) -> Self {
        <Goldilocks64 as BaseField64>::add(self, rhs)
    }
    fn sub(self, rhs: Self) -> Self {
        <Goldilocks64 as BaseField64>::sub(self, rhs)
    }
    fn mul(self, rhs: Self) -> Self {
        <Goldilocks64 as BaseField64>::mul(self, rhs)
    }
    fn inv(self) -> Option<Self> {
        <Goldilocks64 as BaseField64>::inv(self)
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        <Goldilocks64 as BaseField64>::from_challenge(bytes)
    }
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
}

fn ext2_c1_from_seed(seed: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"zklinear/ext2/c1");
    h.update(seed);
    h.finalize().into()
}

impl FieldElement for Mersenne61Ext2 {
    fn zero() -> Self {
        Mersenne61Ext2::zero()
    }
    fn one() -> Self {
        Mersenne61Ext2::one()
    }
    fn from_u64(v: u64) -> Self {
        Mersenne61Ext2::new(
            <Mersenne61 as BaseField64>::new(v),
            <Mersenne61 as BaseField64>::zero(),
        )
    }
    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }
    fn sub(self, rhs: Self) -> Self {
        self.sub(rhs)
    }
    fn mul(self, rhs: Self) -> Self {
        self.mul(rhs)
    }
    fn inv(self) -> Option<Self> {
        self.inv()
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        let c0 = <Mersenne61 as BaseField64>::from_challenge(bytes);
        let c1 = <Mersenne61 as BaseField64>::from_challenge(ext2_c1_from_seed(bytes));
        Mersenne61Ext2::new(c0, c1)
    }
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.c0.0.to_le_bytes());
        out.extend_from_slice(&self.c1.0.to_le_bytes());
    }
}

impl FieldElement for Goldilocks64Ext2 {
    fn zero() -> Self {
        Goldilocks64Ext2::zero()
    }
    fn one() -> Self {
        Goldilocks64Ext2::one()
    }
    fn from_u64(v: u64) -> Self {
        Goldilocks64Ext2::new(
            <Goldilocks64 as BaseField64>::new(v),
            <Goldilocks64 as BaseField64>::zero(),
        )
    }
    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }
    fn sub(self, rhs: Self) -> Self {
        self.sub(rhs)
    }
    fn mul(self, rhs: Self) -> Self {
        self.mul(rhs)
    }
    fn inv(self) -> Option<Self> {
        self.inv()
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        let c0 = <Goldilocks64 as BaseField64>::from_challenge(bytes);
        let c1 = <Goldilocks64 as BaseField64>::from_challenge(ext2_c1_from_seed(bytes));
        Goldilocks64Ext2::new(c0, c1)
    }
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.c0.0.to_le_bytes());
        out.extend_from_slice(&self.c1.0.to_le_bytes());
    }
}

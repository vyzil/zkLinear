use crate::{
    core::field::{current_modulus, Fp},
    field_profiles::{BaseField64, Goldilocks64, Mersenne61},
};

pub trait BrakedownField: Copy + Clone + Eq + core::fmt::Debug {
    fn zero() -> Self;
    fn new(v: u64) -> Self;
    fn add(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;
    fn to_u64(self) -> u64;
    fn modulus() -> u64;
    fn from_challenge(bytes: [u8; 32]) -> Self;
}

impl BrakedownField for Fp {
    fn zero() -> Self {
        Fp::zero()
    }
    fn new(v: u64) -> Self {
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
    fn to_u64(self) -> u64 {
        self.0
    }
    fn modulus() -> u64 {
        current_modulus()
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        Fp::from_challenge(bytes)
    }
}

impl BrakedownField for Mersenne61 {
    fn zero() -> Self {
        <Mersenne61 as BaseField64>::zero()
    }
    fn new(v: u64) -> Self {
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
    fn to_u64(self) -> u64 {
        <Mersenne61 as BaseField64>::to_u64(self)
    }
    fn modulus() -> u64 {
        Mersenne61::P
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        <Mersenne61 as BaseField64>::from_challenge(bytes)
    }
}

impl BrakedownField for Goldilocks64 {
    fn zero() -> Self {
        <Goldilocks64 as BaseField64>::zero()
    }
    fn new(v: u64) -> Self {
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
    fn to_u64(self) -> u64 {
        <Goldilocks64 as BaseField64>::to_u64(self)
    }
    fn modulus() -> u64 {
        Goldilocks64::P
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        <Goldilocks64 as BaseField64>::from_challenge(bytes)
    }
}


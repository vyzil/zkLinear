use crate::{
    core::field::{current_modulus, Fp},
    field_profiles::{
        BaseField64, Goldilocks64, Goldilocks64Ext2, Mersenne61, Mersenne61Ext2,
    },
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
    fn append_le_bytes(self, out: &mut Vec<u8>);
    fn wire_word_len() -> usize;
    fn to_wire_words(self, out: &mut Vec<u64>);
    fn from_wire_words(words: &[u64]) -> Option<Self>;
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
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
    fn wire_word_len() -> usize {
        1
    }
    fn to_wire_words(self, out: &mut Vec<u64>) {
        out.push(self.0);
    }
    fn from_wire_words(words: &[u64]) -> Option<Self> {
        if words.len() != 1 {
            return None;
        }
        if words[0] >= current_modulus() {
            return None;
        }
        Some(Fp::new(words[0]))
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
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
    fn wire_word_len() -> usize {
        1
    }
    fn to_wire_words(self, out: &mut Vec<u64>) {
        out.push(self.0);
    }
    fn from_wire_words(words: &[u64]) -> Option<Self> {
        if words.len() != 1 || words[0] >= Mersenne61::P {
            return None;
        }
        Some(<Mersenne61 as BaseField64>::new(words[0]))
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
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
    fn wire_word_len() -> usize {
        1
    }
    fn to_wire_words(self, out: &mut Vec<u64>) {
        out.push(self.0);
    }
    fn from_wire_words(words: &[u64]) -> Option<Self> {
        if words.len() != 1 || words[0] >= Goldilocks64::P {
            return None;
        }
        Some(<Goldilocks64 as BaseField64>::new(words[0]))
    }
}

impl BrakedownField for Mersenne61Ext2 {
    fn zero() -> Self {
        Mersenne61Ext2::zero()
    }
    fn new(v: u64) -> Self {
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
    fn to_u64(self) -> u64 {
        self.c0.0
    }
    fn modulus() -> u64 {
        Mersenne61::P
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        let c0 = <Mersenne61 as BaseField64>::from_challenge(bytes);
        let mut seeded = [0u8; 32];
        seeded.copy_from_slice(&bytes);
        seeded[0] ^= 0xA5;
        let c1 = <Mersenne61 as BaseField64>::from_challenge(seeded);
        Mersenne61Ext2::new(c0, c1)
    }
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.c0.0.to_le_bytes());
        out.extend_from_slice(&self.c1.0.to_le_bytes());
    }
    fn wire_word_len() -> usize {
        2
    }
    fn to_wire_words(self, out: &mut Vec<u64>) {
        out.push(self.c0.0);
        out.push(self.c1.0);
    }
    fn from_wire_words(words: &[u64]) -> Option<Self> {
        if words.len() != 2 || words[0] >= Mersenne61::P || words[1] >= Mersenne61::P {
            return None;
        }
        Some(Mersenne61Ext2::new(
            <Mersenne61 as BaseField64>::new(words[0]),
            <Mersenne61 as BaseField64>::new(words[1]),
        ))
    }
}

impl BrakedownField for Goldilocks64Ext2 {
    fn zero() -> Self {
        Goldilocks64Ext2::zero()
    }
    fn new(v: u64) -> Self {
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
    fn to_u64(self) -> u64 {
        self.c0.0
    }
    fn modulus() -> u64 {
        Goldilocks64::P
    }
    fn from_challenge(bytes: [u8; 32]) -> Self {
        let c0 = <Goldilocks64 as BaseField64>::from_challenge(bytes);
        let mut seeded = [0u8; 32];
        seeded.copy_from_slice(&bytes);
        seeded[0] ^= 0x5A;
        let c1 = <Goldilocks64 as BaseField64>::from_challenge(seeded);
        Goldilocks64Ext2::new(c0, c1)
    }
    fn append_le_bytes(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.c0.0.to_le_bytes());
        out.extend_from_slice(&self.c1.0.to_le_bytes());
    }
    fn wire_word_len() -> usize {
        2
    }
    fn to_wire_words(self, out: &mut Vec<u64>) {
        out.push(self.c0.0);
        out.push(self.c1.0);
    }
    fn from_wire_words(words: &[u64]) -> Option<Self> {
        if words.len() != 2 || words[0] >= Goldilocks64::P || words[1] >= Goldilocks64::P {
            return None;
        }
        Some(Goldilocks64Ext2::new(
            <Goldilocks64 as BaseField64>::new(words[0]),
            <Goldilocks64 as BaseField64>::new(words[1]),
        ))
    }
}

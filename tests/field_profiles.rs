use zk_linear::field_profiles::{
    BaseField64, Goldilocks64, Goldilocks64Ext2, Mersenne61, Mersenne61Ext2,
};

#[test]
fn mersenne61_basic_arithmetic() {
    let a = Mersenne61::new(123456789);
    let b = Mersenne61::new(987654321);
    let c = a.add(b);
    let d = c.sub(b);
    assert_eq!(d, a);

    let x = Mersenne61::new((1u64 << 61) - 2);
    let y = Mersenne61::new(5);
    // x == p-1, so (p-1)*5 == p-5 == -5 mod p
    let z = x.mul(y);
    assert_eq!(z.to_u64(), ((1u64 << 61) - 1) - 5);
}

#[test]
fn goldilocks64_basic_arithmetic() {
    let a = Goldilocks64::new(11111111);
    let b = Goldilocks64::new(22222222);
    let c = a.add(b);
    let d = c.sub(a);
    assert_eq!(d, b);

    let p_minus_one = Goldilocks64::new(Goldilocks64::P - 1);
    let two = Goldilocks64::new(2);
    assert_eq!(p_minus_one.mul(two).to_u64(), Goldilocks64::P - 2);
}

#[test]
fn ext2_multiplication_sanity() {
    let a = Mersenne61Ext2::new(Mersenne61::new(3), Mersenne61::new(4));
    let b = Mersenne61Ext2::new(Mersenne61::new(5), Mersenne61::new(6));
    let c = a.mul(b);
    // non_residue = -1:
    // c0 = 3*5 + 4*6*(-1) = 15 - 24 = -9
    // c1 = 3*6 + 4*5 = 38
    assert_eq!(c.c0.to_u64(), Mersenne61::P - 9);
    assert_eq!(c.c1.to_u64(), 38);

    let g1 = Goldilocks64Ext2::new(Goldilocks64::new(1), Goldilocks64::new(2));
    let g2 = Goldilocks64Ext2::new(Goldilocks64::new(7), Goldilocks64::new(11));
    let g3 = g1.mul(g2);
    // c0 = 7 - 22 = -15, c1 = 11 + 14 = 25
    assert_eq!(g3.c0.to_u64(), Goldilocks64::P - 15);
    assert_eq!(g3.c1.to_u64(), 25);
}

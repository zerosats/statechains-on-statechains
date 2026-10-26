//! Scalar-field Montgomery multiplication in a fixed Boolean circuit.
//! Operands and outputs are canonical scalars; Montgomery R is 2^256.
use crate::boolean::{Builder, Wire};
pub(super) const ORDER: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220,
    230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
];

pub(super) fn nonzero(b: &mut Builder, a: &[Wire]) -> Wire {
    a.iter().fold(b.zero, |v, &x| b.or(v, x))
}
pub(super) fn canonical_nonzero(b: &mut Builder, a: &[Wire]) -> Wire {
    let le: Vec<_> = a.iter().rev().copied().collect();
    let q = b.constant_le(&ORDER, 256);
    let (_, canonical) = b.subtract_le(&le, &q);
    let nz = nonzero(b, a);
    b.and(canonical, nz)
}
pub(super) fn multiply(b: &mut Builder, a: &[Wire], c: &[Wire]) -> Vec<Wire> {
    assert_eq!(a.len(), 256);
    assert_eq!(c.len(), 256);
    let a: Vec<_> = a.iter().rev().copied().collect();
    let mut c: Vec<_> = c.iter().rev().copied().collect();
    c.resize(258, b.zero);
    let q = b.constant_le(&ORDER, 258);
    let mut t = vec![b.zero; 258];
    for bit in a {
        let row: Vec<_> = c.iter().map(|&x| b.and(x, bit)).collect();
        t = b.add_le(&t, &row)[..258].to_vec();
        // ORDER is odd. Adding it conditionally makes t even before shifting.
        // Bounds t < 2*ORDER between rounds keep every intermediate < 2^258.
        let low = t[0];
        let correction: Vec<_> = q.iter().map(|&x| b.and(x, low)).collect();
        t = b.add_le(&t, &correction)[1..258].to_vec();
        t.push(b.zero);
    }
    let (reduced, borrow) = b.subtract_le(&t, &q);
    let out: Vec<_> = t
        .iter()
        .zip(reduced)
        .take(256)
        .map(|(&a, c)| {
            let d = b.xor(a, c);
            let d = b.and(borrow, d);
            b.xor(c, d)
        })
        .collect();
    out.into_iter().rev().collect()
}
pub(super) fn subtract(b: &mut Builder, a: &[Wire], c: &[Wire]) -> Vec<Wire> {
    let a: Vec<_> = a.iter().rev().copied().collect();
    let c: Vec<_> = c.iter().rev().copied().collect();
    let (difference, borrow) = b.subtract_le(&a, &c);
    let q = b.constant_le(&ORDER, 256);
    let correction: Vec<_> = q.iter().map(|&v| b.and(v, borrow)).collect();
    b.add_le(&difference, &correction)[..256]
        .iter()
        .rev()
        .copied()
        .collect()
}

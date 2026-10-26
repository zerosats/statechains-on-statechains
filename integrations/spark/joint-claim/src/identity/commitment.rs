//! SHA-256 input consistency for a fixed hidden wallet key share. Commitment
//! precedes nonce exchange, so preprocessing cannot choose another related key.
use crate::boolean::{Builder, Wire};
use sha2::{Digest, Sha256};
pub(super) fn domain() -> [u8; 32] {
    Sha256::digest(b"ZARK/spark/joint-identity/key-commit/v1").into()
}
fn word(b: &Builder, n: u32) -> Vec<Wire> {
    b.constant_le(&n.to_be_bytes(), 32)
        .into_iter()
        .rev()
        .collect()
}
fn add(b: &mut Builder, a: &[Wire], c: &[Wire]) -> Vec<Wire> {
    let a: Vec<_> = a.iter().rev().copied().collect();
    let c: Vec<_> = c.iter().rev().copied().collect();
    b.add_le(&a, &c)[..32].iter().rev().copied().collect()
}
fn rotate(a: &[Wire], n: usize) -> Vec<Wire> {
    a[32 - n..].iter().chain(&a[..32 - n]).copied().collect()
}
fn shift(b: &Builder, a: &[Wire], n: usize) -> Vec<Wire> {
    std::iter::repeat_n(b.zero, n)
        .chain(a[..32 - n].iter().copied())
        .collect()
}
fn xor3(b: &mut Builder, a: &[Wire], c: &[Wire], d: &[Wire]) -> Vec<Wire> {
    let t = b.xor_words(a, c);
    b.xor_words(&t, d)
}
pub(super) fn digest(b: &mut Builder, user: &[Wire], salt: &[Wire]) -> Vec<Wire> {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let iv = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut h: Vec<Vec<Wire>> = iv.iter().map(|&v| word(b, v)).collect();
    let mut message = user.to_vec();
    message.extend_from_slice(salt);
    let one = b.one;
    let zero = b.zero;
    message.extend(
        domain()
            .iter()
            .flat_map(|v| {
                (0..8)
                    .rev()
                    .map(move |i| if v & (1 << i) != 0 { one } else { zero })
            })
            .collect::<Vec<_>>(),
    );
    message.push(b.one);
    message.resize(1024 - 64, b.zero);
    message.extend(b.constant_le(&768u64.to_be_bytes(), 64).into_iter().rev());
    for block in message.chunks(512) {
        let mut w: Vec<Vec<Wire>> = block.chunks(32).map(|v| v.to_vec()).collect();
        for i in 16..64 {
            let s0 = xor3(
                b,
                &rotate(&w[i - 15], 7),
                &rotate(&w[i - 15], 18),
                &shift(b, &w[i - 15], 3),
            );
            let s1 = xor3(
                b,
                &rotate(&w[i - 2], 17),
                &rotate(&w[i - 2], 19),
                &shift(b, &w[i - 2], 10),
            );
            let t = add(b, &w[i - 16], &s0);
            let t = add(b, &t, &w[i - 7]);
            w.push(add(b, &t, &s1));
        }
        let mut s = h.clone();
        for i in 0..64 {
            let e = &s[4];
            let f = &s[5];
            let g = &s[6];
            let big1 = xor3(b, &rotate(e, 6), &rotate(e, 11), &rotate(e, 25));
            let ch: Vec<_> = e
                .iter()
                .zip(f)
                .zip(g)
                .map(|((&e, &f), &g)| {
                    let t = b.xor(f, g);
                    let t = b.and(e, t);
                    b.xor(g, t)
                })
                .collect();
            let t = add(b, &s[7], &big1);
            let t = add(b, &t, &ch);
            let t = add(b, &t, &word(b, K[i]));
            let t1 = add(b, &t, &w[i]);
            let big0 = xor3(b, &rotate(&s[0], 2), &rotate(&s[0], 13), &rotate(&s[0], 22));
            let maj: Vec<_> = s[0]
                .iter()
                .zip(&s[1])
                .zip(&s[2])
                .map(|((&a, &c), &d)| {
                    let t = b.and(a, c);
                    let u = b.xor(a, c);
                    let u = b.and(u, d);
                    b.xor(t, u)
                })
                .collect();
            let t2 = add(b, &big0, &maj);
            let next0 = add(b, &t1, &t2);
            let next4 = add(b, &s[3], &t1);
            s = vec![
                next0,
                s[0].clone(),
                s[1].clone(),
                s[2].clone(),
                next4,
                s[4].clone(),
                s[5].clone(),
                s[6].clone(),
            ];
        }
        h = h.iter().zip(s).map(|(a, c)| add(b, a, &c)).collect();
    }
    h.into_iter().flatten().collect()
}

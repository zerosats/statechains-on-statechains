//! Boolean circuits for modular scalar addition and GCM's binary field.
//! No gate depends on a secret value; private values are supplied only at run.
use tandem::{Circuit, Gate};

pub(super) type Wire = u32;
pub(super) struct Builder {
    pub gates: Vec<Gate>,
    pub zero: Wire,
    pub one: Wire,
}
impl Builder {
    pub fn inputs(contributor: usize, evaluator: usize) -> (Self, Vec<Wire>, Vec<Wire>) {
        let mut gates = Vec::with_capacity(contributor + evaluator);
        let c = (0..contributor)
            .map(|_| {
                let w = gates.len() as Wire;
                gates.push(Gate::InContrib);
                w
            })
            .collect();
        let e = (0..evaluator)
            .map(|_| {
                let w = gates.len() as Wire;
                gates.push(Gate::InEval);
                w
            })
            .collect();
        let zero = gates.len() as Wire;
        gates.push(Gate::Xor(0, 0));
        let one = gates.len() as Wire;
        gates.push(Gate::Not(zero));
        (Self { gates, zero, one }, c, e)
    }
    pub fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        if a == b {
            return self.zero;
        }
        if a == self.zero {
            return b;
        }
        if b == self.zero {
            return a;
        }
        let w = self.gates.len() as Wire;
        self.gates.push(Gate::Xor(a, b));
        w
    }
    pub fn and(&mut self, a: Wire, b: Wire) -> Wire {
        if a == b {
            return a;
        }
        if a == self.zero || b == self.zero {
            return self.zero;
        }
        if a == self.one {
            return b;
        }
        if b == self.one {
            return a;
        }
        let w = self.gates.len() as Wire;
        self.gates.push(Gate::And(a, b));
        w
    }
    pub fn not(&mut self, a: Wire) -> Wire {
        self.xor(a, self.one)
    }
    pub fn xor_words(&mut self, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b).map(|(&a, &b)| self.xor(a, b)).collect()
    }
    pub fn or(&mut self, a: Wire, b: Wire) -> Wire {
        let xor = self.xor(a, b);
        let and = self.and(a, b);
        self.xor(xor, and)
    }
    pub fn constant_le(&self, bytes_be: &[u8], length: usize) -> Vec<Wire> {
        (0..length)
            .map(|i| {
                if i / 8 < bytes_be.len()
                    && bytes_be[bytes_be.len() - 1 - i / 8] & (1 << (i % 8)) != 0
                {
                    self.one
                } else {
                    self.zero
                }
            })
            .collect()
    }
    pub(super) fn add_le(&mut self, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
        let mut carry = self.zero;
        let mut out = Vec::new();
        for (&a, &b) in a.iter().zip(b) {
            let p = self.xor(a, b);
            out.push(self.xor(p, carry));
            let g = self.and(a, b);
            let t = self.and(p, carry);
            carry = self.xor(g, t);
        }
        out.push(carry);
        out
    }
    pub(super) fn subtract_le(&mut self, a: &[Wire], b: &[Wire]) -> (Vec<Wire>, Wire) {
        let mut borrow = self.zero;
        let mut out = Vec::new();
        for (&a, &b) in a.iter().zip(b) {
            let p = self.xor(a, b);
            out.push(self.xor(p, borrow));
            let na = self.not(a);
            let g = self.and(na, b);
            let np = self.not(p);
            let t = self.and(np, borrow);
            borrow = self.xor(g, t);
        }
        (out, borrow)
    }
    /// Both inputs are canonical secp256k1 scalars in big-endian bit order.
    /// A validity output prevents accidental reduction of noncanonical inputs.
    pub fn scalar_sum(&mut self, a: &[Wire], b: &[Wire]) -> (Vec<Wire>, Wire) {
        const ORDER: [u8; 32] = [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186,
            174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
        ];
        let a: Vec<_> = a.iter().rev().copied().collect();
        let b: Vec<_> = b.iter().rev().copied().collect();
        let q = self.constant_le(&ORDER, 256);
        let (_, ca) = self.subtract_le(&a, &q);
        let (_, cb) = self.subtract_le(&b, &q);
        let sum = self.add_le(&a, &b);
        let q = self.constant_le(&ORDER, 257);
        let (reduced, borrow) = self.subtract_le(&sum, &q);
        let out: Vec<_> = sum
            .iter()
            .zip(reduced)
            .take(256)
            .map(|(&a, b)| {
                let diff = self.xor(a, b);
                let select = self.and(borrow, diff);
                self.xor(b, select)
            })
            .collect();
        let nonzero = out.iter().fold(self.zero, |z, &bit| self.or(z, bit));
        let canonical = self.and(ca, cb);
        let valid = self.and(canonical, nonzero);
        (out.into_iter().rev().collect(), valid)
    }
    /// Carryless multiplication. Karatsuba reduces secret AND gates from
    /// 16,384 to 2,187 for a 128-bit GCM field multiplication.
    fn polynomial_product(&mut self, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
        let n = a.len();
        assert_eq!(n, b.len());
        assert!(n.is_power_of_two());
        if n == 1 {
            return vec![self.and(a[0], b[0]), self.zero];
        }
        let m = n / 2;
        let lo = self.polynomial_product(&a[..m], &b[..m]);
        let hi = self.polynomial_product(&a[m..], &b[m..]);
        let ax = self.xor_words(&a[..m], &a[m..]);
        let bx = self.xor_words(&b[..m], &b[m..]);
        let mid = self.polynomial_product(&ax, &bx);
        let mut out = vec![self.zero; 2 * n];
        for i in 0..n {
            out[i] = self.xor(out[i], lo[i]);
            out[n + i] = self.xor(out[n + i], hi[i]);
            let t = self.xor(mid[i], lo[i]);
            let t = self.xor(t, hi[i]);
            out[m + i] = self.xor(out[m + i], t);
        }
        out
    }
    pub fn gcm_multiply(&mut self, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
        let mut product = self.polynomial_product(a, b);
        // GCM bit strings enumerate polynomial coefficients MSB first. Reduce
        // modulo x^128 + x^7 + x^2 + x + 1 in that representation.
        for i in (128..255).rev() {
            for j in [0, 1, 2, 7] {
                product[i - 128 + j] = self.xor(product[i - 128 + j], product[i]);
            }
        }
        product[..128].to_vec()
    }
    pub fn finish(self, output: Vec<Wire>) -> Circuit {
        Circuit::new(self.gates, output)
    }
}

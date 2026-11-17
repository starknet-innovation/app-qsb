//! 256-bit modular arithmetic for the two secp256k1 moduli: the field prime `p`
//! (to test and lift x-coordinates) and the group order `n` (to scale menu
//! scalars). Montgomery multiplication on eight 32-bit limbs, little-endian.
//!
//! Nothing here is constant-time with respect to the exponent's bit length, but
//! every exponent used is a public constant; the operands that can be secret
//! (menu scalars) only meet the data-independent multiplication.

/// A 256-bit integer, least-significant limb first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U256(pub [u32; 8]);

impl U256 {
    pub const ZERO: U256 = U256([0; 8]);
    pub const ONE: U256 = U256([1, 0, 0, 0, 0, 0, 0, 0]);

    pub fn from_be(b: &[u8; 32]) -> U256 {
        let mut l = [0u32; 8];
        for (i, limb) in l.iter_mut().enumerate() {
            let at = 28 - 4 * i;
            *limb = u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        }
        U256(l)
    }

    pub fn to_be(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            let at = 28 - 4 * i;
            b[at..at + 4].copy_from_slice(&limb.to_be_bytes());
        }
        b
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&l| l == 0)
    }

    pub fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// `self < other`.
    pub fn lt(&self, other: &U256) -> bool {
        for i in (0..8).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i] < other.0[i];
            }
        }
        false
    }

    /// `self + other`, and the carry out.
    pub fn add(&self, other: &U256) -> (U256, bool) {
        let mut out = [0u32; 8];
        let mut carry = 0u64;
        for (i, o) in out.iter_mut().enumerate() {
            let s = self.0[i] as u64 + other.0[i] as u64 + carry;
            *o = s as u32;
            carry = s >> 32;
        }
        (U256(out), carry != 0)
    }

    /// `self - other`, and the borrow out.
    pub fn sub(&self, other: &U256) -> (U256, bool) {
        let mut out = [0u32; 8];
        let mut borrow = 0i64;
        for (i, o) in out.iter_mut().enumerate() {
            let d = self.0[i] as i64 - other.0[i] as i64 - borrow;
            *o = d as u32;
            borrow = (d < 0) as i64;
        }
        (U256(out), borrow != 0)
    }

    fn bit(&self, i: usize) -> bool {
        (self.0[i / 32] >> (i % 32)) & 1 == 1
    }
}

/// An odd modulus below 2^256 with its Montgomery constants (R = 2^256).
pub struct Modulus {
    pub m: U256,
    /// -m^-1 mod 2^32.
    inv: u32,
    /// R^2 mod m.
    r2: U256,
}

/// The field prime p = 2^256 - 2^32 - 977.
pub const P: Modulus = Modulus {
    m: U256([
        0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff,
    ]),
    inv: 0xd2253531,
    r2: U256([0x000e90a1, 0x000007a2, 0x00000001, 0, 0, 0, 0, 0]),
};

/// The group order n.
pub const N: Modulus = Modulus {
    m: U256([
        0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6, 0xfffffffe, 0xffffffff, 0xffffffff,
        0xffffffff,
    ]),
    inv: 0x5588b13f,
    r2: U256([
        0x67d7d140, 0x896cf214, 0x0e7cf878, 0x741496c2, 0x5bcd07c6, 0xe697f5e4, 0x81c69bc5,
        0x9d671cd5,
    ]),
};

impl Modulus {
    /// `a mod m` for any 256-bit `a`: both moduli exceed 2^255, so one subtraction does.
    pub fn reduce(&self, a: &U256) -> U256 {
        let (d, borrow) = a.sub(&self.m);
        if borrow {
            *a
        } else {
            d
        }
    }

    /// Montgomery product a * b * R^-1 mod m, for a, b < m (CIOS).
    #[allow(clippy::needless_range_loop)]
    fn mont_mul(&self, a: &U256, b: &U256) -> U256 {
        let m = &self.m.0;
        let mut t = [0u32; 10];
        for i in 0..8 {
            let mut carry = 0u64;
            for j in 0..8 {
                let s = t[j] as u64 + a.0[j] as u64 * b.0[i] as u64 + carry;
                t[j] = s as u32;
                carry = s >> 32;
            }
            let s = t[8] as u64 + carry;
            t[8] = s as u32;
            t[9] = (s >> 32) as u32;

            let u = t[0].wrapping_mul(self.inv);
            let s = t[0] as u64 + u as u64 * m[0] as u64;
            let mut carry = s >> 32;
            for j in 1..8 {
                let s = t[j] as u64 + u as u64 * m[j] as u64 + carry;
                t[j - 1] = s as u32;
                carry = s >> 32;
            }
            let s = t[8] as u64 + carry;
            t[7] = s as u32;
            t[8] = t[9] + (s >> 32) as u32;
        }
        let mut out = U256([0; 8]);
        out.0.copy_from_slice(&t[..8]);
        if t[8] != 0 || !out.lt(&self.m) {
            out = out.sub(&self.m).0;
        }
        out
    }

    /// a * b mod m, for a, b < m.
    pub fn mul(&self, a: &U256, b: &U256) -> U256 {
        self.mont_mul(&self.mont_mul(a, &self.r2), b)
    }

    /// a + b mod m, for a, b < m.
    pub fn add(&self, a: &U256, b: &U256) -> U256 {
        let (s, carry) = a.add(b);
        if carry || !s.lt(&self.m) {
            s.sub(&self.m).0
        } else {
            s
        }
    }

    /// a^e mod m, for a < m.
    pub fn pow(&self, a: &U256, e: &U256) -> U256 {
        let am = self.mont_mul(a, &self.r2);
        let mut acc = self.mont_mul(&U256::ONE, &self.r2);
        for i in (0..256).rev() {
            acc = self.mont_mul(&acc, &acc);
            if e.bit(i) {
                acc = self.mont_mul(&acc, &am);
            }
        }
        self.mont_mul(&acc, &U256::ONE)
    }

    /// a^-1 mod m for a prime m and a != 0 (Fermat).
    pub fn inv(&self, a: &U256) -> U256 {
        let e = self.m.sub(&U256([2, 0, 0, 0, 0, 0, 0, 0])).0;
        self.pow(a, &e)
    }
}

/// (p + 1) / 4: p ≡ 3 (mod 4), so y = (x³ + 7)^((p+1)/4) is a square root when one exists.
const SQRT_EXP: U256 = U256([
    0xbfffff0c, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff,
]);

/// The curve point with x-coordinate `x` and the given y parity, if there is one.
/// Returns y.
pub fn lift_x(x: &U256, odd: bool) -> Option<U256> {
    if x.is_zero() || !x.lt(&P.m) {
        return None;
    }
    let x3 = P.mul(&P.mul(x, x), x);
    let y2 = P.add(&x3, &U256([7, 0, 0, 0, 0, 0, 0, 0]));
    let y = P.pow(&y2, &SQRT_EXP);
    if P.mul(&y, &y) != y2 {
        return None;
    }
    Some(if y.is_odd() == odd || y.is_zero() {
        y
    } else {
        P.m.sub(&y).0
    })
}

/// Whether `x` is the x-coordinate of a secp256k1 point.
pub fn on_curve_x(x: &U256) -> bool {
    lift_x(x, false).is_some()
}

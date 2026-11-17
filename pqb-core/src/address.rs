//! Bitcoin mainnet address encoding: Base58Check and Bech32/Bech32m (BIP-173, BIP-350).

use crate::error::{Error, Result};
use crate::hash::{sha256d, Hashes};
use crate::script::{classify, Standard};

/// Longest address produced here: a 32-byte witness program is 62 characters.
pub const ADDRESS_MAX: usize = 64;

/// An address held in a fixed buffer.
#[derive(Clone, Copy)]
pub struct Address {
    len: u8,
    buf: [u8; ADDRESS_MAX],
}

impl Address {
    fn empty() -> Self {
        Address {
            len: 0,
            buf: [0; ADDRESS_MAX],
        }
    }

    fn push(&mut self, c: u8) {
        self.buf[self.len as usize] = c;
        self.len += 1;
    }

    pub fn as_str(&self) -> &str {
        // Only ASCII alphabet characters are ever pushed.
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The mainnet address of a standard output script.
pub fn from_script<H: Hashes>(script: &[u8]) -> Result<Address> {
    match classify(script).ok_or(Error::UnsupportedOutput)? {
        Standard::P2pkh(h) => Ok(base58check::<H>(0x00, h)),
        Standard::P2sh(h) => Ok(base58check::<H>(0x05, h)),
        Standard::P2wpkh(p) => Ok(segwit(0, p)),
        Standard::P2wsh(p) => Ok(segwit(0, p)),
        Standard::P2tr(p) => Ok(segwit(1, p)),
    }
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58check<H: Hashes>(version: u8, payload: &[u8; 20]) -> Address {
    let mut data = [0u8; 25];
    data[0] = version;
    data[1..21].copy_from_slice(payload);
    let check = sha256d::<H>(&data[..21]);
    data[21..].copy_from_slice(&check[..4]);

    // Repeated division of the big-endian number by 58.
    let mut digits = [0u8; 40];
    let mut ndigits = 0;
    let mut num = data;
    let mut start = num.iter().position(|&b| b != 0).unwrap_or(num.len());
    let zeros = start;
    while start < num.len() {
        let mut rem = 0u32;
        for b in num[start..].iter_mut() {
            let acc = (rem << 8) | *b as u32;
            *b = (acc / 58) as u8;
            rem = acc % 58;
        }
        digits[ndigits] = BASE58[rem as usize];
        ndigits += 1;
        while start < num.len() && num[start] == 0 {
            start += 1;
        }
    }
    let mut out = Address::empty();
    for _ in 0..zeros {
        out.push(b'1');
    }
    for i in (0..ndigits).rev() {
        out.push(digits[i]);
    }
    out
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod_step(chk: u32, v: u8) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let top = chk >> 25;
    let mut chk = ((chk & 0x1ff_ffff) << 5) ^ v as u32;
    for (i, g) in GEN.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            chk ^= g;
        }
    }
    chk
}

fn segwit(version: u8, program: &[u8]) -> Address {
    const HRP: &[u8] = b"bc";
    // 5-bit groups: the witness version, then the program regrouped.
    let mut data = [0u8; 1 + 52];
    let mut n = 0;
    data[n] = version;
    n += 1;
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in program {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data[n] = ((acc >> bits) & 31) as u8;
            n += 1;
        }
    }
    if bits > 0 {
        data[n] = ((acc << (5 - bits)) & 31) as u8;
        n += 1;
    }

    let mut chk = 1u32;
    for &c in HRP {
        chk = polymod_step(chk, c >> 5);
    }
    chk = polymod_step(chk, 0);
    for &c in HRP {
        chk = polymod_step(chk, c & 31);
    }
    for &d in &data[..n] {
        chk = polymod_step(chk, d);
    }
    for _ in 0..6 {
        chk = polymod_step(chk, 0);
    }
    chk ^= if version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };

    let mut out = Address::empty();
    for &c in HRP {
        out.push(c);
    }
    out.push(b'1');
    for &d in &data[..n] {
        out.push(CHARSET[d as usize]);
    }
    for i in 0..6 {
        out.push(CHARSET[((chk >> (5 * (5 - i))) & 31) as usize]);
    }
    out
}

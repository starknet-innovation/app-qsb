//! DER ECDSA signatures, normalised to low S (BIP-62/BIP-146 standardness).

use crate::error::{Error, Result};

/// The secp256k1 group order.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// floor(N / 2).
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// A DER signature of at most 72 bytes.
#[derive(Clone, Copy, Debug)]
pub struct DerSignature {
    len: u8,
    buf: [u8; 72],
}

impl DerSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

/// Parse one DER INTEGER at `pos` into a 32-byte big-endian value.
fn integer(sig: &[u8], pos: usize) -> Result<([u8; 32], usize)> {
    if sig.get(pos) != Some(&0x02) {
        return Err(Error::BadSignature);
    }
    let len = *sig.get(pos + 1).ok_or(Error::BadSignature)? as usize;
    let body = sig.get(pos + 2..pos + 2 + len).ok_or(Error::BadSignature)?;
    let start = body
        .iter()
        .position(|&b| b != 0)
        .ok_or(Error::BadSignature)?;
    let digits = &body[start..];
    if digits.len() > 32 {
        return Err(Error::BadSignature);
    }
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(digits);
    Ok((out, pos + 2 + len))
}

fn push_integer(out: &mut DerSignature, v: &[u8; 32]) {
    let start = v.iter().position(|&b| b != 0).unwrap_or(31);
    let pad = v[start] & 0x80 != 0;
    let len = 32 - start + pad as usize;
    let mut i = out.len as usize;
    out.buf[i] = 0x02;
    out.buf[i + 1] = len as u8;
    i += 2;
    if pad {
        out.buf[i] = 0;
        i += 1;
    }
    out.buf[i..i + 32 - start].copy_from_slice(&v[start..]);
    out.len = (i + 32 - start) as u8;
}

/// Re-encode `sig` minimally with S replaced by N - S when S > N/2.
pub fn normalize_low_s(sig: &[u8]) -> Result<DerSignature> {
    if sig.len() < 8 || sig[0] != 0x30 || sig[1] as usize + 2 > sig.len() {
        return Err(Error::BadSignature);
    }
    let (r, next) = integer(sig, 2)?;
    let (mut s, end) = integer(sig, next)?;
    if end != sig[1] as usize + 2 || r >= N || s >= N {
        return Err(Error::BadSignature);
    }
    if s > HALF_N {
        // s = N - s, big-endian subtraction.
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = N[i] as i16 - s[i] as i16 - borrow;
            borrow = (d < 0) as i16;
            s[i] = (d + 256 * borrow) as u8;
        }
    }
    let mut out = DerSignature {
        len: 2,
        buf: [0; 72],
    };
    push_integer(&mut out, &r);
    push_integer(&mut out, &s);
    out.buf[0] = 0x30;
    out.buf[1] = out.len - 2;
    Ok(out)
}

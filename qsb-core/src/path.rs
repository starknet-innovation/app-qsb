//! The BIP-32 paths this app derives.
//!
//! QSB's wallet is one P2WPKH or nested SegWit (P2SH-P2WPKH) address. Only the
//! standard BIP-84 and BIP-49 mainnet paths are accepted, and the purpose fixes
//! the address type, so a host cannot make the app show or sign for a key under
//! an address type its path doesn't belong to:
//!
//! - `m/84'/0'/account'/change/index` → P2WPKH (`bc1q…`)
//! - `m/49'/0'/account'/change/index` → P2SH-P2WPKH (`3…`)
//!
//! with `account ≤ 100'`, `change ∈ {0, 1}` and `index ≤ 50000`, the limits the
//! Ledger Bitcoin app treats as standard.

use crate::error::{Error, Result};

pub const HARDENED: u32 = 0x8000_0000;
pub const PATH_LEN: usize = 5;
const MAX_ACCOUNT: u32 = 100;
const MAX_INDEX: u32 = 50_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressType {
    /// BIP-84 native SegWit.
    P2wpkh,
    /// BIP-49 nested SegWit.
    P2shP2wpkh,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Path {
    pub elements: [u32; PATH_LEN],
}

impl Path {
    pub fn address_type(&self) -> AddressType {
        if self.elements[0] == 84 | HARDENED {
            AddressType::P2wpkh
        } else {
            AddressType::P2shP2wpkh
        }
    }
}

/// Parse `len || element[len]` (big-endian u32s) from the front of `data`.
/// Returns the path and the bytes after it.
pub fn parse(data: &[u8]) -> Result<(Path, &[u8])> {
    let (&len, rest) = data.split_first().ok_or(Error::BadLength)?;
    if len as usize != PATH_LEN {
        return Err(Error::BadPath);
    }
    if rest.len() < 4 * PATH_LEN {
        return Err(Error::BadLength);
    }
    let mut elements = [0u32; PATH_LEN];
    for (i, e) in elements.iter_mut().enumerate() {
        *e = u32::from_be_bytes(
            rest[4 * i..4 * i + 4]
                .try_into()
                .map_err(|_| Error::BadLength)?,
        );
    }
    let [purpose, coin, account, change, index] = elements;
    let standard = (purpose == 84 | HARDENED || purpose == 49 | HARDENED)
        && coin == HARDENED
        && account & HARDENED != 0
        && account & !HARDENED <= MAX_ACCOUNT
        && change <= 1
        && index <= MAX_INDEX;
    if !standard {
        return Err(Error::BadPath);
    }
    Ok((Path { elements }, &rest[4 * PATH_LEN..]))
}

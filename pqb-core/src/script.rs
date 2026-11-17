//! Standard output scripts the app recognises.

/// Longest script kept verbatim. Every destination the app can show as an
/// address (P2PKH 25, P2SH 23, P2WPKH 22, P2WSH 34, P2TR 34 bytes) fits.
pub const SMALL_SCRIPT_MAX: usize = 34;

/// A short output script held in full.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SmallScript {
    len: u8,
    data: [u8; SMALL_SCRIPT_MAX],
}

impl SmallScript {
    pub fn new(script: &[u8]) -> Option<Self> {
        if script.len() > SMALL_SCRIPT_MAX {
            return None;
        }
        let mut data = [0u8; SMALL_SCRIPT_MAX];
        data[..script.len()].copy_from_slice(script);
        Some(SmallScript {
            len: script.len() as u8,
            data,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

/// The script types the app can render as a mainnet address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Standard<'a> {
    P2pkh(&'a [u8; 20]),
    P2sh(&'a [u8; 20]),
    P2wpkh(&'a [u8; 20]),
    P2wsh(&'a [u8; 32]),
    P2tr(&'a [u8; 32]),
}

pub fn classify(s: &[u8]) -> Option<Standard<'_>> {
    match s.len() {
        25 if s[..3] == [0x76, 0xa9, 0x14] && s[23..] == [0x88, 0xac] => {
            Some(Standard::P2pkh(s[3..23].try_into().ok()?))
        }
        23 if s[..2] == [0xa9, 0x14] && s[22] == 0x87 => {
            Some(Standard::P2sh(s[2..22].try_into().ok()?))
        }
        22 if s[..2] == [0x00, 0x14] => Some(Standard::P2wpkh(s[2..22].try_into().ok()?)),
        34 if s[..2] == [0x00, 0x20] => Some(Standard::P2wsh(s[2..34].try_into().ok()?)),
        34 if s[..2] == [0x51, 0x20] => Some(Standard::P2tr(s[2..34].try_into().ok()?)),
        _ => None,
    }
}

pub fn p2wpkh(pkh: &[u8; 20]) -> [u8; 22] {
    let mut s = [0u8; 22];
    s[0] = 0x00;
    s[1] = 0x14;
    s[2..].copy_from_slice(pkh);
    s
}

pub fn p2sh(script_hash: &[u8; 20]) -> [u8; 23] {
    let mut s = [0u8; 23];
    s[0] = 0xa9;
    s[1] = 0x14;
    s[2..22].copy_from_slice(script_hash);
    s[22] = 0x87;
    s
}

/// The BIP-143 scriptCode for a P2WPKH key hash, with its length prefix.
pub fn p2wpkh_script_code(pkh: &[u8; 20]) -> [u8; 26] {
    let mut s = [0u8; 26];
    s[..4].copy_from_slice(&[0x19, 0x76, 0xa9, 0x14]);
    s[4..24].copy_from_slice(pkh);
    s[24] = 0x88;
    s[25] = 0xac;
    s
}

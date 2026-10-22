//! QSB HORS secrets derived from the device seed (spec "QSB HORS Ledger App",
//! version `QSB-HORS-v1`).
//!
//! A QSB Config A vault commits to 2 rounds × 150 one-time secrets of 20 bytes
//! (qsb-app `public/qsb/bitcoin_tx.py`). Instead of drawing them from
//! `os.urandom`, the app derives each one from a SLIP-0021 key, so a vault can be
//! rebuilt from the seed and an unrevealed secret never leaves the device:
//!
//! ```text
//! K          = SLIP21(["QSB-HORS"])                        (32 bytes, from the OS)
//! s[v][r][i] = HMAC-SHA256(K, "QSB-HORS-v1" ‖ 0x00 ‖ net ‖ v ‖ r ‖ i)[0..20)
//! c[v][r][i] = RIPEMD160(SHA256(s))                         (qsb-app's commitment)
//! R[v]       = SHA256("QSB-HORS-v1/root" ‖ c[r=0][0..150) ‖ c[r=1][0..150))
//! ```
//!
//! `net` is one byte (0x00 mainnet, 0x01 test networks), `v` the vault index
//! (u32 big-endian, below 2^31), `r` the round (one byte) and `i` the index
//! (u16 big-endian). Nothing here touches a secp256k1 key.
//!
//! A withdrawal reveals the first 8 indices of round 1's subset and the first 7
//! of round 2's: 15 preimages, returned in the order the host sends the indices,
//! since the scriptSig order must match the GPU search's subset.

use crate::address;
use crate::amount::MAX_MONEY;
use crate::error::{Error, Result};
use crate::hash::{hash160, Hashes, Sha256};
use crate::script::SmallScript;

/// Secrets per round.
pub const N: usize = 150;
pub const ROUNDS: usize = 2;
/// Preimages a withdrawal reveals per round (Config A's t1s and t2s).
pub const SIGNED: [usize; ROUNDS] = [8, 7];
pub const REVEALED: usize = 15;
pub const SECRET_LEN: usize = 20;
/// Commitments or preimages per response: 12 × 20 bytes stays under 256.
pub const CHUNK: usize = 12;
/// The SLIP-0021 label the app derives `K` under.
pub const SLIP21_LABEL: &[u8] = b"QSB-HORS";
pub const SPEC_VERSION: &[u8] = b"QSB-HORS-v1";
pub const NET_MAINNET: u8 = 0x00;
pub const NET_TEST: u8 = 0x01;
pub const MAX_VAULT_INDEX: u32 = 0x7fff_ffff;

const ROOT_TAG: &[u8] = b"QSB-HORS-v1/root";
const REVEAL_TAG: &[u8] = b"QSB-HORS-v1/reveal";
const GUARD_TAG: &[u8] = b"QSB-HORS-v1/guard";

/// Overwrite secret material. `black_box` keeps the stores from being optimised
/// away; this crate has no `unsafe`, so the device crate's buffers use volatile
/// writes instead.
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    core::hint::black_box(buf);
}

/// One vault: the network byte and the vault index.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vault {
    pub net: u8,
    pub index: u32,
}

/// `net (1) || v (4)`, checked against the network this build serves.
pub fn parse_vault(data: &[u8], build_net: u8) -> Result<Vault> {
    let [net, a, b, c, d] = <[u8; 5]>::try_from(data).map_err(|_| Error::BadData)?;
    vault(net, u32::from_be_bytes([a, b, c, d]), build_net)
}

fn vault(net: u8, index: u32, build_net: u8) -> Result<Vault> {
    if net != NET_MAINNET && net != NET_TEST {
        return Err(Error::BadData);
    }
    if net != build_net {
        return Err(Error::WrongNetwork);
    }
    if index > MAX_VAULT_INDEX {
        return Err(Error::BadData);
    }
    Ok(Vault { net, index })
}

/// The secret `s[v][round][index]` under the SLIP-0021 key `k`.
pub fn secret<H: Hashes>(k: &[u8; 32], vault: Vault, round: u8, index: u16) -> [u8; SECRET_LEN] {
    let mut message = [0u8; 20];
    message[..11].copy_from_slice(SPEC_VERSION);
    message[11] = 0x00;
    message[12] = vault.net;
    message[13..17].copy_from_slice(&vault.index.to_be_bytes());
    message[17] = round;
    message[18..20].copy_from_slice(&index.to_be_bytes());
    let mut mac = H::hmac_sha256(k, &message);
    let mut s = [0u8; SECRET_LEN];
    s.copy_from_slice(&mac[..SECRET_LEN]);
    wipe(&mut mac);
    s
}

/// The reveal guard's tag for the wallet `K` belongs to: `HMAC(K, "QSB-HORS-v1/guard")[0..8)`.
/// It tells this seed's records from another's (`guard`) and says nothing about `K`.
pub fn wallet_tag<H: Hashes>(k: &[u8; 32]) -> [u8; 8] {
    let mut mac = H::hmac_sha256(k, GUARD_TAG);
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&mac[..8]);
    wipe(&mut mac);
    tag
}

/// The public commitment to `s[v][round][index]`: HASH160, as qsb-app commits.
pub fn commitment<H: Hashes>(k: &[u8; 32], vault: Vault, round: u8, index: u16) -> [u8; 20] {
    let mut s = secret::<H>(k, vault, round, index);
    let c = hash160::<H>(&s);
    wipe(&mut s);
    c
}

/// The commitment root `R[v]` over all 300 commitments.
pub fn commitment_root<H: Hashes>(k: &[u8; 32], vault: Vault) -> [u8; 32] {
    let mut h = H::Sha256::new();
    h.update(ROOT_TAG);
    for round in 0..ROUNDS as u8 {
        for index in 0..N as u16 {
            h.update(&commitment::<H>(k, vault, round, index));
        }
    }
    h.finalize()
}

/// The root's first 8 bytes as four groups of four hex digits, e.g. "5f7a 0bc1 bf0f a932".
pub fn fingerprint(root: &[u8; 32]) -> [u8; 19] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [b' '; 19];
    for (i, b) in root[..8].iter().enumerate() {
        let at = i * 2 + i / 2;
        out[at] = HEX[(b >> 4) as usize];
        out[at + 1] = HEX[(b & 15) as usize];
    }
    out
}

/// GET_COMMITMENTS: `net (1) || v (4) || start (2) || count (1)`, round in P1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommitmentsRequest {
    pub vault: Vault,
    pub round: u8,
    pub start: u16,
    pub count: u8,
}

pub fn parse_commitments(round: u8, data: &[u8], build_net: u8) -> Result<CommitmentsRequest> {
    if data.len() != 8 || round as usize >= ROUNDS {
        return Err(Error::BadData);
    }
    let vault = parse_vault(&data[..5], build_net)?;
    let start = u16::from_be_bytes([data[5], data[6]]);
    let count = data[7];
    if count == 0 || count as usize > CHUNK || start as usize + count as usize > N {
        return Err(Error::BadData);
    }
    Ok(CommitmentsRequest {
        vault,
        round,
        start,
        count,
    })
}

/// REVEAL_PREPARE: what the host asks to reveal, and what it says the withdrawal does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RevealRequest {
    pub vault: Vault,
    pub round1: [u16; 8],
    pub round2: [u16; 7],
    /// SHA-256 of the unsigned withdrawal, as the host serialises it.
    pub binding: [u8; 32],
    /// Host-reported: the device cannot check these in v1.
    pub amount: u64,
    pub destination: SmallScript,
}

impl RevealRequest {
    /// The 15 (round, index) pairs in reveal order: round 1's, then round 2's.
    pub fn revealed(&self) -> [(u8, u16); REVEALED] {
        let mut out = [(0u8, 0u16); REVEALED];
        for (slot, &i) in out.iter_mut().zip(self.round1.iter()) {
            *slot = (0, i);
        }
        for (slot, &i) in out[8..].iter_mut().zip(self.round2.iter()) {
            *slot = (1, i);
        }
        out
    }

    /// SHA256("QSB-HORS-v1/reveal" ‖ round 1 indices ‖ round 2 indices ‖ binding).
    pub fn reveal_hash<H: Hashes>(&self) -> [u8; 32] {
        let mut h = H::Sha256::new();
        h.update(REVEAL_TAG);
        for i in self.round1.iter().chain(self.round2.iter()) {
            h.update(&i.to_be_bytes());
        }
        h.update(&self.binding);
        h.finalize()
    }
}

fn indices<const T: usize>(data: &[u8]) -> Result<[u16; T]> {
    let mut out = [0u16; T];
    for k in 0..T {
        let i = u16::from_be_bytes([data[2 * k], data[2 * k + 1]]);
        if i as usize >= N || out[..k].contains(&i) {
            return Err(Error::BadData);
        }
        out[k] = i;
    }
    Ok(out)
}

/// `net (1) || v (4) || round 1 indices (8 × u16) || round 2 indices (7 × u16) ||
/// binding (32) || amount (8) || destination length (1) || destination (≤ 34)`.
///
/// Checked before any screen: indices below 150 and distinct within a round, the
/// network this build serves, and a destination the app can show as an address.
pub fn parse_reveal<H: Hashes>(data: &[u8], build_net: u8) -> Result<RevealRequest> {
    const FIXED: usize = 5 + 16 + 14 + 32 + 8 + 1;
    if data.len() < FIXED || data.len() != FIXED + data[FIXED - 1] as usize {
        return Err(Error::BadData);
    }
    let vault = parse_vault(&data[..5], build_net)?;
    let round1 = indices::<8>(&data[5..21])?;
    let round2 = indices::<7>(&data[21..35])?;
    let binding: [u8; 32] = data[35..67].try_into().map_err(|_| Error::BadData)?;
    let amount = u64::from_be_bytes(data[67..75].try_into().map_err(|_| Error::BadData)?);
    if amount > MAX_MONEY {
        return Err(Error::BadData);
    }
    let destination = SmallScript::new(&data[FIXED..]).ok_or(Error::BadData)?;
    address::from_script::<H>(destination.as_bytes()).map_err(|_| Error::BadData)?;
    Ok(RevealRequest {
        vault,
        round1,
        round2,
        binding,
        amount,
        destination,
    })
}

/// REVEAL_READ chunk `c`: preimages 1–12 (chunk 0) or 13–15 (chunk 1).
pub fn chunk_range(chunk: u8) -> Option<core::ops::Range<usize>> {
    match chunk {
        0 => Some(0..CHUNK),
        1 => Some(CHUNK..REVEALED),
        _ => None,
    }
}

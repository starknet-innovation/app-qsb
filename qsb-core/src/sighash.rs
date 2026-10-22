//! BIP-143 signature hashes for the wallet's P2WPKH key.

use crate::hash::{sha256, Hashes, Sha256};
use crate::script::p2wpkh_script_code;

pub const SIGHASH_ALL: u8 = 0x01;

/// The parts of a BIP-143 preimage shared by every input.
#[derive(Clone, Copy)]
pub struct Bip143Common {
    pub version: u32,
    pub hash_prevouts: [u8; 32],
    pub hash_sequence: [u8; 32],
    pub hash_outputs: [u8; 32],
    pub locktime: u32,
}

/// SIGHASH_ALL digest for an input spending `pkh`'s P2WPKH (native or nested) output.
pub fn p2wpkh_sighash_all<H: Hashes>(
    common: &Bip143Common,
    outpoint: &[u8; 36],
    pkh: &[u8; 20],
    amount: u64,
    sequence: u32,
) -> [u8; 32] {
    let mut h = H::Sha256::new();
    h.update(&common.version.to_le_bytes());
    h.update(&common.hash_prevouts);
    h.update(&common.hash_sequence);
    h.update(outpoint);
    h.update(&p2wpkh_script_code(pkh));
    h.update(&amount.to_le_bytes());
    h.update(&sequence.to_le_bytes());
    h.update(&common.hash_outputs);
    h.update(&common.locktime.to_le_bytes());
    h.update(&(SIGHASH_ALL as u32).to_le_bytes());
    sha256::<H>(&h.finalize())
}

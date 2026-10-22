//! BIP-322 message signatures for the wallet's P2WPKH and P2SH-P2WPKH addresses.
//!
//! The device signs input 0 of the virtual `to_sign` transaction. For both address
//! types that is a BIP-143 SIGHASH_ALL over the key's P2PKH scriptCode with amount 0;
//! only the `to_spend` output script differs. The host encodes the returned
//! signature and the public key as the witness ("simple" signature), which
//! verifiers accept for nested SegWit too.

use crate::hash::{sha256, sha256d, Hashes, Sha256};
use crate::sighash::{p2wpkh_sighash_all, Bip143Common};
use crate::varint;

const TAG: &[u8] = b"BIP0322-signed-message";

pub fn message_hash<H: Hashes>(message: &[u8]) -> [u8; 32] {
    let tag = sha256::<H>(TAG);
    let mut h = H::Sha256::new();
    h.update(&tag);
    h.update(&tag);
    h.update(message);
    h.finalize()
}

/// The txid, in internal byte order, of the virtual `to_spend` transaction.
pub fn to_spend_txid<H: Hashes>(message: &[u8], script_pubkey: &[u8]) -> [u8; 32] {
    let mut h = H::Sha256::new();
    h.update(&0u32.to_le_bytes()); // version
    h.update(&[1]); // one input
    h.update(&[0u8; 32]);
    h.update(&0xffff_ffffu32.to_le_bytes());
    h.update(&[34, 0x00, 0x20]); // scriptSig: OP_0 PUSH32 message_hash
    h.update(&message_hash::<H>(message));
    h.update(&0u32.to_le_bytes()); // sequence
    h.update(&[1]); // one output
    h.update(&0u64.to_le_bytes());
    let (len, n) = varint::encode(script_pubkey.len() as u64);
    h.update(&len[..n]);
    h.update(script_pubkey);
    h.update(&0u32.to_le_bytes()); // locktime
    sha256::<H>(&h.finalize())
}

/// The digest the wallet key signs for `message`.
pub fn sighash<H: Hashes>(message: &[u8], script_pubkey: &[u8], pkh: &[u8; 20]) -> [u8; 32] {
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&to_spend_txid::<H>(message, script_pubkey));
    let common = Bip143Common {
        version: 0,
        hash_prevouts: sha256d::<H>(&outpoint),
        hash_sequence: sha256d::<H>(&0u32.to_le_bytes()),
        // One output: value 0, script OP_RETURN.
        hash_outputs: sha256d::<H>(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0x6a]),
        locktime: 0,
    };
    p2wpkh_sighash_all::<H>(&common, &outpoint, pkh, 0, 0)
}

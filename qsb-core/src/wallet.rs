//! The wallet key: one compressed public key and its P2WPKH or P2SH-P2WPKH address.

use crate::address::{self, Address};
use crate::hash::{hash160, Hashes};
use crate::path::AddressType;
use crate::script::{p2sh, p2wpkh, SmallScript};

#[derive(Clone, Copy)]
pub struct Wallet {
    pub pubkey: [u8; 33],
    pub pkh: [u8; 20],
    pub address_type: AddressType,
    script: SmallScript,
}

impl Wallet {
    pub fn new<H: Hashes>(pubkey: [u8; 33], address_type: AddressType) -> Self {
        let pkh = hash160::<H>(&pubkey);
        let witness = p2wpkh(&pkh);
        let script = match address_type {
            AddressType::P2wpkh => SmallScript::new(&witness),
            AddressType::P2shP2wpkh => SmallScript::new(&p2sh(&hash160::<H>(&witness))),
        }
        .expect("standard scripts fit");
        Wallet {
            pubkey,
            pkh,
            address_type,
            script,
        }
    }

    /// The output script of the wallet's address.
    pub fn script(&self) -> &[u8] {
        self.script.as_bytes()
    }

    pub fn address<H: Hashes>(&self) -> Address {
        // The wallet script is always a standard type.
        address::from_script::<H>(self.script()).expect("wallet script is standard")
    }
}

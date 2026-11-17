//! Device-independent logic of the PQB Ledger app.
//!
//! Everything that decides what the user sees, what gets signed and which
//! secrets may be released lives here, so it can be tested on a host: the
//! `PQB-v1` derivation profile, the vault script template, streaming transaction
//! parsing, the persistent allocation and disclosure records, and the deposit
//! and withdrawal state machines. The app crate supplies hashing, key
//! derivation, curve arithmetic, signing, NVM, APDU transport and the screens.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod address;
pub mod amount;
pub mod deposit;
pub mod der;
pub mod error;
pub mod hash;
pub mod pqb;
pub mod record;
pub mod script;
pub mod sha1;
pub mod sighash;
pub mod template;
pub mod tx;
pub mod u256;
pub mod varint;
pub mod withdraw;

#[cfg(test)]
mod tests;

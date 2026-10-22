//! Device-independent logic of the QSB Ledger app.
//!
//! Everything that decides what the user sees, what gets signed and which HORS
//! secrets may be revealed lives here, so it can be tested on a host. The app crate supplies hashing, key derivation,
//! signing, APDU transport and the screens.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod address;
pub mod amount;
pub mod bip322;
pub mod der;
pub mod error;
pub mod guard;
pub mod hash;
pub mod hors;
pub mod path;
pub mod script;
pub mod session;
pub mod sighash;
pub mod signin;
pub mod tx;
pub mod varint;
pub mod vault;
pub mod wallet;

#[cfg(test)]
mod tests;

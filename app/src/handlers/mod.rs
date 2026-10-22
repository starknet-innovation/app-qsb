pub mod hors;
pub mod sign_in;
pub mod sign_tx;
pub mod wallet;

use alloc::boxed::Box;

use qsb_core::session::{MessageCollector, SignTx};

use crate::crypto::DeviceHashes;

/// The multi-APDU operation in progress, if any. Any error ends it.
pub enum Session {
    Idle,
    Tx(Box<SignTx<DeviceHashes>>),
    SignIn(Box<MessageCollector>),
}

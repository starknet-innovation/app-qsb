//! The PQB records (`pqb_core::record`) in the app's NVM.
//!
//! Each of the 33 slots is an `AtomicStorage`: two copies, switched only once
//! the new one is fully written, so a power cut leaves either the old slot or
//! the new one, never a mix. `update` returns once the write is done. The slots
//! live in `.nvm_data`, which an app update or reinstall erases: that ends the
//! continuity the records vouch for (docs/apdu.md, "Conformance").

use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use ledger_device_sdk::NVMData;
use pqb_core::record::{Slot, Store, SLOTS, SLOT_LEN};

const EMPTY: Slot = [0u8; SLOT_LEN];

#[link_section = ".nvm_data"]
static mut STORE: [NVMData<AtomicStorage<Slot>>; SLOTS] =
    [const { NVMData::new(AtomicStorage::new(&EMPTY)) }; SLOTS];

fn slot(i: usize) -> &'static mut AtomicStorage<Slot> {
    let data = &raw mut STORE;
    // SAFETY: the app is single-threaded and only this module touches STORE; no
    // reference from `read` is used across a `write`.
    unsafe { (*data)[i].get_mut() }
}

/// Make every slot hold a value, so reads never meet a never-written storage
/// (Speculos loads `.nvm_data` zeroed). Writes only the first time.
pub fn init() {
    for i in 0..SLOTS {
        slot(i).get_or_init(&EMPTY);
    }
}

pub struct Nvm;

impl Store for Nvm {
    fn read(&self, i: usize) -> &Slot {
        slot(i).get_or_init(&EMPTY)
    }

    fn write(&mut self, i: usize, data: &Slot) {
        slot(i).update(data);
    }
}

//! The reveal guard's table (`qsb_core::guard`) in the app's NVM.
//!
//! `AtomicStorage` keeps two copies and switches between them only once the new
//! one is fully written, so a power cut leaves either the old table or the new
//! one, never a mix. `update` returns once the write is done. The table lives in
//! `.nvm_data`, which an app update or reinstall erases.

use ledger_device_sdk::nvm::{AtomicStorage, SingleStorage};
use ledger_device_sdk::NVMData;
use qsb_core::guard::TABLE_LEN;

#[link_section = ".nvm_data"]
static mut GUARD: NVMData<AtomicStorage<[u8; TABLE_LEN]>> =
    NVMData::new(AtomicStorage::new(&[0u8; TABLE_LEN]));

fn storage() -> &'static mut AtomicStorage<[u8; TABLE_LEN]> {
    let data = &raw mut GUARD;
    // SAFETY: the app is single-threaded and only this module touches GUARD; no
    // reference from `table` is used across a `write`.
    unsafe { (*data).get_mut() }
}

/// The current table. An all-zero table is empty.
pub fn table() -> &'static [u8; TABLE_LEN] {
    storage().get_or_init(&[0u8; TABLE_LEN])
}

/// Replace the table, durably, before returning.
pub fn write(table: &[u8; TABLE_LEN]) {
    storage().update(table);
}

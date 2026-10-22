//! GET_WALLET_ADDRESS: the wallet's public key and address, optionally shown for verification.

use ledger_device_sdk::io::{Command, CommandResponse};
use qsb_core::path;

use crate::crypto::{self, DeviceHashes};
use crate::{ui, AppSW};

pub fn handle(command: Command<'_>, display: bool) -> Result<CommandResponse<'_>, AppSW> {
    let (path, rest) = path::parse(command.get_data())?;
    if !rest.is_empty() {
        return Err(AppSW::WrongDataLength);
    }
    let wallet = crypto::wallet(&path)?;
    let address = wallet.address::<DeviceHashes>();

    let comm = command.into_comm();
    if display && !ui::verify_address(comm, address.as_str()) {
        return Err(AppSW::Deny);
    }
    let mut response = comm.begin_response();
    response
        .append(&wallet.pubkey)?
        .append(&[address.as_str().len() as u8])?
        .append(address.as_str().as_bytes())?;
    Ok(response)
}

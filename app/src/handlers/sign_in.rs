//! SIGN_IN: BIP-322 signature of a QSB sign-in challenge (docs/apdu.md).

use alloc::boxed::Box;

use ledger_device_sdk::io::{Command, CommandResponse};
use qsb_core::session::MessageCollector;
use qsb_core::sighash::SIGHASH_ALL;
use qsb_core::{bip322, signin};

use super::Session;
use crate::crypto::{self, DeviceHashes};
use crate::{ui, AppSW};

pub fn handle<'a>(
    command: Command<'a>,
    first: bool,
    session: &mut Session,
) -> Result<CommandResponse<'a>, AppSW> {
    let data = command.get_data();
    if first {
        *session = Session::Idle;
        *session = Session::SignIn(Box::new(MessageCollector::start(data)?));
    } else {
        match session {
            Session::SignIn(collector) => collector.push(data)?,
            _ => return Err(AppSW::BadState),
        }
    }
    let collector = match session {
        Session::SignIn(collector) if collector.is_complete() => collector,
        Session::SignIn(_) => return Ok(command.into_response()),
        _ => return Err(AppSW::BadState),
    };

    let wallet = crypto::wallet(&collector.path)?;
    let address = wallet.address::<DeviceHashes>();
    let message = collector.message();
    let challenge = signin::parse(message, address.as_str())?;
    let comm = command.into_comm();
    if !ui::review_sign_in(comm, &challenge, address.as_str()) {
        return Err(AppSW::Deny);
    }
    let digest = bip322::sighash::<DeviceHashes>(message, wallet.script(), &wallet.pkh);
    let signature = crypto::sign(&collector.path, &digest)?;
    *session = Session::Idle;
    let mut response = comm.begin_response();
    response
        .append(signature.as_bytes())?
        .append(&[SIGHASH_ALL])?;
    Ok(response)
}

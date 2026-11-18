//! SIGN_IN: BIP-322 signature of a QSB sign-in challenge with a vault's deposit
//! key (docs/apdu.md).

use alloc::boxed::Box;

use ledger_device_sdk::io::{Command, CommandResponse};
use pqb_core::address;
use pqb_core::hash::hash160;
use pqb_core::pqb::Curve;
use pqb_core::record::{self, Standing};
use pqb_core::script::p2wpkh;
use pqb_core::sighash::SIGHASH_ALL;
use pqb_core::signin::{self, Collector};

use super::Session;
use crate::crypto::{self, DeviceCurve, DeviceHashes};
use crate::storage::Nvm;
use crate::{ui, AppSW};

pub fn handle<'a>(
    command: Command<'a>,
    first: bool,
    session: &mut Session,
) -> Result<CommandResponse<'a>, AppSW> {
    let data = command.get_data();
    if first {
        *session = Session::Idle;
        *session = Session::SignIn(Box::new(Collector::start(data)?));
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
    let v = collector.v;

    // Any vault this seed allocated, whatever its state, and any vault of a
    // seed without history on this device: the owner may need a session to
    // follow a withdrawal. Only an index the device knows it never handed out
    // is refused. Nothing is recorded.
    if matches!(
        record::standing(&Nvm, &crypto::wallet_id()?, v)?,
        Standing::NotAllocated
    ) {
        return Err(AppSW::VaultState);
    }

    let (mut dd, root) = {
        let vault = crypto::vault(v)?;
        (
            vault.deposit_key::<DeviceHashes>(),
            vault.root::<DeviceHashes>(),
        )
    };
    let pkh = hash160::<DeviceHashes>(&DeviceCurve::pubkey(&dd));
    let script = p2wpkh(&pkh);
    let signed = (|| -> Result<_, AppSW> {
        let address = address::from_script::<DeviceHashes>(&script)?;
        let message = collector.message();
        let challenge = signin::parse(message, address.as_str())?;
        let comm = command.into_comm();
        if !ui::review_sign_in(comm, &challenge, v, &root, address.as_str()) {
            return Err(AppSW::Deny);
        }
        let digest = signin::sighash::<DeviceHashes>(message, &script, &pkh);
        Ok((comm, crypto::sign(&dd, &digest)?))
    })();
    crypto::wipe(&mut dd);
    let (comm, signature) = signed?;
    *session = Session::Idle;
    let mut response = comm.begin_response();
    response
        .append(signature.as_bytes())?
        .append(&[SIGHASH_ALL])?;
    Ok(response)
}

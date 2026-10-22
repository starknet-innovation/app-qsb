//! SIGN_TX: stream, review and sign a QSB deposit or withdrawal (docs/apdu.md).

use alloc::boxed::Box;

use ledger_device_sdk::io::{Command, CommandResponse};
use qsb_core::session::{parse_start, SignTx};
use qsb_core::sighash::SIGHASH_ALL;

use super::Session;
use crate::crypto::{self, DeviceHashes};
use crate::{ui, AppSW};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    Start,
    Input,
    PrevTx,
    Outputs,
    Review,
    Sign,
}

impl Step {
    pub fn from_p1(p1: u8) -> Option<Step> {
        Some(match p1 {
            0 => Step::Start,
            1 => Step::Input,
            2 => Step::PrevTx,
            3 => Step::Outputs,
            4 => Step::Review,
            5 => Step::Sign,
            _ => return None,
        })
    }
}

fn tx(session: &mut Session) -> Result<&mut SignTx<DeviceHashes>, AppSW> {
    match session {
        Session::Tx(tx) => Ok(tx),
        _ => Err(AppSW::BadState),
    }
}

pub fn handle<'a>(
    command: Command<'a>,
    step: Step,
    session: &mut Session,
) -> Result<CommandResponse<'a>, AppSW> {
    let data = command.get_data();
    match step {
        Step::Start => {
            *session = Session::Idle;
            let start = parse_start(data)?;
            let wallet = crypto::wallet(&start.path)?;
            *session = Session::Tx(Box::new(SignTx::new(start, wallet)));
        }
        Step::Input => tx(session)?.begin_input(data)?,
        Step::PrevTx => tx(session)?.prev_tx_chunk(data)?,
        Step::Outputs => tx(session)?.outputs_chunk(data)?,
        Step::Review => {
            if !data.is_empty() {
                return Err(AppSW::WrongDataLength);
            }
            let review = tx(session)?.finalize()?;
            let comm = command.into_comm();
            if !ui::review_tx(comm, &review)? {
                return Err(AppSW::Deny);
            }
            tx(session)?.approve()?;
            return Ok(comm.begin_response());
        }
        Step::Sign => {
            let &[index] = data else {
                return Err(AppSW::WrongDataLength);
            };
            let tx = tx(session)?;
            let digest = tx.sighash(index)?;
            let signature = crypto::sign(tx.path(), &digest)?;
            if tx.is_complete() {
                *session = Session::Idle;
            }
            let mut response = command.into_response();
            response
                .append(signature.as_bytes())?
                .append(&[SIGHASH_ALL])?;
            return Ok(response);
        }
    }
    Ok(command.into_response())
}

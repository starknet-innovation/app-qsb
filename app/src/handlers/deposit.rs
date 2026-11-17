//! SIGN_DEPOSIT: stream, review and sign a sweep into a vault or a refund from
//! its deposit address (docs/apdu.md).

use alloc::boxed::Box;

use ledger_device_sdk::io::{Command, CommandResponse};
use pqb_core::deposit::{check_sweep, parse_start, DepositKey, Kind, SignDeposit};
use pqb_core::hash::hash160;
use pqb_core::pqb::Curve;
use pqb_core::record::{self, Record, Standing};
use pqb_core::sighash::SIGHASH_ALL;

use super::Session;
use crate::crypto::{self, DeviceCurve, DeviceHashes};
use crate::storage::Nvm;
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

/// A deposit signing session: the streamed transaction, the vault's root for
/// the review, and its deposit key, wiped when the session ends.
pub struct DepositSession {
    tx: SignDeposit<DeviceHashes>,
    root: [u8; 32],
    key: [u8; 32],
}

impl Drop for DepositSession {
    fn drop(&mut self) {
        crypto::wipe(&mut self.key);
    }
}

impl DepositSession {
    pub fn is_approved(&self) -> bool {
        self.tx.is_approved()
    }
}

fn session(session: &mut Session) -> Result<&mut DepositSession, AppSW> {
    match session {
        Session::Deposit(s) => Ok(s),
        _ => Err(AppSW::BadState),
    }
}

pub fn handle<'a>(
    command: Command<'a>,
    step: Step,
    current: &mut Session,
) -> Result<CommandResponse<'a>, AppSW> {
    let data = command.get_data();
    match step {
        Step::Start => {
            *current = Session::Idle;
            let start = parse_start(data)?;
            let vault = crypto::vault(start.v)?;
            let key = vault.deposit_key::<DeviceHashes>();
            let pubkey = DeviceCurve::pubkey(&key);
            let deposit = DepositKey {
                pkh: hash160::<DeviceHashes>(&pubkey),
                vault_script_hash: vault.script_hash::<DeviceHashes>(),
            };
            *current = Session::Deposit(Box::new(DepositSession {
                tx: SignDeposit::new(start, deposit),
                root: vault.root::<DeviceHashes>(),
                key,
            }));
        }
        Step::Input => session(current)?.tx.begin_input(data)?,
        Step::PrevTx => session(current)?.tx.prev_tx_chunk(data)?,
        Step::Outputs => session(current)?.tx.outputs_chunk(data)?,
        Step::Review => {
            if !data.is_empty() {
                return Err(AppSW::WrongDataLength);
            }
            let s = session(current)?;
            let review = s.tx.finalize()?;
            // A sweep funds the vault: only an allocated, undisclosed vault, once.
            let funded = if review.kind == Kind::Sweep {
                let wallet = crypto::wallet_id()?;
                let r = match record::standing(&Nvm, &wallet, review.v)? {
                    Standing::Recorded(r) => r,
                    _ => return Err(AppSW::VaultState),
                };
                Some(Record {
                    funding: Some(check_sweep(&r, &s.tx)?),
                    ..r
                })
            } else {
                None
            };
            let comm = command.into_comm();
            if !ui::review_deposit(comm, &review, &s.root)? {
                return Err(AppSW::Deny);
            }
            // The funding is recorded before any signature leaves.
            if let Some(r) = funded {
                record::put(&mut Nvm, &r)?;
            }
            s.tx.approve()?;
            return Ok(comm.begin_response());
        }
        Step::Sign => {
            let &[index] = data else {
                return Err(AppSW::WrongDataLength);
            };
            let s = session(current)?;
            let digest = s.tx.sighash(index)?;
            let signature = crypto::sign(&s.key, &digest)?;
            if s.tx.is_complete() {
                *current = Session::Idle;
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

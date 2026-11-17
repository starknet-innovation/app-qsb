//! WITHDRAW and REVEAL_READ: one recorded disclosure of a vault's secrets and
//! co-signature, bound to one transaction (docs/apdu.md).

use alloc::boxed::Box;

use ledger_device_sdk::io::{Command, CommandResponse};
use pqb_core::pqb::{Curve, Vault};
use pqb_core::record::{self, Namespace, NsState, Standing};
use pqb_core::withdraw::{self, Decision, Request, Withdraw};

use super::Session;
use crate::crypto::{self, DeviceCurve, DeviceHashes};
use crate::storage::Nvm;
use crate::{ui, AppSW};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    Start,
    PrevTx,
    Outputs,
    Review,
}

impl Step {
    pub fn from_p1(p1: u8) -> Option<Step> {
        Some(match p1 {
            0 => Step::Start,
            1 => Step::PrevTx,
            2 => Step::Outputs,
            3 => Step::Review,
            _ => return None,
        })
    }
}

pub struct WithdrawSession {
    tx: Withdraw<DeviceHashes>,
    vault: Vault,
    root: [u8; 32],
    script_hash: [u8; 32],
}

/// An authorized disclosure, readable until chunk 4 is read or it expires.
pub struct Approved {
    vault: Box<Vault>,
    request: Request,
    /// DER || 0x01.
    cosig: [u8; 73],
    cosig_len: usize,
    q: [u8; 33],
    /// 100 ms ticks left: 60 seconds after approval.
    pub ticks_left: u16,
}

pub const APPROVAL_TICKS: u16 = 600;

fn session(session: &mut Session) -> Result<&mut WithdrawSession, AppSW> {
    match session {
        Session::Withdraw(s) => Ok(s),
        _ => Err(AppSW::BadState),
    }
}

pub fn handle<'a>(
    command: Command<'a>,
    step: Step,
    current: &mut Session,
    approved: &mut Option<Approved>,
) -> Result<CommandResponse<'a>, AppSW> {
    let data = command.get_data();
    match step {
        Step::Start => {
            *current = Session::Idle;
            *approved = None;
            let request = withdraw::parse_start(data)?;
            let vault = crypto::vault(request.v)?;
            let script_hash = vault.script_hash::<DeviceHashes>();
            let root = vault.root::<DeviceHashes>();
            *current = Session::Withdraw(Box::new(WithdrawSession {
                tx: Withdraw::new(request, script_hash),
                vault,
                root,
                script_hash,
            }));
        }
        Step::PrevTx => session(current)?.tx.prev_tx_chunk(data)?,
        Step::Outputs => session(current)?.tx.outputs_chunk(data)?,
        Step::Review => {
            if !data.is_empty() {
                return Err(AppSW::WrongDataLength);
            }
            let s = session(current)?;
            let review = s.tx.finalize()?;
            let request = *s.tx.request();
            let wallet = crypto::wallet_id()?;
            let mut store = Nvm;
            let standing = record::standing(&store, &wallet, request.v)?;
            let decided = withdraw::decide(&standing, &s.root, &s.script_hash, &request, &review);
            let comm = command.into_comm();
            let decision = match decided {
                Ok(d) => d,
                Err(pqb_core::error::Error::Conflict) => {
                    ui::conflict(comm, request.v);
                    return Err(AppSW::Conflict);
                }
                Err(e) => return Err(e.into()),
            };
            if !ui::review_withdrawal(comm, &review, &s.root, decision)? {
                return Err(AppSW::Deny);
            }
            // Recorded, durably, before anything leaves. A crash after this
            // consumes the authorization; the host repeats the exact request.
            let existing = match &standing {
                Standing::Recorded(r) => Some(*r),
                _ => None,
            };
            if matches!(decision, Decision::Emergency { .. })
                && record::namespace(&store, &wallet)?.is_none()
            {
                // From now on this seed is never mistaken for a fresh one.
                record::set_namespace(
                    &mut store,
                    Namespace {
                        wallet,
                        state: NsState::Unknown,
                        next_v: 0,
                    },
                )?;
            }
            let after = withdraw::record_after(
                decision,
                existing.as_ref(),
                &wallet,
                &s.root,
                &s.script_hash,
                &request,
                &review,
            );
            record::put(&mut store, &after)?;

            let mut d = s.vault.cosign_key::<DeviceHashes>();
            let q = DeviceCurve::pubkey(&d);
            let signed = crypto::sign(&d, &review.sighash);
            crypto::wipe(&mut d);
            let der = signed?;
            let mut cosig = [0u8; 73];
            let n = der.as_bytes().len();
            cosig[..n].copy_from_slice(der.as_bytes());
            cosig[n] = 0x01;

            let Session::Withdraw(owned) = core::mem::replace(current, Session::Idle) else {
                return Err(AppSW::BadState);
            };
            let WithdrawSession { vault, .. } = *owned;
            *approved = Some(Approved {
                vault: Box::new(vault),
                request,
                cosig,
                cosig_len: n + 1,
                q,
                ticks_left: APPROVAL_TICKS,
            });
            return Ok(comm.begin_response());
        }
    }
    Ok(command.into_response())
}

/// One chunk of the approved disclosure. Reading chunk 4 ends the approval.
pub fn reveal_read<'a>(
    command: Command<'a>,
    chunk: u8,
    approved: &mut Option<Approved>,
) -> Result<CommandResponse<'a>, AppSW> {
    if !command.get_data().is_empty() {
        return Err(AppSW::WrongDataLength);
    }
    let a = approved.as_ref().ok_or(AppSW::NoApprovedReveal)?;
    let mut buf = [0u8; 250];
    let n = withdraw::read_chunk::<DeviceHashes>(
        &a.vault,
        &a.request,
        &a.cosig[..a.cosig_len],
        &a.q,
        chunk,
        &mut buf,
    );
    let n = match n {
        Ok(n) => n,
        Err(_) => return Err(AppSW::WrongP1P2),
    };
    let mut response = command.into_response();
    let appended = response.append(&buf[..n]).map(|_| ());
    crypto::wipe(&mut buf);
    appended?;
    if chunk == withdraw::CHUNKS - 1 {
        *approved = None;
    }
    Ok(response)
}

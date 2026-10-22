//! QSB-HORS-v1: vault secrets derived from the seed, exported as commitments,
//! and revealed once per vault after the user approves (docs/apdu.md).

use alloc::vec;

use ledger_device_sdk::io::{Command, CommandResponse};
use qsb_core::guard::{self, Check, Entry, TABLE_LEN};
use qsb_core::hors::{self, RevealRequest, NET_MAINNET, SPEC_VERSION};

use crate::crypto::{self, DeviceHashes};
use crate::{storage, ui, version, AppSW};

/// The network this build serves: mainnet only.
const BUILD_NET: u8 = NET_MAINNET;

/// An approved reveal, readable until chunk 1 is read or it expires.
pub struct Approved {
    pub request: RevealRequest,
    /// 100 ms ticks left: 60 seconds after approval.
    pub ticks_left: u16,
}

pub const APPROVAL_TICKS: u16 = 600;

/// The wallet tag the reveal guard keys this seed's records with. `K` is
/// derived for it and wiped before any screen.
fn wallet_tag() -> Result<[u8; 8], AppSW> {
    let key = crypto::hors_key()?;
    let k: &[u8; 32] = key.as_ref().try_into().map_err(|_| AppSW::KeyDeriveFail)?;
    Ok(hors::wallet_tag::<DeviceHashes>(k))
}

pub fn get_version(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    if !command.get_data().is_empty() {
        return Err(AppSW::InvalidData);
    }
    let mut response = command.into_response();
    response.append(&version())?.append(SPEC_VERSION)?;
    Ok(response)
}

pub fn get_commitments(command: Command<'_>, round: u8) -> Result<CommandResponse<'_>, AppSW> {
    let req = hors::parse_commitments(round, command.get_data(), BUILD_NET)?;
    let key = crypto::hors_key()?;
    let k: &[u8; 32] = key.as_ref().try_into().map_err(|_| AppSW::KeyDeriveFail)?;
    let mut response = command.into_response();
    for index in req.start..req.start + req.count as u16 {
        response.append(&hors::commitment::<DeviceHashes>(
            k, req.vault, req.round, index,
        ))?;
    }
    Ok(response)
}

pub fn get_commitment_root(
    command: Command<'_>,
    display: bool,
) -> Result<CommandResponse<'_>, AppSW> {
    let vault = hors::parse_vault(command.get_data(), BUILD_NET)?;
    let root = {
        let key = crypto::hors_key()?;
        let k: &[u8; 32] = key.as_ref().try_into().map_err(|_| AppSW::KeyDeriveFail)?;
        hors::commitment_root::<DeviceHashes>(k, vault)
    };
    // Warn before anyone funds a vault whose secrets were already revealed.
    let revealed = display && guard::revealed(storage::table(), &wallet_tag()?, vault)?;
    let comm = command.into_comm();
    if display && !ui::hors_fingerprint(comm, vault, &root, revealed) {
        return Err(AppSW::Deny);
    }
    let mut response = comm.begin_response();
    response.append(&root)?;
    Ok(response)
}

/// Validate, consult the guard, ask the user, and record the reveal before
/// approving it. No preimage leaves here: REVEAL_READ returns them.
pub fn reveal_prepare<'a>(
    command: Command<'a>,
    approved: &mut Option<Approved>,
) -> Result<CommandResponse<'a>, AppSW> {
    *approved = None;
    let request = hors::parse_reveal::<DeviceHashes>(command.get_data(), BUILD_NET)?;
    let reveal_hash = request.reveal_hash::<DeviceHashes>();
    let wallet = wallet_tag()?;
    let comm = command.into_comm();
    match guard::check(storage::table(), &wallet, request.vault, &reveal_hash)? {
        Check::Conflict => {
            ui::hors_conflict(comm, request.vault);
            return Err(AppSW::RevealConflict);
        }
        Check::ReReveal => {
            if !ui::hors_reveal(comm, &request, true)? {
                return Err(AppSW::Deny);
            }
        }
        Check::New { evict } => {
            if let Some(oldest) = evict {
                if !ui::hors_forget(comm, oldest.vault, oldest.wallet != wallet) {
                    return Err(AppSW::Deny);
                }
            }
            if !ui::hors_reveal(comm, &request, false)? {
                return Err(AppSW::Deny);
            }
            // Recorded, durably, before the approval that lets any preimage out.
            let mut next = vec![0u8; TABLE_LEN];
            let next: &mut [u8; TABLE_LEN] = next
                .as_mut_slice()
                .try_into()
                .map_err(|_| AppSW::InvalidData)?;
            guard::record_into(
                storage::table(),
                Entry {
                    wallet,
                    vault: request.vault,
                    reveal_hash,
                },
                next,
            )?;
            storage::write(next);
        }
    }
    *approved = Some(Approved {
        request,
        ticks_left: APPROVAL_TICKS,
    });
    Ok(comm.begin_response())
}

/// Preimages 1–12 (chunk 0) or 13–15 (chunk 1) of the approved reveal, in the
/// order the host sent the indices. Reading chunk 1 ends the approval.
pub fn reveal_read<'a>(
    command: Command<'a>,
    chunk: u8,
    approved: &mut Option<Approved>,
) -> Result<CommandResponse<'a>, AppSW> {
    if !command.get_data().is_empty() {
        return Err(AppSW::InvalidData);
    }
    let request = approved.as_ref().ok_or(AppSW::NoApprovedReveal)?.request;
    let range = hors::chunk_range(chunk).ok_or(AppSW::WrongP1P2)?;
    let key = crypto::hors_key()?;
    let k: &[u8; 32] = key.as_ref().try_into().map_err(|_| AppSW::KeyDeriveFail)?;
    let mut response = command.into_response();
    for &(round, index) in &request.revealed()[range] {
        let mut preimage = hors::secret::<DeviceHashes>(k, request.vault, round, index);
        let appended = response.append(&preimage).map(|_| ());
        crypto::wipe(&mut preimage);
        appended?;
    }
    if chunk == 1 {
        *approved = None;
    }
    Ok(response)
}

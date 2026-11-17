//! Vault queries, allocation, retirement and the solver's menu points (docs/apdu.md).

use ledger_device_sdk::io::{Command, CommandResponse};
use pqb_core::address;
use pqb_core::hash::hash160;
use pqb_core::pqb::{self, Curve, PROFILE};
use pqb_core::record::{self, Namespace, NsState, Record, Standing, State, CAPACITY};
use pqb_core::script::p2wpkh;
use pqb_core::template::SCRIPT_LEN;
use pqb_core::withdraw;

use crate::crypto::{self, DeviceCurve, DeviceHashes};
use crate::storage::Nvm;
use crate::{ui, version, AppSW};

fn index(data: &[u8]) -> Result<u32, AppSW> {
    if data.len() != 4 {
        return Err(AppSW::WrongDataLength);
    }
    pqb::parse_index(data).ok_or(AppSW::InvalidData)
}

pub fn get_version(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let mut response = command.into_response();
    response.append(&version())?.append(PROFILE)?;
    Ok(response)
}

pub fn get_commitments(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let (v, start, count) = withdraw::parse_commitments(command.get_data())?;
    let vault = crypto::vault(v)?;
    let mut response = command.into_response();
    for i in start..start + count {
        response.append(&vault.commitment::<DeviceHashes>(i))?;
    }
    Ok(response)
}

pub fn get_vault(command: Command<'_>, display: bool) -> Result<CommandResponse<'_>, AppSW> {
    let v = index(command.get_data())?;
    let (root, script_hash) = {
        let vault = crypto::vault(v)?;
        (
            vault.root::<DeviceHashes>(),
            vault.script_hash::<DeviceHashes>(),
        )
    };
    let standing = record::standing(&Nvm, &crypto::wallet_id()?, v)?;
    let status = record::status_byte(&standing);
    let funded = matches!(&standing, Standing::Recorded(r) if r.funding.is_some());
    let comm = command.into_comm();
    if display && !ui::verify_vault(comm, v, &root, status, funded) {
        return Err(AppSW::Deny);
    }
    let mut response = comm.begin_response();
    response
        .append(&root)?
        .append(&script_hash)?
        .append(&[status, funded as u8])?;
    Ok(response)
}

pub fn get_script(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let data = command.get_data();
    if data.len() != 6 {
        return Err(AppSW::WrongDataLength);
    }
    let v = index(&data[..4])?;
    let offset = u16::from_be_bytes([data[4], data[5]]) as usize;
    if offset >= SCRIPT_LEN {
        return Err(AppSW::InvalidData);
    }
    let len = (SCRIPT_LEN - offset).min(250);
    let mut buf = [0u8; 250];
    crypto::vault(v)?.script_chunk::<DeviceHashes>(offset, &mut buf[..len]);
    let mut response = command.into_response();
    response.append(&buf[..len])?;
    Ok(response)
}

pub fn get_deposit_address(
    command: Command<'_>,
    display: bool,
) -> Result<CommandResponse<'_>, AppSW> {
    let v = index(command.get_data())?;
    let pubkey = {
        let vault = crypto::vault(v)?;
        let mut dd = vault.deposit_key::<DeviceHashes>();
        let pubkey = DeviceCurve::pubkey(&dd);
        crypto::wipe(&mut dd);
        pubkey
    };
    let script = p2wpkh(&hash160::<DeviceHashes>(&pubkey));
    let address = address::from_script::<DeviceHashes>(&script)?;
    if display {
        // Shown as a place to pay only while the vault can take its one funding.
        let open = matches!(
            record::standing(&Nvm, &crypto::wallet_id()?, v)?,
            Standing::Recorded(Record {
                state: State::Allocated,
                funding: None,
                disclosure: None,
                ..
            })
        );
        if !open {
            return Err(AppSW::VaultState);
        }
    }
    let comm = command.into_comm();
    if display && !ui::verify_deposit_address(comm, v, address.as_str()) {
        return Err(AppSW::Deny);
    }
    let mut response = comm.begin_response();
    response
        .append(&pubkey)?
        .append(&[address.as_str().len() as u8])?
        .append(address.as_str().as_bytes())?;
    Ok(response)
}

pub fn get_state(command: Command<'_>, record_index: bool) -> Result<CommandResponse<'_>, AppSW> {
    let data = command.get_data();
    let wallet = crypto::wallet_id()?;
    if record_index {
        let &[i] = data else {
            return Err(AppSW::WrongDataLength);
        };
        let r = record::nth(&Nvm, &wallet, i as usize)?.ok_or(AppSW::InvalidData)?;
        let slot = r.encode();
        let mut response = command.into_response();
        // The slot's last 5 bytes are padding.
        response.append(&slot[..251])?;
        return Ok(response);
    }
    if !data.is_empty() {
        return Err(AppSW::WrongDataLength);
    }
    let ns = record::namespace(&Nvm, &wallet)?;
    let (state, next_v) = match ns {
        None => (0, 0),
        Some(n) => (
            match n.state {
                NsState::Fresh => 1,
                NsState::Unknown => 2,
            },
            n.next_v,
        ),
    };
    let count = record::count(&Nvm, &wallet)?;
    let mut response = command.into_response();
    response
        .append(&wallet)?
        .append(&[state])?
        .append(&next_v.to_be_bytes())?
        .append(&[count as u8, CAPACITY as u8])?;
    Ok(response)
}

pub fn allocate(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    if !command.get_data().is_empty() {
        return Err(AppSW::WrongDataLength);
    }
    let wallet = crypto::wallet_id()?;
    let mut store = Nvm;
    let existing = record::namespace(&store, &wallet)?;
    let comm = command.into_comm();
    let ns = match existing {
        Some(ns) => ns,
        None if ui::first_use(comm) => Namespace {
            wallet,
            state: NsState::Fresh,
            next_v: 0,
        },
        None => {
            // Recorded, so the device never treats this seed as fresh later.
            record::set_namespace(
                &mut store,
                Namespace {
                    wallet,
                    state: NsState::Unknown,
                    next_v: 0,
                },
            )?;
            ui::no_history(comm);
            return Err(AppSW::Continuity);
        }
    };
    if ns.state == NsState::Unknown {
        ui::no_history(comm);
        return Err(AppSW::Continuity);
    }
    if !record::has_room(&store)? {
        return Err(AppSW::StoreFull);
    }
    let v = ns.next_v;
    if v > pqb::MAX_VAULT_INDEX {
        return Err(AppSW::StoreFull);
    }
    let (root, script_hash) = {
        let vault = crypto::vault(v)?;
        (
            vault.root::<DeviceHashes>(),
            vault.script_hash::<DeviceHashes>(),
        )
    };
    if !ui::allocate(comm, v, &root) {
        return Err(AppSW::Deny);
    }
    // Namespace, then the record, then the high-water mark: a crash between any
    // two leaves the index taken or nothing published.
    if existing.is_none() {
        record::set_namespace(&mut store, ns)?;
    }
    record::put(
        &mut store,
        &Record {
            wallet,
            v,
            state: State::Allocated,
            emergency: false,
            root,
            script_hash,
            funding: None,
            disclosure: None,
        },
    )?;
    record::set_namespace(
        &mut store,
        Namespace {
            next_v: v + 1,
            ..ns
        },
    )?;
    let mut response = comm.begin_response();
    response
        .append(&v.to_be_bytes())?
        .append(&root)?
        .append(&script_hash)?;
    Ok(response)
}

pub fn retire(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let v = index(command.get_data())?;
    let wallet = crypto::wallet_id()?;
    let mut store = Nvm;
    let (_, mut r) = record::find(&store, &wallet, v)?.ok_or(AppSW::VaultState)?;
    if r.state == State::Retired {
        return Err(AppSW::VaultState);
    }
    let comm = command.into_comm();
    if !ui::retire(comm, v) {
        return Err(AppSW::Deny);
    }
    match record::namespace(&store, &wallet)? {
        Some(ns) if ns.state == NsState::Fresh => {
            // Below next_v without a record: reserved for good.
            record::set_namespace(
                &mut store,
                Namespace {
                    next_v: ns.next_v.max(v + 1),
                    ..ns
                },
            )?;
            record::remove(&mut store, &wallet, v)?;
        }
        _ => {
            r.state = State::Retired;
            record::put(&mut store, &r)?;
        }
    }
    Ok(comm.begin_response())
}

pub fn authorize_menu_points<'a>(
    command: Command<'a>,
    authorized: &mut Option<u32>,
) -> Result<CommandResponse<'a>, AppSW> {
    let v = index(command.get_data())?;
    *authorized = None;
    let comm = command.into_comm();
    if !ui::authorize_menu_points(comm, v) {
        return Err(AppSW::Deny);
    }
    *authorized = Some(v);
    Ok(comm.begin_response())
}

/// The `r` every menu signature of a stage shares, which the solver needs with
/// the points. In pqb v1 it is 1 for stage 0 and 0x81 for stages 1 and 2; the
/// device reports it so a host never has to assume the construction. Same
/// authorization as the points, which already determine it.
pub fn menu_r<'a>(
    command: Command<'a>,
    authorized: &Option<u32>,
) -> Result<CommandResponse<'a>, AppSW> {
    let (v, stage) = withdraw::parse_menu_r(command.get_data())?;
    if *authorized != Some(v) {
        return Err(AppSW::NotAuthorized);
    }
    let r = crypto::vault(v)?.menu_r(stage).to_be();
    let mut response = command.into_response();
    response.append(&r)?;
    Ok(response)
}

pub fn menu_points<'a>(
    command: Command<'a>,
    authorized: &Option<u32>,
) -> Result<CommandResponse<'a>, AppSW> {
    let (v, stage, variant, start, count) = withdraw::parse_menu_points(command.get_data())?;
    if *authorized != Some(v) {
        return Err(AppSW::NotAuthorized);
    }
    let vault = crypto::vault(v)?;
    let mut response = command.into_response();
    for i in start..start + count {
        let point = vault
            .menu_point::<DeviceHashes, DeviceCurve>(stage, variant, i)
            .ok_or(AppSW::InvalidData)?;
        response.append(&point)?;
    }
    Ok(response)
}

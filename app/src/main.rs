//! PQB: a Ledger app holding the signing secrets of Post-Quantum Bitcoin (PQB)
//! vaults, per the BIP "PQB Vault Secret Management" (profile `PQB-v1`).
//!
//! Each vault's 109 one-time preimages, 44 menu scalars, co-signing key and
//! deposit key derive from the device seed through BIP 85. The app exports
//! commitments and scripts, allocates vaults, signs the sweep that funds one,
//! and discloses a withdrawal's secrets and co-signature once per vault, after
//! the user approves and the disclosure is recorded in NVM.
//!
//! The protocol is in docs/apdu.md; the parsing, derivation and checks live in
//! the host-tested `pqb-core` crate.

#![no_std]
#![no_main]

extern crate alloc;

mod crypto;
mod handlers;
mod storage;
mod ui;

use handlers::withdraw::Approved;
use handlers::Session;
use handlers::{deposit, vault, withdraw};
use ledger_device_sdk::io::{self, init_comm, ApduHeader, Command, CommandResponse, Event, Reply};
use ledger_device_sdk::nbgl::{NbglHomeAndSettings, NbglSpinner, StatusType};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

/// Status words; docs/apdu.md lists them.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppSW {
    Deny = 0x6985,
    InvalidData = 0x6A80,
    WrongP1P2 = 0x6A86,
    WrongDataLength = 0x6A87,
    Conflict = 0x6A90,
    NoApprovedReveal = 0x6A91,
    StoreCorrupt = 0x6A93,
    VaultState = 0x6A94,
    Continuity = 0x6A95,
    StoreFull = 0x6A96,
    NotAuthorized = 0x6A97,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    CommError = 0x6F00,
    BadState = 0xB001,
    Parse = 0xB003,
    TxidMismatch = 0xB004,
    NotOwnInput = 0xB005,
    NotVault = 0xB006,
    BadLayout = 0xB007,
    UnsupportedOutput = 0xB008,
    BadAmount = 0xB009,
    SignFail = 0xB00B,
    KeyDeriveFail = 0xB00C,
    Ok = 0x9000,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

impl From<io::CommError> for AppSW {
    fn from(_: io::CommError) -> Self {
        AppSW::CommError
    }
}

impl From<pqb_core::error::Error> for AppSW {
    fn from(e: pqb_core::error::Error) -> Self {
        use pqb_core::error::Error;
        match e {
            Error::BadLength => AppSW::WrongDataLength,
            Error::BadState => AppSW::BadState,
            Error::Parse => AppSW::Parse,
            Error::TxidMismatch => AppSW::TxidMismatch,
            Error::NotOwnInput => AppSW::NotOwnInput,
            Error::NotVault => AppSW::NotVault,
            Error::BadLayout => AppSW::BadLayout,
            Error::UnsupportedOutput => AppSW::UnsupportedOutput,
            Error::BadAmount => AppSW::BadAmount,
            Error::BadSignature => AppSW::SignFail,
            Error::BadData => AppSW::InvalidData,
            Error::Conflict => AppSW::Conflict,
            Error::NoApprovedReveal => AppSW::NoApprovedReveal,
            Error::StoreCorrupt => AppSW::StoreCorrupt,
            Error::StoreFull => AppSW::StoreFull,
            Error::VaultState => AppSW::VaultState,
            Error::Continuity => AppSW::Continuity,
            Error::NotAuthorized => AppSW::NotAuthorized,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Instruction {
    GetVersion,
    GetAppName,
    GetCommitments,
    GetVault { display: bool },
    GetScript,
    GetDepositAddress { display: bool },
    GetState { record: bool },
    Allocate,
    Retire,
    SignDeposit(deposit::Step),
    Withdraw(withdraw::Step),
    RevealRead { chunk: u8 },
    MenuPoints { op: u8 },
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    // CLA is checked by the SDK (`set_expected_cla`).
    fn try_from(h: ApduHeader) -> Result<Self, AppSW> {
        match (h.ins, h.p1, h.p2) {
            (0x03, 0, 0) => Ok(Instruction::GetVersion),
            (0x04, 0, 0) => Ok(Instruction::GetAppName),
            (0x10, 0, 0) => Ok(Instruction::GetCommitments),
            (0x11, 0 | 1, 0) => Ok(Instruction::GetVault { display: h.p1 == 1 }),
            (0x12, 0, 0) => Ok(Instruction::GetScript),
            (0x13, 0 | 1, 0) => Ok(Instruction::GetDepositAddress { display: h.p1 == 1 }),
            (0x14, 0 | 1, 0) => Ok(Instruction::GetState { record: h.p1 == 1 }),
            (0x20, 0, 0) => Ok(Instruction::Allocate),
            (0x21, 0, 0) => Ok(Instruction::Retire),
            (0x30, p1, 0) => deposit::Step::from_p1(p1)
                .map(Instruction::SignDeposit)
                .ok_or(AppSW::WrongP1P2),
            (0x40, p1, 0) => withdraw::Step::from_p1(p1)
                .map(Instruction::Withdraw)
                .ok_or(AppSW::WrongP1P2),
            (0x41, 0..=4, 0) => Ok(Instruction::RevealRead { chunk: h.p1 }),
            (0x42, 0..=2, 0) => Ok(Instruction::MenuPoints { op: h.p1 }),
            (0x03 | 0x04 | 0x10..=0x14 | 0x20 | 0x21 | 0x30 | 0x40..=0x42, _, _) => {
                Err(AppSW::WrongP1P2)
            }
            _ => Err(AppSW::InsNotSupported),
        }
    }
}

/// What is on screen between commands: home, or a spinner while the host
/// collects signatures or secrets.
struct Screen {
    home: NbglHomeAndSettings,
    // Lives as long as the app: NBGL keeps a pointer to its text while it spins.
    spinner: NbglSpinner,
    /// The "Disclosing secrets" spinner is showing.
    disclosing: bool,
}

impl Screen {
    fn home(&mut self) {
        self.home.show_and_return();
        self.disclosing = false;
    }

    fn signing(&mut self) {
        ui::signing(&mut self.spinner);
        self.disclosing = false;
    }

    fn disclosing(&mut self) {
        ui::disclosing(&mut self.spinner);
        self.disclosing = true;
    }
}

/// State kept between commands.
struct App {
    session: Session,
    /// An approved disclosure, readable until chunk 4 is read or 60 s pass.
    approved: Option<Approved>,
    /// The vault whose menu points the user agreed to export.
    menu_points: Option<u32>,
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xe0);
    storage::init();

    let mut screen = Screen {
        home: ui::home(),
        spinner: NbglSpinner::new(),
        disclosing: false,
    };
    screen.home();
    let mut app = App {
        session: Session::Idle,
        approved: None,
        menu_points: None,
    };

    loop {
        let command = match comm.next_event() {
            Event::Command(command) => command,
            // Every 100 ms while no screen blocks: the approval runs out.
            Event::Ticker => {
                if let Some(approved) = app.approved.as_mut() {
                    approved.ticks_left = approved.ticks_left.saturating_sub(1);
                    if approved.ticks_left == 0 {
                        app.approved = None;
                        // Only the disclosure's own spinner: never a signing one.
                        if screen.disclosing {
                            screen.home();
                        }
                    }
                }
                continue;
            }
            _ => continue,
        };
        let decoded = command.decode::<Instruction>();
        let Ok(ins) = decoded else {
            let _ = comm.send(&[], decoded.unwrap_err());
            continue;
        };

        // An approved transaction waits, behind the spinner, for its signatures
        // to be collected. Any other command means the host gave up on it.
        let collecting = matches!(&app.session, Session::Deposit(s) if s.is_approved());
        let sign = matches!(ins, Instruction::SignDeposit(deposit::Step::Sign));
        if collecting && !sign {
            app.session = Session::Idle;
            screen.home();
        }
        // Likewise an approved disclosure, behind its spinner, ends with any
        // command but REVEAL_READ (and the session state is never resumed).
        let reading = matches!(ins, Instruction::RevealRead { .. });
        if app.approved.is_some() && !reading {
            app.approved = None;
            screen.home();
        }

        let outcome = match handle(command, ins, &mut app) {
            Ok(response) => response.send(AppSW::Ok).map(|_| ()).map_err(AppSW::from),
            Err(sw) => {
                let _ = comm.send(&[], sw);
                Err(sw)
            }
        };
        // Errors end the session, except a SIGN of an input already signed:
        // the approved transaction stays.
        match outcome {
            Err(AppSW::BadState) if collecting && sign => {}
            Err(_) => app.session = Session::Idle,
            Ok(()) => {}
        }

        // A status screen follows a review the user saw: approved (Ok) or
        // rejected (Deny). Errors before any review leave the screen as it is.
        let reviewed = matches!(outcome, Ok(()) | Err(AppSW::Deny));
        let ok = outcome.is_ok();
        let idle = matches!(app.session, Session::Idle);
        match ins {
            Instruction::GetVault { display: true }
            | Instruction::GetDepositAddress { display: true }
                if reviewed =>
            {
                if matches!(ins, Instruction::GetDepositAddress { .. }) {
                    ui::status(comm, StatusType::Address, ok);
                }
                screen.home();
            }
            Instruction::Allocate if reviewed => {
                ui::message(comm, if ok { "Vault created" } else { "Rejected" }, ok);
                screen.home();
            }
            Instruction::Allocate if outcome == Err(AppSW::Continuity) => screen.home(),
            Instruction::Retire if reviewed => {
                ui::message(comm, if ok { "Vault retired" } else { "Cancelled" }, ok);
                screen.home();
            }
            Instruction::MenuPoints { op: 0 } if reviewed => {
                ui::message(comm, if ok { "Export approved" } else { "Cancelled" }, ok);
                screen.home();
            }
            Instruction::SignDeposit(deposit::Step::Review) if ok => screen.signing(),
            Instruction::SignDeposit(deposit::Step::Review) if reviewed => {
                ui::status(comm, StatusType::Transaction, false);
                screen.home();
            }
            // The last signature was collected, or signing failed.
            Instruction::SignDeposit(deposit::Step::Sign) if collecting && idle => {
                if ok {
                    ui::status(comm, StatusType::Transaction, true);
                }
                screen.home();
            }
            // Approved: the host reads the secrets behind a spinner.
            Instruction::Withdraw(withdraw::Step::Review) if ok => screen.disclosing(),
            Instruction::Withdraw(withdraw::Step::Review) if reviewed => {
                ui::message(comm, "Disclosure rejected", false);
                screen.home();
            }
            // The conflict page was shown and dismissed.
            Instruction::Withdraw(withdraw::Step::Review) if outcome == Err(AppSW::Conflict) => {
                screen.home()
            }
            Instruction::RevealRead { chunk: 4 } if ok => {
                ui::message(comm, "Secrets disclosed", true);
                screen.home();
            }
            _ => {}
        }
        // The disclosure spinner shows only while an approval exists.
        if screen.disclosing && app.approved.is_none() {
            screen.home();
        }
    }
}

fn handle<'a>(
    command: Command<'a>,
    ins: Instruction,
    app: &mut App,
) -> Result<CommandResponse<'a>, AppSW> {
    match ins {
        Instruction::GetVersion => vault::get_version(command),
        Instruction::GetAppName => {
            let mut response = command.into_response();
            response.append(b"PQB")?;
            Ok(response)
        }
        Instruction::GetCommitments => vault::get_commitments(command),
        Instruction::GetVault { display } => vault::get_vault(command, display),
        Instruction::GetScript => vault::get_script(command),
        Instruction::GetDepositAddress { display } => vault::get_deposit_address(command, display),
        Instruction::GetState { record } => vault::get_state(command, record),
        Instruction::Allocate => vault::allocate(command),
        Instruction::Retire => vault::retire(command),
        Instruction::SignDeposit(step) => deposit::handle(command, step, &mut app.session),
        Instruction::Withdraw(step) => {
            withdraw::handle(command, step, &mut app.session, &mut app.approved)
        }
        Instruction::RevealRead { chunk } => {
            withdraw::reveal_read(command, chunk, &mut app.approved)
        }
        Instruction::MenuPoints { op: 0 } => {
            vault::authorize_menu_points(command, &mut app.menu_points)
        }
        Instruction::MenuPoints { op: 1 } => vault::menu_points(command, &app.menu_points),
        Instruction::MenuPoints { .. } => vault::menu_r(command, &app.menu_points),
    }
}

/// `CARGO_PKG_VERSION` as three bytes, parsed at compile time.
pub const fn version() -> [u8; 3] {
    let v = env!("CARGO_PKG_VERSION").as_bytes();
    let mut out = [0u8; 3];
    let (mut part, mut i) = (0, 0);
    while i < v.len() && part < 3 {
        if v[i] == b'.' {
            part += 1;
        } else {
            out[part] = out[part] * 10 + (v[i] - b'0');
        }
        i += 1;
    }
    out
}

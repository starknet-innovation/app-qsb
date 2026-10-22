//! QSB: a Ledger app for QSB (quantum-safe Bitcoin) vaults.
//!
//! It signs exactly three things for one BIP-84 or BIP-49 wallet address, each
//! after showing what it does: a deposit into a QSB vault, the wallet's helper
//! input of a withdrawal from a QSB vault, and the QSB service's sign-in
//! challenge. Everything else is refused.
//!
//! It also derives the vaults' one-time HORS secrets from the seed (SLIP-0021,
//! spec QSB-HORS-v1), exports only their commitments, and reveals the 15
//! preimages a withdrawal needs once per vault, after the user approves.
//!
//! The protocol is in docs/apdu.md; the parsing and checks live in the
//! host-tested `qsb-core` crate.

#![no_std]
#![no_main]

extern crate alloc;

mod crypto;
mod handlers;
mod storage;
mod ui;

use handlers::hors::Approved;
use handlers::sign_tx::Step;
use handlers::Session;
use ledger_device_sdk::io::{self, init_comm, ApduHeader, Command, CommandResponse, Event, Reply};
use ledger_device_sdk::nbgl::{NbglHomeAndSettings, NbglSpinner, StatusType};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

/// Status words; docs/apdu.md lists them.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppSW {
    Deny = 0x6985,
    WrongP1P2 = 0x6A86,
    WrongDataLength = 0x6A87,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    CommError = 0x6F00,
    BadState = 0xB001,
    BadPath = 0xB002,
    Parse = 0xB003,
    TxidMismatch = 0xB004,
    NotOwnInput = 0xB005,
    NotVault = 0xB006,
    BadLayout = 0xB007,
    UnsupportedOutput = 0xB008,
    BadAmount = 0xB009,
    BadMessage = 0xB00A,
    SignFail = 0xB00B,
    KeyDeriveFail = 0xB00C,
    // The HORS commands' status words, from the QSB-HORS-v1 spec.
    InvalidData = 0x6A80,
    RevealConflict = 0x6A90,
    NoApprovedReveal = 0x6A91,
    WrongNetwork = 0x6A92,
    /// The reveal guard's stored record is unreadable: reveals are refused.
    GuardCorrupt = 0x6A93,
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

impl From<qsb_core::error::Error> for AppSW {
    fn from(e: qsb_core::error::Error) -> Self {
        use qsb_core::error::Error;
        match e {
            Error::BadLength => AppSW::WrongDataLength,
            Error::BadPath => AppSW::BadPath,
            Error::BadState => AppSW::BadState,
            Error::Parse => AppSW::Parse,
            Error::TxidMismatch => AppSW::TxidMismatch,
            Error::NotOwnInput => AppSW::NotOwnInput,
            Error::NotVault => AppSW::NotVault,
            Error::BadLayout => AppSW::BadLayout,
            Error::UnsupportedOutput => AppSW::UnsupportedOutput,
            Error::BadAmount => AppSW::BadAmount,
            Error::BadMessage => AppSW::BadMessage,
            Error::BadSignature => AppSW::SignFail,
            Error::BadData => AppSW::InvalidData,
            Error::WrongNetwork => AppSW::WrongNetwork,
            Error::RevealConflict => AppSW::RevealConflict,
            Error::NoApprovedReveal => AppSW::NoApprovedReveal,
            Error::GuardCorrupt => AppSW::GuardCorrupt,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Instruction {
    GetVersion,
    GetAppName,
    GetWalletAddress { display: bool },
    SignTx(Step),
    SignIn { first: bool },
    HorsVersion,
    GetCommitments { round: u8 },
    GetCommitmentRoot { display: bool },
    RevealPrepare,
    RevealRead { chunk: u8 },
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    // CLA is checked by the SDK (`set_expected_cla`).
    fn try_from(h: ApduHeader) -> Result<Self, AppSW> {
        match (h.ins, h.p1, h.p2) {
            (0x03, 0, 0) => Ok(Instruction::GetVersion),
            (0x04, 0, 0) => Ok(Instruction::GetAppName),
            (0x05, 0 | 1, 0) => Ok(Instruction::GetWalletAddress { display: h.p1 == 1 }),
            (0x06, p1, 0) => Step::from_p1(p1)
                .map(Instruction::SignTx)
                .ok_or(AppSW::WrongP1P2),
            (0x07, 0x00 | 0x80, 0) => Ok(Instruction::SignIn { first: h.p1 == 0 }),
            (0x01, 0, 0) => Ok(Instruction::HorsVersion),
            (0x10, 0 | 1, 0) => Ok(Instruction::GetCommitments { round: h.p1 }),
            (0x11, 0 | 1, 0) => Ok(Instruction::GetCommitmentRoot { display: h.p1 == 1 }),
            (0x20, 0, 0) => Ok(Instruction::RevealPrepare),
            (0x21, 0 | 1, 0) => Ok(Instruction::RevealRead { chunk: h.p1 }),
            (0x01 | 0x03..=0x07 | 0x10 | 0x11 | 0x20 | 0x21, _, _) => Err(AppSW::WrongP1P2),
            _ => Err(AppSW::InsNotSupported),
        }
    }
}

/// What is on screen between commands: home, or a spinner while the host
/// collects signatures or preimages.
struct Screen {
    home: NbglHomeAndSettings,
    // Lives as long as the app: NBGL keeps a pointer to its text while it spins.
    spinner: NbglSpinner,
    /// The "Revealing secrets" spinner is showing.
    revealing: bool,
}

impl Screen {
    fn home(&mut self) {
        self.home.show_and_return();
        self.revealing = false;
    }

    fn signing(&mut self) {
        ui::signing(&mut self.spinner);
        self.revealing = false;
    }

    fn revealing(&mut self) {
        ui::revealing(&mut self.spinner);
        self.revealing = true;
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xe0);

    let mut screen = Screen {
        home: ui::home(),
        spinner: NbglSpinner::new(),
        revealing: false,
    };
    screen.home();
    let mut session = Session::Idle;
    // An approved HORS reveal, readable until chunk 1 is read or 60 s pass.
    let mut reveal: Option<Approved> = None;

    loop {
        let command = match comm.next_event() {
            Event::Command(command) => command,
            // Every 100 ms while no screen blocks: the reveal approval runs out.
            Event::Ticker => {
                if let Some(approved) = reveal.as_mut() {
                    approved.ticks_left = approved.ticks_left.saturating_sub(1);
                    if approved.ticks_left == 0 {
                        reveal = None;
                        // Only the reveal's own spinner: never a signing one.
                        if screen.revealing {
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
        let collecting = matches!(&session, Session::Tx(tx) if tx.is_approved());
        let sign = matches!(ins, Instruction::SignTx(Step::Sign));
        if collecting && !sign {
            session = Session::Idle;
            screen.home();
        }

        let outcome = match handle(command, ins, &mut session, &mut reveal) {
            Ok(response) => response.send(AppSW::Ok).map(|_| ()).map_err(AppSW::from),
            Err(sw) => {
                let _ = comm.send(&[], sw);
                Err(sw)
            }
        };
        // Errors end the session, except a SIGN for an input that isn't signable
        // (not the wallet's, or already signed): the approved transaction stays.
        match outcome {
            Err(AppSW::BadState) if collecting && sign => {}
            Err(_) => session = Session::Idle,
            Ok(()) => {}
        }

        // A status screen follows a review the user saw: approved (Ok) or
        // rejected (Deny). Errors before any review leave the screen as it is.
        let reviewed = matches!(outcome, Ok(()) | Err(AppSW::Deny));
        let ok = outcome.is_ok();
        let idle = matches!(session, Session::Idle);
        match ins {
            Instruction::GetWalletAddress { display: true } if reviewed => {
                ui::status(comm, StatusType::Address, ok);
                screen.home();
            }
            Instruction::SignTx(Step::Review) if ok => screen.signing(),
            Instruction::SignTx(Step::Review) if reviewed => {
                ui::status(comm, StatusType::Transaction, false);
                screen.home();
            }
            // The last signature was collected, or signing failed.
            Instruction::SignTx(Step::Sign) if collecting && idle => {
                if ok {
                    ui::status(comm, StatusType::Transaction, true);
                }
                screen.home();
            }
            Instruction::SignIn { .. } if reviewed && idle => {
                ui::status(comm, StatusType::Message, ok);
                screen.home();
            }
            Instruction::GetCommitmentRoot { display: true } if reviewed => screen.home(),
            // Approved: the host reads the preimages behind a spinner.
            Instruction::RevealPrepare if ok => screen.revealing(),
            Instruction::RevealPrepare if reviewed => {
                ui::hors_status(comm, false);
                screen.home();
            }
            // The conflict page was shown and dismissed.
            Instruction::RevealPrepare if outcome == Err(AppSW::RevealConflict) => screen.home(),
            Instruction::RevealRead { chunk: 1 } if ok => {
                ui::hors_status(comm, true);
                screen.home();
            }
            _ => {}
        }
        // The reveal spinner shows only while an approval exists: a REVEAL_PREPARE
        // refused before any screen still ended the previous one.
        if screen.revealing && reveal.is_none() {
            screen.home();
        }
    }
}

fn handle<'a>(
    command: Command<'a>,
    ins: Instruction,
    session: &mut Session,
    reveal: &mut Option<Approved>,
) -> Result<CommandResponse<'a>, AppSW> {
    match ins {
        Instruction::GetVersion => {
            let mut response = command.into_response();
            response.append(&version())?;
            Ok(response)
        }
        Instruction::GetAppName => {
            let mut response = command.into_response();
            response.append(b"QSB")?;
            Ok(response)
        }
        Instruction::GetWalletAddress { display } => handlers::wallet::handle(command, display),
        Instruction::SignTx(step) => handlers::sign_tx::handle(command, step, session),
        Instruction::SignIn { first } => handlers::sign_in::handle(command, first, session),
        Instruction::HorsVersion => handlers::hors::get_version(command),
        Instruction::GetCommitments { round } => handlers::hors::get_commitments(command, round),
        Instruction::GetCommitmentRoot { display } => {
            handlers::hors::get_commitment_root(command, display)
        }
        Instruction::RevealPrepare => handlers::hors::reveal_prepare(command, reveal),
        Instruction::RevealRead { chunk } => handlers::hors::reveal_read(command, chunk, reveal),
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

//! The transaction signing session.
//!
//! The host streams the transaction in order: a header, then for each input its
//! outpoint and sequence followed by the full previous transaction, then the
//! serialized outputs. The app hashes everything it later signs, checks each
//! previous transaction against its outpoint's txid (so input amounts and scripts
//! are proven, not claimed), recognises the QSB vault script, and only then
//! builds the review. Signatures are released per input after approval.
//!
//! Two transaction kinds exist, matching what qsb-app asks a wallet to sign:
//!
//! - **Deposit** (`fundingPsbt`): 1–8 inputs, all spending the wallet's address;
//!   output 0 pays a QSB vault script; an optional output 1 returns change to the
//!   wallet's address. Every input is signed.
//! - **Withdrawal** (`helperPsbt`): input 0 spends the wallet's helper UTXO,
//!   input 1 spends a QSB vault output (its HORS scriptSig is assembled by the
//!   QSB client, not here); one output pays the destination. Only input 0 is
//!   signed, with SIGHASH_ALL, which is what fixes destination, amount and fee.

use crate::amount::MAX_MONEY;
use crate::error::{Error, Result};
use crate::hash::{finalize_double, Hashes, Sha256};
use crate::path::{self, Path};
use crate::script::{classify, SmallScript};
use crate::sighash::{p2wpkh_sighash_all, Bip143Common};
use crate::tx::{OutputVisitor, OutputsParser, PrevTxParser, ScriptCapture};
use crate::wallet::Wallet;

/// Most inputs a deposit may have; qsb-app's server refuses more (`checkFunding`).
pub const MAX_INPUTS: usize = 8;
pub const MAX_OUTPUTS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Deposit,
    Withdrawal,
}

/// The `START` command.
#[derive(Clone, Copy, Debug)]
pub struct Start {
    pub kind: Kind,
    pub path: Path,
    pub version: u32,
    pub locktime: u32,
    pub n_inputs: u8,
    pub n_outputs: u8,
}

/// `kind (1) || path || version (4 LE) || locktime (4 LE) || inputs (1) || outputs (1)`.
pub fn parse_start(data: &[u8]) -> Result<Start> {
    let (&kind, rest) = data.split_first().ok_or(Error::BadLength)?;
    let kind = match kind {
        1 => Kind::Deposit,
        2 => Kind::Withdrawal,
        _ => return Err(Error::BadLayout),
    };
    let (path, rest) = path::parse(rest)?;
    if rest.len() != 10 {
        return Err(Error::BadLength);
    }
    let start = Start {
        kind,
        path,
        version: u32::from_le_bytes(rest[0..4].try_into().map_err(|_| Error::BadLength)?),
        locktime: u32::from_le_bytes(rest[4..8].try_into().map_err(|_| Error::BadLength)?),
        n_inputs: rest[8],
        n_outputs: rest[9],
    };
    let layout_ok = match kind {
        Kind::Deposit => {
            (1..=MAX_INPUTS as u8).contains(&start.n_inputs) && (1..=2).contains(&start.n_outputs)
        }
        Kind::Withdrawal => start.n_inputs == 2 && start.n_outputs == 1,
    };
    if !layout_ok {
        return Err(Error::BadLayout);
    }
    Ok(start)
}

#[derive(Clone, Copy)]
struct Input {
    outpoint: [u8; 36],
    sequence: u32,
    amount: u64,
    ours: bool,
    signed: bool,
}

impl Input {
    const EMPTY: Input = Input {
        outpoint: [0; 36],
        sequence: 0,
        amount: 0,
        ours: false,
        signed: false,
    };
}

#[derive(Clone, Copy)]
struct Output {
    value: u64,
    script: Option<SmallScript>,
    vault: Option<[u8; 32]>,
}

/// Records each output of the transaction being signed.
struct Outputs<H: Hashes> {
    capture: ScriptCapture<H>,
    value: u64,
    list: [Option<Output>; MAX_OUTPUTS],
}

impl<H: Hashes> OutputVisitor for Outputs<H> {
    fn value(&mut self, _: u64, value: u64) -> Result<()> {
        if value > MAX_MONEY {
            return Err(Error::BadAmount);
        }
        self.value = value;
        Ok(())
    }
    fn script_begin(&mut self, _: u64, len: u64) -> Result<()> {
        self.capture.begin(len);
        Ok(())
    }
    fn script_data(&mut self, _: u64, data: &[u8]) -> Result<()> {
        self.capture.update(data);
        Ok(())
    }
    fn end(&mut self, index: u64) -> Result<()> {
        let captured = self.capture.finish();
        let slot = self.list.get_mut(index as usize).ok_or(Error::BadLayout)?;
        *slot = Some(Output {
            value: self.value,
            script: captured.small,
            vault: captured.vault,
        });
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Inputs,
    Outputs,
    Ready,
    Reviewing,
    Approved,
}

/// What the user is asked to approve.
#[derive(Clone, Copy, Debug)]
pub struct Review {
    pub kind: Kind,
    /// The vault's script fingerprint (see `vault`).
    pub vault: [u8; 32],
    /// Deposit: the amount paid into the vault. Withdrawal: the amount paid to `destination`.
    pub amount: u64,
    /// Withdrawal only: the output script receiving `amount`.
    pub destination: Option<SmallScript>,
    pub fee: u64,
    /// Withdrawal only: the vault output being spent and the wallet's helper input.
    pub vault_value: u64,
    pub helper_value: u64,
    /// Deposit only: change returned to the wallet.
    pub change: u64,
    /// The fee is more than 10% of the value moved.
    pub high_fee: bool,
}

pub struct SignTx<H: Hashes> {
    start: Start,
    wallet: Wallet,
    inputs: [Input; MAX_INPUTS],
    begun: u8,
    done: u8,
    prev: Option<PrevTxParser<H>>,
    hash_prevouts: H::Sha256,
    hash_sequence: H::Sha256,
    hash_outputs: H::Sha256,
    outputs_parser: OutputsParser,
    outputs: Outputs<H>,
    vault: Option<([u8; 32], u64)>,
    phase: Phase,
    common: Option<Bip143Common>,
}

impl<H: Hashes> SignTx<H> {
    /// `wallet` must be the key derived from `start.path`.
    pub fn new(start: Start, wallet: Wallet) -> Self {
        SignTx {
            start,
            wallet,
            inputs: [Input::EMPTY; MAX_INPUTS],
            begun: 0,
            done: 0,
            prev: None,
            hash_prevouts: H::Sha256::new(),
            hash_sequence: H::Sha256::new(),
            hash_outputs: H::Sha256::new(),
            outputs_parser: OutputsParser::new(start.n_outputs as u64),
            outputs: Outputs {
                capture: ScriptCapture::new(),
                value: 0,
                list: [None; MAX_OUTPUTS],
            },
            vault: None,
            phase: Phase::Inputs,
            common: None,
        }
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// The path of the key that signs.
    pub fn path(&self) -> &Path {
        &self.start.path
    }

    /// The user approved the review; signatures can be collected.
    pub fn is_approved(&self) -> bool {
        self.phase == Phase::Approved
    }

    /// Every input the wallet signs has been signed.
    pub fn is_complete(&self) -> bool {
        self.phase == Phase::Approved
            && self.inputs[..self.start.n_inputs as usize]
                .iter()
                .all(|i| !i.ours || i.signed)
    }

    /// `INPUT`: `prev txid (32, internal order) || vout (4 LE) || sequence (4 LE)`.
    pub fn begin_input(&mut self, data: &[u8]) -> Result<()> {
        if self.phase != Phase::Inputs
            || self.begun != self.done
            || self.begun >= self.start.n_inputs
        {
            return Err(Error::BadState);
        }
        if data.len() != 40 {
            return Err(Error::BadLength);
        }
        let outpoint: [u8; 36] = data[..36].try_into().map_err(|_| Error::BadLength)?;
        let sequence = u32::from_le_bytes(data[36..40].try_into().map_err(|_| Error::BadLength)?);
        if self.inputs[..self.begun as usize]
            .iter()
            .any(|i| i.outpoint == outpoint)
        {
            return Err(Error::BadLayout);
        }
        let vout = u32::from_le_bytes(data[32..36].try_into().map_err(|_| Error::BadLength)?);
        self.hash_prevouts.update(&outpoint);
        self.hash_sequence.update(&data[36..40]);
        self.inputs[self.begun as usize] = Input {
            outpoint,
            sequence,
            ..Input::EMPTY
        };
        self.prev = Some(PrevTxParser::new(vout));
        self.begun += 1;
        Ok(())
    }

    /// `PREVTX`: the next bytes of the current input's previous transaction.
    pub fn prev_tx_chunk(&mut self, data: &[u8]) -> Result<()> {
        let parser = self.prev.as_mut().ok_or(Error::BadState)?;
        parser.feed(data)?;
        if !parser.is_done() {
            return Ok(());
        }
        let prev = self.prev.take().ok_or(Error::BadState)?.finish()?;
        let index = self.done as usize;
        let input = &mut self.inputs[index];
        if prev.txid[..] != input.outpoint[..32] {
            return Err(Error::TxidMismatch);
        }
        let ours = prev
            .script
            .small
            .map(|s| s.as_bytes() == self.wallet.script())
            .unwrap_or(false);
        match (self.start.kind, index) {
            (Kind::Deposit, _) | (Kind::Withdrawal, 0) => {
                if !ours {
                    return Err(Error::NotOwnInput);
                }
                input.ours = true;
            }
            (Kind::Withdrawal, _) => {
                let fingerprint = prev.script.vault.ok_or(Error::NotVault)?;
                self.vault = Some((fingerprint, prev.value));
            }
        }
        input.amount = prev.value;
        self.done += 1;
        if self.done == self.start.n_inputs {
            self.phase = Phase::Outputs;
        }
        Ok(())
    }

    /// `OUTPUTS`: the next bytes of the serialized outputs (without their count).
    pub fn outputs_chunk(&mut self, data: &[u8]) -> Result<()> {
        if self.phase != Phase::Outputs {
            return Err(Error::BadState);
        }
        let used = self.outputs_parser.feed(data, &mut self.outputs)?;
        if used != data.len() {
            return Err(Error::Parse);
        }
        self.hash_outputs.update(data);
        if self.outputs_parser.is_done() {
            self.phase = Phase::Ready;
        }
        Ok(())
    }

    /// Check the whole transaction and return what to show the user.
    pub fn finalize(&mut self) -> Result<Review> {
        if self.phase != Phase::Ready {
            return Err(Error::BadState);
        }
        let n_in = self.start.n_inputs as usize;
        let n_out = self.start.n_outputs as usize;
        let total_in = self.inputs[..n_in]
            .iter()
            .try_fold(0u64, |sum, i| {
                sum.checked_add(i.amount).filter(|&s| s <= MAX_MONEY)
            })
            .ok_or(Error::BadAmount)?;
        let mut outs = [None; MAX_OUTPUTS];
        for (slot, out) in outs.iter_mut().zip(self.outputs.list.iter()).take(n_out) {
            *slot = Some(out.ok_or(Error::BadState)?);
        }
        let total_out = outs[..n_out]
            .iter()
            .flatten()
            .try_fold(0u64, |sum, o| {
                sum.checked_add(o.value).filter(|&s| s <= MAX_MONEY)
            })
            .ok_or(Error::BadAmount)?;
        let fee = total_in
            .checked_sub(total_out)
            .filter(|&f| f > 0)
            .ok_or(Error::BadAmount)?;
        let first = outs[0].ok_or(Error::BadState)?;

        let review = match self.start.kind {
            Kind::Deposit => {
                let vault = first.vault.ok_or(Error::NotVault)?;
                if first.value == 0 {
                    return Err(Error::BadAmount);
                }
                let change = match outs[1] {
                    None => 0,
                    Some(o) => {
                        let to_wallet = o.script.map(|s| s.as_bytes() == self.wallet.script());
                        if to_wallet != Some(true) || o.value == 0 {
                            return Err(Error::BadLayout);
                        }
                        o.value
                    }
                };
                Review {
                    kind: Kind::Deposit,
                    vault,
                    amount: first.value,
                    destination: None,
                    fee,
                    vault_value: first.value,
                    helper_value: 0,
                    change,
                    high_fee: fee > first.value / 10,
                }
            }
            Kind::Withdrawal => {
                let (vault, vault_value) = self.vault.ok_or(Error::NotVault)?;
                let destination = first.script.ok_or(Error::UnsupportedOutput)?;
                if classify(destination.as_bytes()).is_none() {
                    return Err(Error::UnsupportedOutput);
                }
                Review {
                    kind: Kind::Withdrawal,
                    vault,
                    amount: first.value,
                    destination: Some(destination),
                    fee,
                    vault_value,
                    helper_value: self.inputs[0].amount,
                    change: 0,
                    high_fee: fee > total_in / 10,
                }
            }
        };

        let take =
            |h: &mut H::Sha256| finalize_double::<H>(core::mem::replace(h, H::Sha256::new()));
        self.common = Some(Bip143Common {
            version: self.start.version,
            hash_prevouts: take(&mut self.hash_prevouts),
            hash_sequence: take(&mut self.hash_sequence),
            hash_outputs: take(&mut self.hash_outputs),
            locktime: self.start.locktime,
        });
        self.phase = Phase::Reviewing;
        Ok(review)
    }

    /// Record the user's approval of the review `finalize` returned.
    pub fn approve(&mut self) -> Result<()> {
        if self.phase != Phase::Reviewing {
            return Err(Error::BadState);
        }
        self.phase = Phase::Approved;
        Ok(())
    }

    /// The SIGHASH_ALL digest for one of the wallet's inputs, once per input, after approval.
    pub fn sighash(&mut self, index: u8) -> Result<[u8; 32]> {
        let common = match (self.phase, self.common) {
            (Phase::Approved, Some(c)) => c,
            _ => return Err(Error::BadState),
        };
        let input = self.inputs[..self.start.n_inputs as usize]
            .get_mut(index as usize)
            .filter(|i| i.ours && !i.signed)
            .ok_or(Error::BadState)?;
        input.signed = true;
        Ok(p2wpkh_sighash_all::<H>(
            &common,
            &input.outpoint,
            &self.wallet.pkh,
            input.amount,
            input.sequence,
        ))
    }
}

/// Collects a sign-in message sent over several APDUs.
pub struct MessageCollector {
    pub path: Path,
    len: usize,
    got: usize,
    buf: [u8; crate::signin::MESSAGE_MAX],
}

impl MessageCollector {
    /// First chunk: `path || message length (2 BE) || message bytes…`.
    pub fn start(data: &[u8]) -> Result<Self> {
        let (path, rest) = path::parse(data)?;
        if rest.len() < 2 {
            return Err(Error::BadLength);
        }
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if len == 0 || len > crate::signin::MESSAGE_MAX {
            return Err(Error::BadMessage);
        }
        let mut c = MessageCollector {
            path,
            len,
            got: 0,
            buf: [0; crate::signin::MESSAGE_MAX],
        };
        c.push(&rest[2..])?;
        Ok(c)
    }

    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        if self.got + data.len() > self.len {
            return Err(Error::BadLength);
        }
        self.buf[self.got..self.got + data.len()].copy_from_slice(data);
        self.got += data.len();
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.got == self.len
    }

    pub fn message(&self) -> &[u8] {
        &self.buf[..self.got]
    }
}

//! Signing with a vault's deposit key: the sweep into the vault, and refunds.
//!
//! Every PQB vault has an ordinary P2WPKH deposit address whose key `dd` comes
//! from the vault seed (BIP "PQB-v1 derivation profile"). Any wallet can pay it;
//! the device then signs one of two transactions, every input of which spends
//! that address, each amount proven by its full previous transaction:
//!
//! - **Sweep**: exactly one output, paying this vault's own locking script (the
//!   device derives the script and compares its SHA-256). This is the vault's
//!   funding transaction, recorded before any signature leaves.
//! - **Refund**: one or two outputs to addresses the device can show; one may
//!   return change to the deposit address. A vault script can't be an output.
//!
//! The host streams: START, then per input its outpoint and sequence followed
//! by the previous transaction, then the serialized outputs, then REVIEW and one
//! SIGN per input.

use crate::amount::MAX_MONEY;
use crate::error::{Error, Result};
use crate::hash::{finalize_double, Hashes, Sha256};
use crate::pqb;
use crate::record::{Funding, Record, State};
use crate::script::{classify, p2wpkh, SmallScript};
use crate::sighash::{p2wpkh_sighash_all, Bip143Common};
use crate::tx::{OutputVisitor, OutputsParser, PrevTxParser, ScriptCapture};

/// Most inputs a sweep or refund may have.
pub const MAX_INPUTS: usize = 8;
pub const MAX_OUTPUTS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Sweep,
    Refund,
}

/// The `START` command.
#[derive(Clone, Copy, Debug)]
pub struct Start {
    pub kind: Kind,
    pub v: u32,
    pub version: u32,
    pub locktime: u32,
    pub n_inputs: u8,
    pub n_outputs: u8,
}

/// `kind (1) || v (4 BE) || version (4 LE) || locktime (4 LE) || inputs (1) || outputs (1)`.
pub fn parse_start(data: &[u8]) -> Result<Start> {
    if data.len() != 15 {
        return Err(Error::BadLength);
    }
    let kind = match data[0] {
        1 => Kind::Sweep,
        2 => Kind::Refund,
        _ => return Err(Error::BadLayout),
    };
    let v = pqb::parse_index(&data[1..5]).ok_or(Error::BadData)?;
    let start = Start {
        kind,
        v,
        version: u32::from_le_bytes(data[5..9].try_into().map_err(|_| Error::BadLength)?),
        locktime: u32::from_le_bytes(data[9..13].try_into().map_err(|_| Error::BadLength)?),
        n_inputs: data[13],
        n_outputs: data[14],
    };
    let outputs_ok = match kind {
        Kind::Sweep => start.n_outputs == 1,
        Kind::Refund => (1..=MAX_OUTPUTS as u8).contains(&start.n_outputs),
    };
    if !(1..=MAX_INPUTS as u8).contains(&start.n_inputs) || !outputs_ok {
        return Err(Error::BadLayout);
    }
    Ok(start)
}

#[derive(Clone, Copy)]
struct Input {
    outpoint: [u8; 36],
    sequence: u32,
    amount: u64,
    signed: bool,
}

impl Input {
    const EMPTY: Input = Input {
        outpoint: [0; 36],
        sequence: 0,
        amount: 0,
        signed: false,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    /// The script, when short enough to keep.
    pub script: Option<SmallScript>,
    /// SHA-256 of the script, when it has a vault script's length.
    pub vault_hash: Option<[u8; 32]>,
}

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
            vault_hash: captured.vault_hash,
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

/// One output as the review shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payee {
    pub value: u64,
    pub script: SmallScript,
    /// Returns to the vault's own deposit address.
    pub change: bool,
}

/// What the user is asked to approve.
#[derive(Clone, Copy, Debug)]
pub struct Review {
    pub kind: Kind,
    pub v: u32,
    /// Sweep: the amount paid into the vault. Refund: everything sent elsewhere.
    pub amount: u64,
    pub fee: u64,
    /// Refund only: the outputs, in order.
    pub payees: [Option<Payee>; MAX_OUTPUTS],
    /// The fee is more than 10% of the inputs.
    pub high_fee: bool,
}

/// The deposit key's public side, the vault this is for, and its script hash.
#[derive(Clone, Copy)]
pub struct DepositKey {
    pub pkh: [u8; 20],
    pub vault_script_hash: [u8; 32],
}

pub struct SignDeposit<H: Hashes> {
    start: Start,
    key: DepositKey,
    inputs: [Input; MAX_INPUTS],
    begun: u8,
    done: u8,
    prev: Option<PrevTxParser<H>>,
    hash_prevouts: H::Sha256,
    hash_sequence: H::Sha256,
    hash_outputs: H::Sha256,
    txid: H::Sha256,
    outputs_parser: OutputsParser,
    outputs: Outputs<H>,
    phase: Phase,
    common: Option<Bip143Common>,
    review: Option<Review>,
    tx_id: [u8; 32],
}

impl<H: Hashes> SignDeposit<H> {
    pub fn new(start: Start, key: DepositKey) -> Self {
        // The txid of the transaction being signed (legacy serialization; counts
        // are at most 8, so one CompactSize byte each).
        let mut txid = H::Sha256::new();
        txid.update(&start.version.to_le_bytes());
        txid.update(&[start.n_inputs]);
        SignDeposit {
            start,
            key,
            inputs: [Input::EMPTY; MAX_INPUTS],
            begun: 0,
            done: 0,
            prev: None,
            hash_prevouts: H::Sha256::new(),
            hash_sequence: H::Sha256::new(),
            hash_outputs: H::Sha256::new(),
            txid,
            outputs_parser: OutputsParser::new(start.n_outputs as u64),
            outputs: Outputs {
                capture: ScriptCapture::new(),
                value: 0,
                list: [None; MAX_OUTPUTS],
            },
            phase: Phase::Inputs,
            common: None,
            review: None,
            tx_id: [0; 32],
        }
    }

    pub fn start(&self) -> &Start {
        &self.start
    }

    pub fn is_approved(&self) -> bool {
        self.phase == Phase::Approved
    }

    pub fn is_complete(&self) -> bool {
        self.phase == Phase::Approved
            && self.inputs[..self.start.n_inputs as usize]
                .iter()
                .all(|i| i.signed)
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
        self.txid.update(&outpoint);
        self.txid.update(&[0x00]);
        self.txid.update(&data[36..40]);
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
        let input = &mut self.inputs[self.done as usize];
        if prev.txid[..] != input.outpoint[..32] {
            return Err(Error::TxidMismatch);
        }
        let ours = prev
            .script
            .small
            .is_some_and(|s| s.as_bytes() == p2wpkh(&self.key.pkh));
        if !ours {
            return Err(Error::NotOwnInput);
        }
        input.amount = prev.value;
        self.done += 1;
        if self.done == self.start.n_inputs {
            self.phase = Phase::Outputs;
            self.txid.update(&[self.start.n_outputs]);
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
        self.txid.update(data);
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
        let deposit = p2wpkh(&self.key.pkh);

        let mut payees = [None; MAX_OUTPUTS];
        let amount = match self.start.kind {
            Kind::Sweep => {
                let out = outs[0].ok_or(Error::BadState)?;
                if out.vault_hash != Some(self.key.vault_script_hash) {
                    return Err(Error::NotVault);
                }
                if out.value == 0 {
                    return Err(Error::BadAmount);
                }
                out.value
            }
            Kind::Refund => {
                let mut sent = 0;
                for (slot, out) in payees.iter_mut().zip(outs.iter().flatten()) {
                    let script = out.script.ok_or(Error::UnsupportedOutput)?;
                    if classify(script.as_bytes()).is_none() {
                        return Err(Error::UnsupportedOutput);
                    }
                    if out.value == 0 {
                        return Err(Error::BadAmount);
                    }
                    let change = script.as_bytes() == deposit;
                    if !change {
                        sent += out.value;
                    }
                    *slot = Some(Payee {
                        value: out.value,
                        script,
                        change,
                    });
                }
                // Something has to leave the deposit address.
                if sent == 0 {
                    return Err(Error::BadLayout);
                }
                sent
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
        self.txid.update(&self.start.locktime.to_le_bytes());
        self.tx_id = take(&mut self.txid);
        let review = Review {
            kind: self.start.kind,
            v: self.start.v,
            amount,
            fee,
            payees,
            high_fee: fee > total_in / 10,
        };
        self.review = Some(review);
        self.phase = Phase::Reviewing;
        Ok(review)
    }

    /// Sweep only, after `finalize`: the vault output this transaction creates.
    pub fn funding(&self) -> Result<Funding> {
        match (self.start.kind, self.review) {
            (Kind::Sweep, Some(review)) => Ok(Funding {
                txid: self.tx_id,
                vout: 0,
                value: review.amount,
                sweep_input: self.inputs[0].outpoint,
            }),
            _ => Err(Error::BadState),
        }
    }

    /// Whether one of this transaction's inputs spends `outpoint`.
    pub fn spends(&self, outpoint: &[u8; 36]) -> bool {
        self.inputs[..self.done as usize]
            .iter()
            .any(|i| i.outpoint == *outpoint)
    }

    /// Record the user's approval of the review `finalize` returned.
    pub fn approve(&mut self) -> Result<()> {
        if self.phase != Phase::Reviewing {
            return Err(Error::BadState);
        }
        self.phase = Phase::Approved;
        Ok(())
    }

    /// The SIGHASH_ALL digest for input `index`, once per input, after approval.
    pub fn sighash(&mut self, index: u8) -> Result<[u8; 32]> {
        let common = match (self.phase, self.common) {
            (Phase::Approved, Some(c)) => c,
            _ => return Err(Error::BadState),
        };
        let input = self.inputs[..self.start.n_inputs as usize]
            .get_mut(index as usize)
            .filter(|i| !i.signed)
            .ok_or(Error::BadState)?;
        input.signed = true;
        Ok(p2wpkh_sighash_all::<H>(
            &common,
            &input.outpoint,
            &self.key.pkh,
            input.amount,
            input.sequence,
        ))
    }
}

/// Whether a sweep may fund `record`'s vault, given what is recorded.
///
/// The vault must be allocated by this device and never disclosed. A vault takes
/// one funding: a sweep with a different txid is accepted only if it spends the
/// recorded sweep's input, so at most one of the two can ever confirm.
pub fn check_sweep<H: Hashes>(record: &Record, sweep: &SignDeposit<H>) -> Result<Funding> {
    if record.state != State::Allocated || record.disclosure.is_some() {
        return Err(Error::VaultState);
    }
    let funding = sweep.funding()?;
    match record.funding {
        None => Ok(funding),
        Some(f) if f.txid == funding.txid => Ok(funding),
        Some(f) if sweep.spends(&f.sweep_input) => Ok(funding),
        Some(_) => Err(Error::Conflict),
    }
}

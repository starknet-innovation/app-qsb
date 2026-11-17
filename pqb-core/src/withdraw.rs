//! A withdrawal from a PQB vault: one disclosure of its secrets and the ECDSA
//! co-signature, bound to one transaction (BIP "Disclosure requests and retries").
//!
//! A `PQB-v1` withdrawal has exactly one input, the vault output. The host sends
//! the transaction's fields and the requested indices (START), the full
//! previous transaction that created the vault output (PREVTX), and the
//! serialized outputs (OUTPUTS). From these the device itself builds
//!
//! ```text
//! T = version || 0x01 || outpoint || 0x00 || sequence || n_out || outputs || locktime
//! B = SHA256(T)
//! I = round0 (8 × u8) || round1 (9 × u8) || p0 || p1 || p2
//! D = SHA256("PQB-v1/reveal" || I || B)
//! z = SHA256d(version || 0x01 || outpoint || CompactSize(script) || script || sequence
//!             || n_out || outputs || locktime || 01000000)
//! ```
//!
//! `z` is the legacy SIGHASH_ALL digest of the vault input with the vault script
//! as scriptCode (it has no OP_CODESEPARATOR), which the co-signature signs.
//! The vault script reaches the sighash straight from the previous transaction's
//! output, and is accepted only if its SHA-256 is the script hash the device
//! derived for vault `v`, so it is never buffered.
//!
//! The device does not check the three PQB puzzle solutions: the release is
//! "classically bound, quantum-unverified" and the review says so.

use crate::amount::MAX_MONEY;
use crate::error::{Error, Result};
use crate::hash::{finalize_double, Hashes, Sha256};
use crate::pqb::{self, Vault, MENU_WIDTHS, PROFILE, ROUND0, ROUND1, TABLE};
use crate::record::{Disclosure, Funding, Record, Standing, State};
use crate::script::{classify, SmallScript};
use crate::sighash::SIGHASH_ALL;
use crate::tx::{OutputVisitor, OutputsParser, PrevTxParser, ScriptCapture};

pub const MAX_OUTPUTS: usize = 4;
pub const START_LEN: usize = 73;

/// What the host asks for: the transaction's fixed fields and the selection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request {
    pub v: u32,
    pub version: u32,
    /// prev txid (internal order) || vout (LE).
    pub outpoint: [u8; 36],
    pub sequence: u32,
    pub locktime: u32,
    pub n_outputs: u8,
    pub round0: [u8; ROUND0],
    pub round1: [u8; ROUND1],
    pub picks: [u8; 3],
}

impl Request {
    /// I, the selection as the digest encodes it.
    pub fn selection(&self) -> [u8; 20] {
        let mut i = [0u8; 20];
        i[..8].copy_from_slice(&self.round0);
        i[8..17].copy_from_slice(&self.round1);
        i[17..].copy_from_slice(&self.picks);
        i
    }

    pub fn vout(&self) -> u32 {
        u32::from_le_bytes([
            self.outpoint[32],
            self.outpoint[33],
            self.outpoint[34],
            self.outpoint[35],
        ])
    }
}

fn ascending_below(list: &[u8], bound: usize) -> bool {
    list.iter().all(|&i| (i as usize) < bound) && list.windows(2).all(|w| w[0] < w[1])
}

/// `v (4 BE) || version (4 LE) || prev txid (32) || vout (4 LE) || sequence (4 LE) ||
/// locktime (4 LE) || outputs (1) || round0 (8) || round1 (9) || picks (3)`.
///
/// Checked before any screen: exactly 8 and 9 indices below 109, strictly
/// ascending within each round, none in both; p0 below 12, p1 and p2 below 16.
pub fn parse_start(data: &[u8]) -> Result<Request> {
    if data.len() != START_LEN {
        return Err(Error::BadLength);
    }
    let v = pqb::parse_index(&data[..4]).ok_or(Error::BadData)?;
    let le = |r: core::ops::Range<usize>| -> Result<u32> {
        Ok(u32::from_le_bytes(
            data[r].try_into().map_err(|_| Error::BadLength)?,
        ))
    };
    let req = Request {
        v,
        version: le(4..8)?,
        outpoint: data[8..44].try_into().map_err(|_| Error::BadLength)?,
        sequence: le(44..48)?,
        locktime: le(48..52)?,
        n_outputs: data[52],
        round0: data[53..61].try_into().map_err(|_| Error::BadLength)?,
        round1: data[61..70].try_into().map_err(|_| Error::BadLength)?,
        picks: data[70..73].try_into().map_err(|_| Error::BadLength)?,
    };
    if !(1..=MAX_OUTPUTS as u8).contains(&req.n_outputs) {
        return Err(Error::BadLayout);
    }
    let picks_ok = req
        .picks
        .iter()
        .zip(MENU_WIDTHS.iter())
        .all(|(&p, &w)| (p as usize) < w);
    if !ascending_below(&req.round0, TABLE)
        || !ascending_below(&req.round1, TABLE)
        || req.round0.iter().any(|i| req.round1.contains(i))
        || !picks_ok
    {
        return Err(Error::BadData);
    }
    Ok(req)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    PrevTx,
    Outputs,
    Ready,
    Done,
}

struct Outputs<H: Hashes> {
    capture: ScriptCapture<H>,
    value: u64,
    list: [Option<(u64, Option<SmallScript>)>; MAX_OUTPUTS],
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
        let small = self.capture.finish().small;
        let slot = self.list.get_mut(index as usize).ok_or(Error::BadLayout)?;
        *slot = Some((self.value, small));
        Ok(())
    }
}

/// What the user is asked to authorize.
#[derive(Clone, Copy, Debug)]
pub struct Review {
    pub v: u32,
    pub outputs: [Option<(u64, SmallScript)>; MAX_OUTPUTS],
    pub fee: u64,
    pub vault_value: u64,
    pub high_fee: bool,
    pub binding: [u8; 32],
    pub digest: [u8; 32],
    /// The co-signature's message.
    pub sighash: [u8; 32],
    pub funding: Funding,
}

pub struct Withdraw<H: Hashes> {
    req: Request,
    script_hash: [u8; 32],
    phase: Phase,
    prev: Option<PrevTxParser<H>>,
    binding: H::Sha256,
    sighash: Option<H::Sha256>,
    vault_value: u64,
    outputs_parser: OutputsParser,
    outputs: Outputs<H>,
}

impl<H: Hashes> Withdraw<H> {
    /// `script_hash` is the one the device derived for vault `req.v`.
    pub fn new(req: Request, script_hash: [u8; 32]) -> Self {
        let mut binding = H::Sha256::new();
        binding.update(&req.version.to_le_bytes());
        binding.update(&[0x01]);
        binding.update(&req.outpoint);
        binding.update(&[0x00]);
        binding.update(&req.sequence.to_le_bytes());
        binding.update(&[req.n_outputs]);
        let mut sighash = H::Sha256::new();
        sighash.update(&req.version.to_le_bytes());
        sighash.update(&[0x01]);
        sighash.update(&req.outpoint);
        Withdraw {
            req,
            script_hash,
            phase: Phase::PrevTx,
            prev: Some(PrevTxParser::with_tee(req.vout(), sighash)),
            binding,
            sighash: None,
            vault_value: 0,
            outputs_parser: OutputsParser::new(req.n_outputs as u64),
            outputs: Outputs {
                capture: ScriptCapture::new(),
                value: 0,
                list: [None; MAX_OUTPUTS],
            },
        }
    }

    pub fn request(&self) -> &Request {
        &self.req
    }

    /// `PREVTX`: the next bytes of the transaction that created the vault output.
    pub fn prev_tx_chunk(&mut self, data: &[u8]) -> Result<()> {
        if self.phase != Phase::PrevTx {
            return Err(Error::BadState);
        }
        let parser = self.prev.as_mut().ok_or(Error::BadState)?;
        parser.feed(data)?;
        if !parser.is_done() {
            return Ok(());
        }
        let prev = self.prev.take().ok_or(Error::BadState)?.finish()?;
        if prev.txid[..] != self.req.outpoint[..32] {
            return Err(Error::TxidMismatch);
        }
        if prev.script.vault_hash != Some(self.script_hash) {
            return Err(Error::NotVault);
        }
        let mut sighash = prev.tee.ok_or(Error::BadState)?;
        sighash.update(&self.req.sequence.to_le_bytes());
        sighash.update(&[self.req.n_outputs]);
        self.sighash = Some(sighash);
        self.vault_value = prev.value;
        self.phase = Phase::Outputs;
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
        self.binding.update(data);
        if let Some(h) = self.sighash.as_mut() {
            h.update(data);
        }
        if self.outputs_parser.is_done() {
            self.phase = Phase::Ready;
        }
        Ok(())
    }

    /// Check the transaction and compute B, D and the co-signature's sighash.
    pub fn finalize(&mut self) -> Result<Review> {
        if self.phase != Phase::Ready {
            return Err(Error::BadState);
        }
        self.phase = Phase::Done;
        let mut outputs = [None; MAX_OUTPUTS];
        let mut total = 0u64;
        for (slot, out) in outputs
            .iter_mut()
            .zip(self.outputs.list.iter())
            .take(self.req.n_outputs as usize)
        {
            let (value, script) = out.ok_or(Error::BadState)?;
            let script = script.ok_or(Error::UnsupportedOutput)?;
            if classify(script.as_bytes()).is_none() {
                return Err(Error::UnsupportedOutput);
            }
            if value == 0 {
                return Err(Error::BadAmount);
            }
            total = total
                .checked_add(value)
                .filter(|&t| t <= MAX_MONEY)
                .ok_or(Error::BadAmount)?;
            *slot = Some((value, script));
        }
        let fee = self
            .vault_value
            .checked_sub(total)
            .filter(|&f| f > 0)
            .ok_or(Error::BadAmount)?;

        let locktime = self.req.locktime.to_le_bytes();
        let mut binding = core::mem::replace(&mut self.binding, H::Sha256::new());
        binding.update(&locktime);
        let binding = binding.finalize();
        let mut sighash = self.sighash.take().ok_or(Error::BadState)?;
        sighash.update(&locktime);
        sighash.update(&(SIGHASH_ALL as u32).to_le_bytes());
        let sighash = finalize_double::<H>(sighash);

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&self.req.outpoint[..32]);
        Ok(Review {
            v: self.req.v,
            outputs,
            fee,
            vault_value: self.vault_value,
            high_fee: fee > self.vault_value / 10,
            binding,
            digest: digest::<H>(&self.req.selection(), &binding),
            sighash,
            funding: Funding {
                txid,
                vout: self.req.vout(),
                value: self.vault_value,
                sweep_input: [0; 36],
            },
        })
    }
}

/// D = SHA256("PQB-v1/reveal" || I || B).
pub fn digest<H: Hashes>(selection: &[u8; 20], binding: &[u8; 32]) -> [u8; 32] {
    let mut h = H::Sha256::new();
    h.update(PROFILE);
    h.update(b"/reveal");
    h.update(selection);
    h.update(binding);
    h.finalize()
}

/// How a disclosure request meets the record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// An allocated vault's first disclosure.
    Fresh,
    /// The exact disclosure already recorded, after a timeout, crash or failed submission.
    Retry,
    /// No trustworthy history: allowed only on the emergency path, outside
    /// custody conformance. `retry` when this exact emergency disclosure is recorded.
    Emergency { retry: bool },
}

fn same_disclosure(d: &Disclosure, req: &Request, review: &Review) -> bool {
    d.round0 == req.round0
        && d.round1 == req.round1
        && d.picks == req.picks
        && d.binding == review.binding
        && d.digest == review.digest
}

/// Whether the device may release this disclosure, and on which path.
pub fn decide(
    standing: &Standing,
    root: &[u8; 32],
    script_hash: &[u8; 32],
    req: &Request,
    review: &Review,
) -> Result<Decision> {
    let r = match standing {
        Standing::NotAllocated | Standing::Reserved => return Err(Error::VaultState),
        Standing::NoHistory => return Ok(Decision::Emergency { retry: false }),
        Standing::Recorded(r) => r,
    };
    if r.root != *root || r.script_hash != *script_hash {
        return Err(Error::Conflict);
    }
    if let Some(f) = r.funding {
        if f.txid != review.funding.txid || f.vout != review.funding.vout {
            return Err(Error::Conflict);
        }
    }
    let same = r
        .disclosure
        .as_ref()
        .map(|d| same_disclosure(d, req, review));
    match (r.state, same) {
        (State::Retired, _) => Err(Error::VaultState),
        (State::Allocated, None) => Ok(Decision::Fresh),
        (State::Exposed, Some(true)) => Ok(Decision::Retry),
        (State::Unknown, None) => Ok(Decision::Emergency { retry: false }),
        (State::Unknown, Some(true)) => Ok(Decision::Emergency { retry: true }),
        _ => Err(Error::Conflict),
    }
}

/// The record to write, durably, before anything is released.
pub fn record_after(
    decision: Decision,
    existing: Option<&Record>,
    wallet: &[u8; 16],
    root: &[u8; 32],
    script_hash: &[u8; 32],
    req: &Request,
    review: &Review,
) -> Record {
    let emergency = matches!(decision, Decision::Emergency { .. });
    Record {
        wallet: *wallet,
        v: req.v,
        state: if emergency {
            State::Unknown
        } else {
            State::Exposed
        },
        emergency: emergency || existing.is_some_and(|r| r.emergency),
        root: *root,
        script_hash: *script_hash,
        funding: Some(existing.and_then(|r| r.funding).unwrap_or(review.funding)),
        disclosure: Some(Disclosure {
            round0: req.round0,
            round1: req.round1,
            picks: req.picks,
            binding: review.binding,
            digest: review.digest,
        }),
    }
}

/// Chunks REVEAL_READ returns, in order.
pub const CHUNKS: u8 = 5;

/// REVEAL_READ chunk `chunk` of an authorized disclosure, written to `out`
/// (at least 250 bytes). Returns its length.
///
/// ```text
/// 0: s[j] for the 8 round-0 indices          (8 × 20)
/// 1: w[j] for the first 5 round-1 indices    (5 × 32)
/// 2: w[j] for the last 4 round-1 indices     (4 × 32)
/// 3: len || g[p0] || len || g[p1] || len || g[p2]
/// 4: len || co-signature (DER || 0x01) || Q (33)
/// ```
pub fn read_chunk<H: Hashes>(
    vault: &Vault,
    req: &Request,
    cosig: &[u8],
    q: &[u8; 33],
    chunk: u8,
    out: &mut [u8],
) -> Result<usize> {
    let mut n = 0;
    let mut put = |data: &[u8], n: &mut usize| {
        out[*n..*n + data.len()].copy_from_slice(data);
        *n += data.len();
    };
    match chunk {
        0 => {
            for &j in &req.round0 {
                let mut s = vault.table_secret::<H>(j as usize);
                put(&s, &mut n);
                pqb::wipe(&mut s);
            }
        }
        1 | 2 => {
            let range = if chunk == 1 { 0..5 } else { 5..ROUND1 };
            for &j in &req.round1[range] {
                let mut w = vault.table_round1::<H>(j as usize);
                put(&w, &mut n);
                pqb::wipe(&mut w);
            }
        }
        3 => {
            let mut g = [0u8; 73];
            for (stage, &p) in req.picks.iter().enumerate() {
                let len = vault.menu_signature::<H>(stage, p as usize).write(&mut g);
                put(&[len as u8], &mut n);
                put(&g[..len], &mut n);
            }
            pqb::wipe(&mut g);
        }
        4 => {
            put(&[cosig.len() as u8], &mut n);
            put(cosig, &mut n);
            put(q, &mut n);
        }
        _ => return Err(Error::BadData),
    }
    Ok(n)
}

/// GET_COMMITMENTS: `v (4 BE) || start (1) || count (1)`, count 1..=12, in root order.
pub fn parse_commitments(data: &[u8]) -> Result<(u32, usize, usize)> {
    if data.len() != 6 {
        return Err(Error::BadLength);
    }
    let v = pqb::parse_index(&data[..4]).ok_or(Error::BadData)?;
    let (start, count) = (data[4] as usize, data[5] as usize);
    if count == 0 || count > 12 || start + count > pqb::COMMITMENTS {
        return Err(Error::BadData);
    }
    Ok((v, start, count))
}

/// MENU_POINTS stage `r`: `v (4 BE) || stage (1)`.
pub fn parse_menu_r(data: &[u8]) -> Result<(u32, usize)> {
    if data.len() != 5 {
        return Err(Error::BadLength);
    }
    let v = pqb::parse_index(&data[..4]).ok_or(Error::BadData)?;
    let stage = data[4] as usize;
    if stage >= pqb::STAGES {
        return Err(Error::BadData);
    }
    Ok((v, stage))
}

/// MENU_POINTS read: `v (4 BE) || stage (1) || variant (1) || start (1) || count (1)`, count 1..=7.
pub fn parse_menu_points(data: &[u8]) -> Result<(u32, usize, u8, usize, usize)> {
    if data.len() != 8 {
        return Err(Error::BadLength);
    }
    let v = pqb::parse_index(&data[..4]).ok_or(Error::BadData)?;
    let (stage, variant, start, count) = (
        data[4] as usize,
        data[5],
        data[6] as usize,
        data[7] as usize,
    );
    if stage >= pqb::STAGES
        || variant > 3
        || count == 0
        || count > 7
        || start + count > MENU_WIDTHS[stage]
    {
        return Err(Error::BadData);
    }
    Ok((v, stage, variant, start, count))
}

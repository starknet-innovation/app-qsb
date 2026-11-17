use std::vec;
use std::vec::Vec;

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    absolute, transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};

use super::support::{test_seed, vault};
use crate::deposit::{check_sweep, parse_start, DepositKey, Kind, Review, SignDeposit};
use crate::error::Error;
use crate::hash::hash160;
use crate::hash::soft::Soft;
use crate::pqb::Curve;
use crate::record::{Funding, Record, State};
use crate::script::p2wpkh;

/// The legacy serialization the app expects for previous transactions.
pub fn stripped(tx: &Transaction) -> Vec<u8> {
    let mut t = tx.clone();
    for input in &mut t.input {
        input.witness = Witness::new();
    }
    serialize(&t)
}

/// A SegWit transaction from an arbitrary outpoint, paying `value` to `script` at output 0.
pub fn funding_tx(script: &[u8], value: u64) -> Transaction {
    funding_tx_n(script, value, 0)
}

pub fn funding_tx_n(script: &[u8], value: u64, salt: u8) -> Transaction {
    Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([salt.wrapping_add(0x5a); 32]),
                vout: 3,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
            },
            TxOut {
                value: Amount::from_sat(777),
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x00, 0x14, salt, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19,
                ]),
            },
        ],
    }
}

pub fn input(prev: &Transaction, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: prev.compute_txid(),
            vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

pub fn out(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
    }
}

struct Fixture {
    key: DepositKey,
    deposit: Vec<u8>,
    script: Vec<u8>,
}

fn fixture() -> Fixture {
    let v = vault(test_seed());
    let pubkey = super::support::SoftCurve::pubkey(&v.deposit_key::<Soft>());
    let pkh = hash160::<Soft>(&pubkey);
    let mut script = Vec::new();
    v.script_into::<Soft>(|b| script.extend_from_slice(b));
    Fixture {
        key: DepositKey {
            pkh,
            vault_script_hash: v.script_hash::<Soft>(),
        },
        deposit: p2wpkh(&pkh).to_vec(),
        script,
    }
}

fn start_bytes(kind: u8, v: u32, tx: &Transaction) -> Vec<u8> {
    let mut b = vec![kind];
    b.extend_from_slice(&v.to_be_bytes());
    b.extend_from_slice(&(tx.version.0 as u32).to_le_bytes());
    b.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    b.push(tx.input.len() as u8);
    b.push(tx.output.len() as u8);
    b
}

/// Stream `tx` through a session, `chunk` bytes at a time, and return the review.
fn stream(
    kind: Kind,
    key: DepositKey,
    tx: &Transaction,
    prevs: &[&Transaction],
    chunk: usize,
) -> Result<(SignDeposit<Soft>, Review), Error> {
    let k = if kind == Kind::Sweep { 1 } else { 2 };
    let start = parse_start(&start_bytes(k, 3, tx))?;
    let mut s = SignDeposit::<Soft>::new(start, key);
    for (input, prev) in tx.input.iter().zip(prevs) {
        let mut header = input.previous_output.txid.to_byte_array().to_vec();
        header.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        header.extend_from_slice(&input.sequence.0.to_le_bytes());
        s.begin_input(&header)?;
        for c in stripped(prev).chunks(chunk) {
            s.prev_tx_chunk(c)?;
        }
    }
    let outputs: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
    for c in outputs.chunks(chunk) {
        s.outputs_chunk(c)?;
    }
    let review = s.finalize()?;
    Ok((s, review))
}

fn reference_sighash(tx: &Transaction, index: usize, pkh: &[u8; 20], amount: u64) -> [u8; 32] {
    let spk = ScriptBuf::from_bytes(p2wpkh(pkh).to_vec());
    SighashCache::new(tx)
        .p2wpkh_signature_hash(index, &spk, Amount::from_sat(amount), EcdsaSighashType::All)
        .unwrap()
        .to_byte_array()
}

fn sweep_tx(f: &Fixture, values: &[u64], fee: u64) -> (Transaction, Vec<Transaction>) {
    let prevs: Vec<Transaction> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| funding_tx_n(&f.deposit, v, i as u8))
        .collect();
    let total: u64 = values.iter().sum();
    let tx = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: prevs.iter().map(|p| input(p, 0)).collect(),
        output: vec![out(total - fee, &f.script)],
    };
    (tx, prevs)
}

#[test]
fn sweep_signs_every_input_like_rust_bitcoin() {
    let f = fixture();
    let (tx, prevs) = sweep_tx(&f, &[60_000, 50_000], 15_000);
    for chunk in [1usize, 13, 250, 10_000] {
        let refs: Vec<&Transaction> = prevs.iter().collect();
        let (mut s, review) = stream(Kind::Sweep, f.key, &tx, &refs, chunk).unwrap();
        assert_eq!(review.kind, Kind::Sweep);
        assert_eq!(review.amount, 95_000);
        assert_eq!(review.fee, 15_000);
        assert!(review.high_fee);
        let funding = s.funding().unwrap();
        assert_eq!(funding.txid, tx.compute_txid().to_byte_array());
        assert_eq!(funding.vout, 0);
        assert_eq!(funding.value, 95_000);
        assert!(s.sighash(0).is_err(), "nothing signs before approval");
        s.approve().unwrap();
        for (i, p) in prevs.iter().enumerate() {
            let want = reference_sighash(&tx, i, &f.key.pkh, p.output[0].value.to_sat());
            assert_eq!(s.sighash(i as u8).unwrap(), want);
            assert_eq!(s.sighash(i as u8), Err(Error::BadState), "once per input");
        }
        assert!(s.is_complete());
    }
}

#[test]
fn sweep_refusals() {
    let f = fixture();
    let refs = |p: &Vec<Transaction>| p.to_vec();

    // Paying another vault (another seed's script) is refused.
    let other = {
        let v = vault([9; 32]);
        let mut s = Vec::new();
        v.script_into::<Soft>(|b| s.extend_from_slice(b));
        s
    };
    let (mut tx, prevs) = sweep_tx(&f, &[60_000], 1_000);
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(other);
    let p = refs(&prevs);
    assert_eq!(
        stream(Kind::Sweep, f.key, &tx, &[&p[0]], 50).err(),
        Some(Error::NotVault)
    );
    // A standard address isn't a sweep.
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(f.deposit.clone());
    assert_eq!(
        stream(Kind::Sweep, f.key, &tx, &[&p[0]], 50).err(),
        Some(Error::NotVault)
    );

    // An input that isn't the deposit address.
    let (tx, mut prevs) = sweep_tx(&f, &[60_000], 1_000);
    prevs[0] = funding_tx(
        &[
            0x00, 0x14, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        ],
        60_000,
    );
    let mut tx2 = tx.clone();
    tx2.input[0] = input(&prevs[0], 0);
    assert_eq!(
        stream(Kind::Sweep, f.key, &tx2, &[&prevs[0]], 50).err(),
        Some(Error::NotOwnInput)
    );

    // A previous transaction that isn't the outpoint's.
    let (tx, prevs) = sweep_tx(&f, &[60_000], 1_000);
    let wrong = funding_tx_n(&f.deposit, 60_000, 77);
    assert_eq!(
        stream(Kind::Sweep, f.key, &tx, &[&wrong], 50).err(),
        Some(Error::TxidMismatch)
    );
    // Zero or negative fee.
    let (mut tx, _) = sweep_tx(&f, &[60_000], 1);
    tx.output[0].value = Amount::from_sat(60_000);
    assert_eq!(
        stream(Kind::Sweep, f.key, &tx, &[&prevs[0]], 50).err(),
        Some(Error::BadAmount)
    );
    // Layouts.
    assert_eq!(
        parse_start(&[1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2]).err(),
        Some(Error::BadLayout)
    );
    assert_eq!(
        parse_start(&[1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 9, 1]).err(),
        Some(Error::BadLayout)
    );
    assert_eq!(
        parse_start(&[1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1]).err(),
        Some(Error::BadLayout)
    );
    assert_eq!(
        parse_start(&[3, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1]).err(),
        Some(Error::BadLayout)
    );
    assert_eq!(
        parse_start(&[1, 0x80, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1]).err(),
        Some(Error::BadData)
    );
    assert_eq!(parse_start(&[1, 0, 0, 0, 0]).err(), Some(Error::BadLength));
}

#[test]
fn refund_with_change() {
    let f = fixture();
    let prev = funding_tx(&f.deposit, 80_000);
    let dest = [
        0x51, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    let tx = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(&prev, 0)],
        output: vec![out(30_000, &dest), out(49_000, &f.deposit)],
    };
    let (mut s, review) = stream(Kind::Refund, f.key, &tx, &[&prev], 7).unwrap();
    assert_eq!(review.amount, 30_000);
    assert_eq!(review.fee, 1_000);
    assert!(!review.high_fee);
    let p0 = review.payees[0].unwrap();
    let p1 = review.payees[1].unwrap();
    assert!(!p0.change && p0.script.as_bytes() == dest);
    assert!(p1.change && p1.value == 49_000);
    assert_eq!(
        s.funding().err(),
        Some(Error::BadState),
        "a refund funds nothing"
    );
    s.approve().unwrap();
    assert_eq!(
        s.sighash(0).unwrap(),
        reference_sighash(&tx, 0, &f.key.pkh, 80_000)
    );

    // Everything back to the deposit address moves nothing: refused.
    let mut back = tx.clone();
    back.output = vec![out(79_000, &f.deposit)];
    assert_eq!(
        stream(Kind::Refund, f.key, &back, &[&prev], 7).err(),
        Some(Error::BadLayout)
    );
    // The vault script can't be a refund output.
    let mut to_vault = tx.clone();
    to_vault.output = vec![out(79_000, &f.script)];
    assert_eq!(
        stream(Kind::Refund, f.key, &to_vault, &[&prev], 7).err(),
        Some(Error::UnsupportedOutput)
    );
    // Neither can OP_RETURN.
    let mut op_return = tx.clone();
    op_return.output = vec![out(79_000, &[0x6a, 0x01, 0x00])];
    assert_eq!(
        stream(Kind::Refund, f.key, &op_return, &[&prev], 7).err(),
        Some(Error::UnsupportedOutput)
    );
}

#[test]
fn commands_out_of_order() {
    let f = fixture();
    let (tx, prevs) = sweep_tx(&f, &[60_000], 1_000);
    let start = parse_start(&start_bytes(1, 0, &tx)).unwrap();
    let mut s = SignDeposit::<Soft>::new(start, f.key);
    assert_eq!(s.prev_tx_chunk(&[0]), Err(Error::BadState));
    assert_eq!(s.outputs_chunk(&[0]), Err(Error::BadState));
    assert_eq!(s.finalize().err(), Some(Error::BadState));
    assert_eq!(s.approve(), Err(Error::BadState));
    let mut header = tx.input[0].previous_output.txid.to_byte_array().to_vec();
    header.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    s.begin_input(&header).unwrap();
    assert_eq!(
        s.begin_input(&header),
        Err(Error::BadState),
        "previous tx first"
    );
    for c in stripped(&prevs[0]).chunks(100) {
        s.prev_tx_chunk(c).unwrap();
    }
    assert_eq!(
        s.begin_input(&header),
        Err(Error::BadState),
        "only one input"
    );
}

fn record(state: State, funding: Option<Funding>) -> Record {
    Record {
        wallet: [1; 16],
        v: 3,
        state,
        emergency: false,
        root: [2; 32],
        script_hash: [3; 32],
        funding,
        disclosure: None,
    }
}

#[test]
fn one_funding_per_vault() {
    let f = fixture();
    let (tx, prevs) = sweep_tx(&f, &[60_000, 40_000], 1_000);
    let refs: Vec<&Transaction> = prevs.iter().collect();
    let (s, _) = stream(Kind::Sweep, f.key, &tx, &refs, 250).unwrap();
    let funding = s.funding().unwrap();

    assert_eq!(
        check_sweep(&record(State::Allocated, None), &s),
        Ok(funding)
    );
    // The same sweep again: fine.
    assert_eq!(
        check_sweep(&record(State::Allocated, Some(funding)), &s),
        Ok(funding)
    );
    // Another sweep that spends the recorded sweep's input: they conflict, fine.
    let replaced = Funding {
        txid: [9; 32],
        ..funding
    };
    assert_eq!(
        check_sweep(&record(State::Allocated, Some(replaced)), &s),
        Ok(funding)
    );
    // A sweep that could confirm alongside the recorded one: refused.
    let unrelated = Funding {
        txid: [9; 32],
        sweep_input: [7; 36],
        ..funding
    };
    assert_eq!(
        check_sweep(&record(State::Allocated, Some(unrelated)), &s),
        Err(Error::Conflict)
    );
    for state in [State::Exposed, State::Retired, State::Unknown] {
        assert_eq!(
            check_sweep(&record(state, None), &s),
            Err(Error::VaultState)
        );
    }
}

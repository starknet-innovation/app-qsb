use std::vec;
use std::vec::Vec;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    absolute, transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use k256::ecdsa::signature::hazmat::PrehashVerifier;

use crate::error::Error;
use crate::hash::soft::Soft;
use crate::path::{AddressType, HARDENED};
use crate::session::{parse_start, Kind, Review, SignTx};
use crate::wallet::Wallet;

fn tx(name: &str) -> Transaction {
    let text = match name {
        "deposit" => include_str!("../../../tests/fixtures/mainnet-deposit.hex"),
        "deposit-prev" => include_str!("../../../tests/fixtures/mainnet-deposit-prev.hex"),
        "withdrawal" => include_str!("../../../tests/fixtures/mainnet-withdrawal.hex"),
        _ => unreachable!(),
    };
    deserialize(&hex::decode(text.trim()).unwrap()).unwrap()
}

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

fn funding_tx_n(script: &[u8], value: u64, salt: u8) -> Transaction {
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

fn start_bytes(kind: u8, address_type: AddressType, tx: &Transaction) -> Vec<u8> {
    let purpose = if address_type == AddressType::P2wpkh {
        84
    } else {
        49
    };
    let mut v = vec![kind, 5];
    for e in [purpose | HARDENED, HARDENED, HARDENED, 0, 7] {
        v.extend_from_slice(&e.to_be_bytes());
    }
    v.extend_from_slice(&(tx.version.0 as u32).to_le_bytes());
    v.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    v.push(tx.input.len() as u8);
    v.push(tx.output.len() as u8);
    v
}

/// Stream `tx` through a session, `chunk` bytes at a time, and return the review.
fn stream(
    kind: Kind,
    wallet: Wallet,
    tx: &Transaction,
    prevs: &[&Transaction],
    chunk: usize,
) -> Result<(SignTx<Soft>, Review), Error> {
    let kind_byte = if kind == Kind::Deposit { 1 } else { 2 };
    let start = parse_start(&start_bytes(kind_byte, wallet.address_type, tx))?;
    assert_eq!(start.path.address_type(), wallet.address_type);
    let mut s = SignTx::<Soft>::new(start, wallet);
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

fn reference_sighash(tx: &Transaction, index: usize, wallet: &Wallet, amount: u64) -> [u8; 32] {
    let spk = ScriptBuf::from_bytes(crate::script::p2wpkh(&wallet.pkh).to_vec());
    SighashCache::new(tx)
        .p2wpkh_signature_hash(index, &spk, Amount::from_sat(amount), EcdsaSighashType::All)
        .unwrap()
        .to_byte_array()
}

/// Check the signature already on chain for `index` against our digest.
fn verify_onchain(tx: &Transaction, index: usize, digest: &[u8; 32]) {
    let witness = &tx.input[index].witness;
    let sig = witness.nth(0).unwrap();
    assert_eq!(*sig.last().unwrap(), 0x01);
    let sig = k256::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(witness.nth(1).unwrap()).unwrap();
    key.verify_prehash(digest, &sig).unwrap();
}

fn witness_wallet(tx: &Transaction, index: usize) -> Wallet {
    Wallet::new::<Soft>(
        tx.input[index].witness.nth(1).unwrap().try_into().unwrap(),
        AddressType::P2wpkh,
    )
}

const MAINNET_VAULT: &str = "5f7a0bc1bf0fa932d95ad2dd9b60104dbbebb1f7b42ee5f1f2d58c344525290e";

#[test]
fn mainnet_withdrawal() {
    let withdrawal = tx("withdrawal");
    let deposit = tx("deposit");
    let wallet = witness_wallet(&withdrawal, 0);
    assert_eq!(
        hex::encode(wallet.script()),
        "0014ad2ecdfc574f02426f3ce4ec183bd998a0dd24fd"
    );
    for chunk in [1, 13, 255] {
        let (mut s, review) = stream(
            Kind::Withdrawal,
            wallet,
            &withdrawal,
            &[&deposit, &deposit],
            chunk,
        )
        .unwrap();
        assert_eq!(review.kind, Kind::Withdrawal);
        assert_eq!(hex::encode(review.vault), MAINNET_VAULT);
        assert_eq!(review.vault_value, 100_000);
        assert_eq!(review.helper_value, 1_449);
        assert_eq!(review.amount, 92_083);
        assert_eq!(review.fee, 9_366);
        assert!(!review.high_fee);
        assert_eq!(review.destination.unwrap().as_bytes(), wallet.script());

        assert_eq!(s.sighash(0), Err(Error::BadState), "not before approval");
        s.approve().unwrap();
        assert_eq!(
            s.sighash(1),
            Err(Error::BadState),
            "the vault input is not ours"
        );
        let digest = s.sighash(0).unwrap();
        assert_eq!(digest, reference_sighash(&withdrawal, 0, &wallet, 1_449));
        verify_onchain(&withdrawal, 0, &digest);
        assert_eq!(s.sighash(0), Err(Error::BadState), "each input once");
    }
}

#[test]
fn mainnet_deposit() {
    let deposit = tx("deposit");
    let prev = tx("deposit-prev");
    let wallet = witness_wallet(&deposit, 0);
    let (mut s, review) = stream(Kind::Deposit, wallet, &deposit, &[&prev], 255).unwrap();
    assert_eq!(review.kind, Kind::Deposit);
    assert_eq!(hex::encode(review.vault), MAINNET_VAULT);
    assert_eq!(review.amount, 100_000);
    assert_eq!(review.change, 1_449);
    assert_eq!(review.fee, 70_308);
    assert!(review.high_fee);
    assert!(review.destination.is_none());
    s.approve().unwrap();
    let amount = prev.output[deposit.input[0].previous_output.vout as usize]
        .value
        .to_sat();
    let digest = s.sighash(0).unwrap();
    assert_eq!(digest, reference_sighash(&deposit, 0, &wallet, amount));
    verify_onchain(&deposit, 0, &digest);
}

fn key(seed: u8) -> (k256::ecdsa::SigningKey, [u8; 33]) {
    let k = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let pubkey = k
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    (k, pubkey)
}

fn input(prev: &Transaction, vout: u32, sequence: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: prev.compute_txid(),
            vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(sequence),
        witness: Witness::new(),
    }
}

fn out(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
    }
}

fn vault() -> Vec<u8> {
    super::vault::script("seed2")
}

/// A three-input nested-SegWit deposit with change.
fn nested_deposit() -> (Wallet, Transaction, Vec<Transaction>) {
    let (_, pubkey) = key(3);
    let wallet = Wallet::new::<Soft>(pubkey, AddressType::P2shP2wpkh);
    let prevs: Vec<Transaction> = (0..3)
        .map(|i| funding_tx_n(wallet.script(), 40_000 + i as u64, i))
        .collect();
    let deposit = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: prevs.iter().map(|p| input(p, 0, 0xffff_fffe)).collect(),
        output: vec![out(100_000, &vault()), out(19_000, wallet.script())],
    };
    (wallet, deposit, prevs)
}

#[test]
fn nested_segwit_deposit_matches_rust_bitcoin() {
    let (wallet, deposit, prevs) = nested_deposit();
    let refs: Vec<&Transaction> = prevs.iter().collect();
    let (mut s, review) = stream(Kind::Deposit, wallet, &deposit, &refs, 255).unwrap();
    assert_eq!(review.amount, 100_000);
    assert_eq!(review.change, 19_000);
    assert_eq!(review.fee, 120_003 - 119_000);
    assert!(!review.high_fee);
    s.approve().unwrap();
    for i in 0..3u8 {
        assert_eq!(
            s.sighash(i).unwrap(),
            reference_sighash(&deposit, i as usize, &wallet, 40_000 + i as u64)
        );
    }
    assert_eq!(s.sighash(3), Err(Error::BadState));
}

#[test]
fn deposit_refusals() {
    let (wallet, deposit, prevs) = nested_deposit();
    let refs: Vec<&Transaction> = prevs.iter().collect();
    let other = Wallet::new::<Soft>(key(4).1, AddressType::P2shP2wpkh);

    // Inputs must all be the wallet's.
    let err = stream(Kind::Deposit, other, &deposit, &refs, 255).err();
    assert_eq!(err, Some(Error::NotOwnInput));

    // A previous transaction that isn't the outpoint's.
    let swapped = [refs[1], refs[0], refs[2]];
    assert_eq!(
        stream(Kind::Deposit, wallet, &deposit, &swapped, 255).err(),
        Some(Error::TxidMismatch)
    );

    // Output 0 must be a vault.
    let mut t = deposit.clone();
    t.output[0] = out(
        100_000,
        &[
            0x00, 0x14, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        ],
    );
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &refs, 255).err(),
        Some(Error::NotVault)
    );

    // A vault with one fixed byte changed is not a vault.
    let mut forged = vault();
    forged[5000 - 1] ^= 0x80;
    t.output[0] = out(100_000, &forged);
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &refs, 255).err(),
        Some(Error::NotVault)
    );

    // Change must return to the wallet.
    let mut t = deposit.clone();
    t.output[1] = out(19_000, other.script());
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &refs, 255).err(),
        Some(Error::BadLayout)
    );

    // Outputs above the inputs: no positive fee.
    let mut t = deposit.clone();
    t.output[1] = out(20_003, wallet.script());
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &refs, 255).err(),
        Some(Error::BadAmount)
    );

    // The same outpoint twice.
    let mut t = deposit.clone();
    t.input[1] = t.input[0].clone();
    let dup = [refs[0], refs[0], refs[2]];
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &dup, 255).err(),
        Some(Error::BadLayout)
    );

    // Declared as a withdrawal, a three-input transaction is refused outright.
    assert_eq!(
        stream(Kind::Withdrawal, wallet, &deposit, &refs, 255).err(),
        Some(Error::BadLayout)
    );
}

/// A withdrawal of a synthetic vault deposit, the helper being another wallet UTXO.
fn withdrawal(
    destination: &[u8],
    value: u64,
    vault_script: &[u8],
) -> (Wallet, Transaction, Transaction, Transaction) {
    let (_, pubkey) = key(5);
    let wallet = Wallet::new::<Soft>(pubkey, AddressType::P2wpkh);
    let helper_prev = funding_tx_n(wallet.script(), 2_000, 1);
    let vault_prev = funding_tx_n(vault_script, 50_000, 2);
    let t = Transaction {
        version: transaction::Version(1),
        lock_time: absolute::LockTime::from_consensus(950_229_240),
        input: vec![
            input(&helper_prev, 0, 0xffff_fffe),
            input(&vault_prev, 0, 0x8000_07a1),
        ],
        output: vec![out(value, destination)],
    };
    (wallet, t, helper_prev, vault_prev)
}

#[test]
fn withdrawal_to_each_address_type() {
    let p2tr = [vec![0x51, 0x20], vec![7u8; 32]].concat();
    let p2wsh = [vec![0x00, 0x20], vec![8u8; 32]].concat();
    let p2pkh = [vec![0x76, 0xa9, 0x14], vec![9u8; 20], vec![0x88, 0xac]].concat();
    let p2sh = [vec![0xa9, 0x14], vec![10u8; 20], vec![0x87]].concat();
    for dest in [p2tr, p2wsh, p2pkh, p2sh] {
        let (wallet, t, helper, vault_prev) = withdrawal(&dest, 46_000, &vault());
        let (mut s, review) =
            stream(Kind::Withdrawal, wallet, &t, &[&helper, &vault_prev], 255).unwrap();
        assert_eq!(review.destination.unwrap().as_bytes(), &dest[..]);
        assert_eq!(review.fee, 6_000);
        assert_eq!(review.vault, crate::hash::sha256::<Soft>(&vault()));
        assert!(review.high_fee, "6,000 of 52,000 is above 10%");
        s.approve().unwrap();
        assert_eq!(
            s.sighash(0).unwrap(),
            reference_sighash(&t, 0, &wallet, 2_000)
        );
    }
}

#[test]
fn withdrawal_refusals() {
    let dest = [vec![0x51, 0x20], vec![7u8; 32]].concat();

    // Input 1 must spend a vault.
    let not_vault = [vec![0x00, 0x14], vec![1u8; 20]].concat();
    let (wallet, t, helper, prev) = withdrawal(&dest, 46_000, &not_vault);
    assert_eq!(
        stream(Kind::Withdrawal, wallet, &t, &[&helper, &prev], 255).err(),
        Some(Error::NotVault)
    );

    // Input 0 must be the wallet's.
    let (wallet, t, helper, prev) = withdrawal(&dest, 46_000, &vault());
    let other = Wallet::new::<Soft>(key(6).1, AddressType::P2wpkh);
    assert_eq!(
        stream(Kind::Withdrawal, other, &t, &[&helper, &prev], 255).err(),
        Some(Error::NotOwnInput)
    );

    // Inputs in the other order.
    let mut swapped = t.clone();
    swapped.input.swap(0, 1);
    assert_eq!(
        stream(Kind::Withdrawal, wallet, &swapped, &[&prev, &helper], 255).err(),
        Some(Error::NotOwnInput)
    );

    // Destinations that can't be shown as an address.
    for script in [
        vec![0x6a, 0x01, 0x00],
        [vec![0x52, 0x20], vec![7u8; 32]].concat(),
        vault(),
    ] {
        let (wallet, t, helper, prev) = withdrawal(&script, 46_000, &vault());
        assert_eq!(
            stream(Kind::Withdrawal, wallet, &t, &[&helper, &prev], 255).err(),
            Some(Error::UnsupportedOutput)
        );
    }

    // Paying out more than the inputs.
    let (wallet, t, helper, prev) = withdrawal(&dest, 52_000, &vault());
    assert_eq!(
        stream(Kind::Withdrawal, wallet, &t, &[&helper, &prev], 255).err(),
        Some(Error::BadAmount)
    );
}

#[test]
fn commands_out_of_order() {
    let (wallet, t, helper, _) = withdrawal(
        &[vec![0x51, 0x20], vec![7u8; 32]].concat(),
        46_000,
        &vault(),
    );
    let start = parse_start(&start_bytes(2, AddressType::P2wpkh, &t)).unwrap();
    let mut s = SignTx::<Soft>::new(start, wallet);
    assert_eq!(s.outputs_chunk(&[0; 8]), Err(Error::BadState));
    assert_eq!(s.prev_tx_chunk(&[0; 8]), Err(Error::BadState));
    assert_eq!(s.finalize().err(), Some(Error::BadState));
    assert_eq!(s.approve(), Err(Error::BadState));
    let mut header = t.input[0].previous_output.txid.to_byte_array().to_vec();
    header.extend_from_slice(&[0, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff]);
    s.begin_input(&header).unwrap();
    // The next input can't start before this previous transaction is complete.
    assert_eq!(s.begin_input(&header), Err(Error::BadState));
    let prev = stripped(&helper);
    s.prev_tx_chunk(&prev[..10]).unwrap();
    assert_eq!(s.begin_input(&header), Err(Error::BadState));
    s.prev_tx_chunk(&prev[10..]).unwrap();
    // Extra bytes after a complete previous transaction.
    assert_eq!(s.prev_tx_chunk(&[0]), Err(Error::BadState));
}

#[test]
fn start_layouts() {
    let (_, t, _, _) = withdrawal(&[0x51; 34], 1, &vault());
    let mut bytes = start_bytes(2, AddressType::P2wpkh, &t);
    assert!(parse_start(&bytes).is_ok());
    let n = bytes.len();
    bytes[n - 2] = 3; // a withdrawal has two inputs
    assert_eq!(parse_start(&bytes).err(), Some(Error::BadLayout));
    bytes[0] = 1; // a deposit may have up to 8
    assert!(parse_start(&bytes).is_ok());
    bytes[n - 2] = 9;
    assert_eq!(parse_start(&bytes).err(), Some(Error::BadLayout));
    bytes[n - 2] = 1;
    bytes[n - 1] = 3; // and up to 2 outputs
    assert_eq!(parse_start(&bytes).err(), Some(Error::BadLayout));
    bytes[n - 1] = 1;
    assert_eq!(parse_start(&bytes[..n - 1]).err(), Some(Error::BadLength));
    bytes[0] = 3; // no such kind
    assert_eq!(parse_start(&bytes).err(), Some(Error::BadLayout));
}

/// Stream with chunk sizes drawn from a seeded generator, so boundaries fall everywhere.
fn stream_random(
    kind: Kind,
    wallet: Wallet,
    tx: &Transaction,
    prevs: &[&Transaction],
    seed: u64,
) -> Result<Review, Error> {
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        1 + (state % 255) as usize
    };
    let kind_byte = if kind == Kind::Deposit { 1 } else { 2 };
    let mut s = SignTx::<Soft>::new(
        parse_start(&start_bytes(kind_byte, wallet.address_type, tx))?,
        wallet,
    );
    let mut feed =
        |data: &[u8], f: &mut dyn FnMut(&[u8]) -> Result<(), Error>| -> Result<(), Error> {
            let mut pos = 0;
            while pos < data.len() {
                let end = (pos + next()).min(data.len());
                f(&data[pos..end])?;
                pos = end;
            }
            Ok(())
        };
    for (input, prev) in tx.input.iter().zip(prevs) {
        let mut header = input.previous_output.txid.to_byte_array().to_vec();
        header.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        header.extend_from_slice(&input.sequence.0.to_le_bytes());
        s.begin_input(&header)?;
        feed(&stripped(prev), &mut |c| s.prev_tx_chunk(c))?;
    }
    let outputs: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
    feed(&outputs, &mut |c| s.outputs_chunk(c))?;
    let review = s.finalize()?;
    s.approve()?;
    for (i, (input, prev)) in tx.input.iter().zip(prevs).enumerate() {
        if kind == Kind::Deposit || i == 0 {
            let amount = prev.output[input.previous_output.vout as usize]
                .value
                .to_sat();
            assert_eq!(
                s.sighash(i as u8)?,
                reference_sighash(tx, i, &s.wallet().clone(), amount)
            );
        }
    }
    assert!(s.is_complete());
    Ok(review)
}

#[test]
fn random_chunk_boundaries() {
    let (wallet, deposit, prevs) = nested_deposit();
    let refs: Vec<&Transaction> = prevs.iter().collect();
    let (wwallet, wtx, helper, vault_prev) = withdrawal(
        &[vec![0x51, 0x20], vec![7u8; 32]].concat(),
        46_000,
        &vault(),
    );
    let mainnet = tx("withdrawal");
    let mainnet_deposit = tx("deposit");
    for seed in 1..40u64 {
        assert_eq!(
            stream_random(Kind::Deposit, wallet, &deposit, &refs, seed)
                .unwrap()
                .amount,
            100_000
        );
        assert_eq!(
            stream_random(
                Kind::Withdrawal,
                wwallet,
                &wtx,
                &[&helper, &vault_prev],
                seed
            )
            .unwrap()
            .fee,
            6_000
        );
        let review = stream_random(
            Kind::Withdrawal,
            witness_wallet(&mainnet, 0),
            &mainnet,
            &[&mainnet_deposit, &mainnet_deposit],
            seed,
        )
        .unwrap();
        assert_eq!(hex::encode(review.vault), MAINNET_VAULT);
    }
}

#[test]
fn output_edge_cases() {
    let (wallet, deposit, prevs) = nested_deposit();
    let refs: Vec<&Transaction> = prevs.iter().collect();

    // Bytes after the last output are refused, in the same chunk or the next.
    let start = parse_start(&start_bytes(1, wallet.address_type, &deposit)).unwrap();
    let mut s = SignTx::<Soft>::new(start, wallet);
    for (input, prev) in deposit.input.iter().zip(&refs) {
        let mut header = input.previous_output.txid.to_byte_array().to_vec();
        header.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        header.extend_from_slice(&input.sequence.0.to_le_bytes());
        s.begin_input(&header).unwrap();
        s.prev_tx_chunk(&stripped(prev)).unwrap();
    }
    let mut outputs: Vec<u8> = deposit.output.iter().flat_map(serialize).collect();
    outputs.push(0);
    assert_eq!(s.outputs_chunk(&outputs), Err(Error::Parse));

    // A zero-value vault output or change output.
    let mut t = deposit.clone();
    t.output[0].value = Amount::ZERO;
    t.output[1].value = Amount::from_sat(119_000);
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &refs, 255).err(),
        Some(Error::BadAmount)
    );
    let mut t = deposit.clone();
    t.output[1].value = Amount::ZERO;
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &refs, 255).err(),
        Some(Error::BadLayout)
    );

    // The vault must be output 0, as qsb-app's server requires.
    let mut t = deposit.clone();
    t.output.swap(0, 1);
    assert_eq!(
        stream(Kind::Deposit, wallet, &t, &refs, 255).err(),
        Some(Error::NotVault)
    );
}

#[test]
fn message_collector() {
    use crate::session::MessageCollector;
    let mut path = vec![5u8];
    for e in [84 | HARDENED, HARDENED, HARDENED, 0, 0] {
        path.extend_from_slice(&e.to_be_bytes());
    }
    let message = vec![b'x'; 512];
    let mut first = path.clone();
    first.extend_from_slice(&512u16.to_be_bytes());
    first.extend_from_slice(&message[..100]);
    let mut c = MessageCollector::start(&first).unwrap();
    assert!(!c.is_complete());
    c.push(&message[100..400]).unwrap();
    c.push(&message[400..]).unwrap();
    assert!(c.is_complete());
    assert_eq!(c.message(), &message[..]);
    assert_eq!(c.push(b"y"), Err(Error::BadLength));

    // Empty, oversized, and a bad path.
    for len in [0u16, 513] {
        let mut d = path.clone();
        d.extend_from_slice(&len.to_be_bytes());
        assert_eq!(MessageCollector::start(&d).err(), Some(Error::BadMessage));
    }
    let mut d = path.clone();
    d.extend_from_slice(&[0, 4]);
    d.extend_from_slice(b"too long");
    assert_eq!(MessageCollector::start(&d).err(), Some(Error::BadLength));
    let mut bad = path.clone();
    bad[4] = 44; // purpose 44'
    bad.extend_from_slice(&[0, 1, b'x']);
    assert_eq!(MessageCollector::start(&bad).err(), Some(Error::BadPath));
}

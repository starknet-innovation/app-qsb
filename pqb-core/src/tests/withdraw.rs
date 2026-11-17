use std::vec;
use std::vec::Vec;

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{absolute, transaction, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Witness};

use super::deposit::{funding_tx, out, stripped};
use super::record::rec;
use super::support::{h, test_seed, vault};
use crate::error::Error;
use crate::hash::sha256;
use crate::hash::soft::Soft;
use crate::record::{Disclosure, Standing, State};
use crate::withdraw::{
    decide, digest, parse_commitments, parse_menu_points, parse_menu_r, parse_start, read_chunk,
    record_after, Decision, Request, Review, Withdraw, START_LEN,
};

#[test]
fn bip_digest_vector() {
    let t = h("020000000111111111111111111111111111111111111111111111111111111111111111110000000000feffff7f01e803000000000000015100f15365");
    let b = sha256::<Soft>(&t);
    assert_eq!(
        hex::encode(b),
        "503f3b44cb5780fafde67c6c7c94b28e82ca8db2b5a421656a40674bada44022"
    );
    let mut i = [0u8; 20];
    i[..8].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
    i[8..17].copy_from_slice(&[100, 101, 102, 103, 104, 105, 106, 107, 108]);
    i[17..].copy_from_slice(&[11, 0, 15]);
    assert_eq!(
        hex::encode(digest::<Soft>(&i, &b)),
        "90c1d3a01bb988d04525c197d94d8ace1cc421d42363e3df8276761510f6a16a"
    );
}

const ROUND0: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const ROUND1: [u8; 9] = [100, 101, 102, 103, 104, 105, 106, 107, 108];
const PICKS: [u8; 3] = [11, 0, 15];

fn start_bytes(v: u32, tx: &Transaction, round0: &[u8], round1: &[u8], picks: &[u8]) -> Vec<u8> {
    let i = &tx.input[0];
    let mut b = v.to_be_bytes().to_vec();
    b.extend_from_slice(&(tx.version.0 as u32).to_le_bytes());
    b.extend_from_slice(&i.previous_output.txid.to_byte_array());
    b.extend_from_slice(&i.previous_output.vout.to_le_bytes());
    b.extend_from_slice(&i.sequence.0.to_le_bytes());
    b.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    b.push(tx.output.len() as u8);
    b.extend_from_slice(round0);
    b.extend_from_slice(round1);
    b.extend_from_slice(picks);
    b
}

fn script(seed: [u8; 32]) -> Vec<u8> {
    let mut s = Vec::new();
    vault(seed).script_into::<Soft>(|b| s.extend_from_slice(b));
    s
}

/// A transaction paying the vault at output 1, and a withdrawal of it.
fn withdrawal(outputs: &[(u64, Vec<u8>)]) -> (Transaction, Transaction) {
    let mut prev = funding_tx(
        &[
            0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ],
        1_000,
    );
    prev.output.push(out(100_000, &script(test_seed())));
    let tx = Transaction {
        version: transaction::Version(2),
        // pqb's pinning nonce: a past time and a sequence.
        lock_time: absolute::LockTime::from_consensus(1_700_000_000),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout: 2,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0x7fff_fffe),
            witness: Witness::new(),
        }],
        output: outputs.iter().map(|(v, s)| out(*v, s)).collect(),
    };
    (prev, tx)
}

fn stream(
    prev: &Transaction,
    tx: &Transaction,
    chunk: usize,
    seed: [u8; 32],
) -> Result<(Request, Review), Error> {
    let req = parse_start(&start_bytes(0, tx, &ROUND0, &ROUND1, &PICKS))?;
    let mut w = Withdraw::<Soft>::new(req, vault(seed).script_hash::<Soft>());
    for c in stripped(prev).chunks(chunk) {
        w.prev_tx_chunk(c)?;
    }
    let outputs: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
    for c in outputs.chunks(chunk) {
        w.outputs_chunk(c)?;
    }
    Ok((req, w.finalize()?))
}

fn p2wpkh_dest() -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[0x42; 20]);
    s
}

fn p2tr_dest() -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&[0x17; 32]);
    s
}

#[test]
fn binding_digest_and_cosignature_sighash() {
    let (prev, tx) = withdrawal(&[(60_000, p2wpkh_dest()), (35_000, p2tr_dest())]);
    let vault_script = script(test_seed());
    let want_z = SighashCache::new(&tx)
        .legacy_signature_hash(0, &ScriptBuf::from_bytes(vault_script), 1)
        .unwrap()
        .to_byte_array();
    let t = serialize(&tx);
    for chunk in [1usize, 31, 250, 20_000] {
        let (req, review) = stream(&prev, &tx, chunk, test_seed()).unwrap();
        assert_eq!(review.binding, sha256::<Soft>(&t), "B = SHA256(T)");
        assert_eq!(
            review.digest,
            digest::<Soft>(&req.selection(), &review.binding)
        );
        assert_eq!(
            review.sighash, want_z,
            "legacy SIGHASH_ALL over the vault script"
        );
        assert_eq!(review.fee, 5_000);
        assert_eq!(review.vault_value, 100_000);
        assert!(!review.high_fee);
        assert_eq!(review.outputs[0].unwrap().0, 60_000);
        assert_eq!(review.outputs[1].unwrap().1.as_bytes(), &p2tr_dest()[..]);
        assert!(review.outputs[2].is_none());
        assert_eq!(review.funding.txid, prev.compute_txid().to_byte_array());
        assert_eq!(review.funding.vout, 2);
        assert_eq!(review.funding.value, 100_000);
    }
}

#[test]
fn withdrawal_refusals() {
    let (prev, tx) = withdrawal(&[(60_000, p2wpkh_dest())]);
    // Another seed's vault.
    assert_eq!(stream(&prev, &tx, 99, [3; 32]).err(), Some(Error::NotVault));
    // Fee not positive.
    let (prev2, tx2) = withdrawal(&[(100_000, p2wpkh_dest())]);
    assert_eq!(
        stream(&prev2, &tx2, 99, test_seed()).err(),
        Some(Error::BadAmount)
    );
    // An output the device can't show.
    let (prev3, tx3) = withdrawal(&[(50_000, vec![0x6a, 0x00])]);
    assert_eq!(
        stream(&prev3, &tx3, 99, test_seed()).err(),
        Some(Error::UnsupportedOutput)
    );
    // A previous transaction that isn't the outpoint's.
    let req = parse_start(&start_bytes(0, &tx, &ROUND0, &ROUND1, &PICKS)).unwrap();
    let mut w = Withdraw::<Soft>::new(req, vault(test_seed()).script_hash::<Soft>());
    let mut other = prev.clone();
    other.lock_time = absolute::LockTime::from_consensus(1);
    let mut r = Ok(());
    for c in stripped(&other).chunks(500) {
        r = w.prev_tx_chunk(c);
    }
    assert_eq!(r, Err(Error::TxidMismatch));
    // Outputs before the previous transaction.
    let mut w = Withdraw::<Soft>::new(req, [0; 32]);
    assert_eq!(w.outputs_chunk(&[0]), Err(Error::BadState));
    assert_eq!(w.finalize().err(), Some(Error::BadState));
}

#[test]
fn request_validation() {
    let (_, tx) = withdrawal(&[(60_000, p2wpkh_dest())]);
    let ok = |r0: &[u8], r1: &[u8], p: &[u8]| parse_start(&start_bytes(0, &tx, r0, r1, p));
    assert!(ok(&ROUND0, &ROUND1, &PICKS).is_ok());
    assert_eq!(
        start_bytes(0, &tx, &ROUND0, &ROUND1, &PICKS).len(),
        START_LEN
    );
    // Unordered, repeated, overlapping and out-of-range indices; bad picks.
    for (r0, r1, p) in [
        ([1, 0, 2, 3, 4, 5, 6, 7], ROUND1, PICKS),
        ([0, 0, 2, 3, 4, 5, 6, 7], ROUND1, PICKS),
        ([0, 1, 2, 3, 4, 5, 6, 109], ROUND1, PICKS),
        ([0, 1, 2, 3, 4, 5, 6, 100], ROUND1, PICKS),
        (ROUND0, [100, 101, 102, 103, 104, 105, 106, 108, 107], PICKS),
        (ROUND0, ROUND1, [12, 0, 0]),
        (ROUND0, ROUND1, [0, 16, 0]),
        (ROUND0, ROUND1, [0, 0, 16]),
    ] {
        assert_eq!(
            ok(&r0, &r1, &p).err(),
            Some(Error::BadData),
            "{r0:?} {r1:?} {p:?}"
        );
    }
    let mut b = start_bytes(0, &tx, &ROUND0, &ROUND1, &PICKS);
    b[52] = 0;
    assert_eq!(parse_start(&b).err(), Some(Error::BadLayout));
    b[52] = 5;
    assert_eq!(parse_start(&b).err(), Some(Error::BadLayout));
    b[52] = 1;
    b[0] = 0x80;
    assert_eq!(parse_start(&b).err(), Some(Error::BadData));
    assert_eq!(parse_start(&b[..72]).err(), Some(Error::BadLength));

    assert_eq!(parse_commitments(&[0, 0, 0, 1, 142, 12]), Ok((1, 142, 12)));
    assert_eq!(
        parse_commitments(&[0, 0, 0, 1, 143, 12]).err(),
        Some(Error::BadData)
    );
    assert_eq!(
        parse_commitments(&[0, 0, 0, 1, 0, 13]).err(),
        Some(Error::BadData)
    );
    assert_eq!(
        parse_commitments(&[0, 0, 0, 1, 0, 0]).err(),
        Some(Error::BadData)
    );
    assert_eq!(
        parse_menu_points(&[0, 0, 0, 0, 0, 1, 5, 7]),
        Ok((0, 0, 1, 5, 7))
    );
    assert_eq!(parse_menu_r(&[0, 0, 0, 9, 2]), Ok((9, 2)));
    assert_eq!(parse_menu_r(&[0, 0, 0, 9, 3]).err(), Some(Error::BadData));
    assert_eq!(
        parse_menu_r(&[0x80, 0, 0, 0, 0]).err(),
        Some(Error::BadData)
    );
    assert_eq!(parse_menu_r(&[0, 0, 0, 0]).err(), Some(Error::BadLength));
    assert_eq!(
        parse_menu_points(&[0, 0, 0, 0, 0, 1, 6, 7]).err(),
        Some(Error::BadData)
    );
    assert_eq!(
        parse_menu_points(&[0, 0, 0, 0, 3, 0, 0, 1]).err(),
        Some(Error::BadData)
    );
    assert_eq!(
        parse_menu_points(&[0, 0, 0, 0, 1, 4, 0, 1]).err(),
        Some(Error::BadData)
    );
}

fn reviewed() -> (Request, Review) {
    let (prev, tx) = withdrawal(&[(60_000, p2wpkh_dest())]);
    stream(&prev, &tx, 500, test_seed()).unwrap()
}

#[test]
fn lifecycle_decisions() {
    let (req, review) = reviewed();
    let root = [0u8; 32];
    let sh = [0xffu8; 32];
    let base = |state| {
        let mut r = rec(0, state);
        r.root = root;
        r.script_hash = sh;
        r.funding = Some(review.funding);
        if state == State::Allocated {
            r.funding = None;
        }
        r
    };
    let d = |s: Standing| decide(&s, &root, &sh, &req, &review);
    assert_eq!(d(Standing::NotAllocated), Err(Error::VaultState));
    assert_eq!(d(Standing::Reserved), Err(Error::VaultState));
    assert_eq!(
        d(Standing::NoHistory),
        Ok(Decision::Emergency { retry: false })
    );
    assert_eq!(
        d(Standing::Recorded(base(State::Allocated))),
        Ok(Decision::Fresh)
    );
    assert_eq!(
        d(Standing::Recorded(base(State::Retired))),
        Err(Error::VaultState)
    );

    // After the first disclosure: the same one again is a retry, anything else a conflict.
    let wallet = [0xaa; 16];
    let after = record_after(
        Decision::Fresh,
        Some(&base(State::Allocated)),
        &wallet,
        &root,
        &sh,
        &req,
        &review,
    );
    assert_eq!(after.state, State::Exposed);
    assert!(!after.emergency);
    assert_eq!(after.funding.unwrap().txid, review.funding.txid);
    assert_eq!(d(Standing::Recorded(after)), Ok(Decision::Retry));
    let other = Disclosure {
        picks: [0, 0, 0],
        ..after.disclosure.unwrap()
    };
    let changed = crate::record::Record {
        disclosure: Some(other),
        ..after
    };
    assert_eq!(d(Standing::Recorded(changed)), Err(Error::Conflict));
    // A different funding outpoint, root or script: conflict.
    let mut moved = after;
    moved.funding.as_mut().unwrap().vout = 9;
    assert_eq!(d(Standing::Recorded(moved)), Err(Error::Conflict));
    let mut wrong_root = after;
    wrong_root.root = [1; 32];
    assert_eq!(d(Standing::Recorded(wrong_root)), Err(Error::Conflict));
    // An exposed vault never goes back: retiring it ends retries too.
    let retired = crate::record::Record {
        state: State::Retired,
        ..after
    };
    assert_eq!(d(Standing::Recorded(retired)), Err(Error::VaultState));

    // The emergency path keeps the uncertainty: state stays unknown.
    let em = record_after(
        Decision::Emergency { retry: false },
        None,
        &wallet,
        &root,
        &sh,
        &req,
        &review,
    );
    assert_eq!(em.state, State::Unknown);
    assert!(em.emergency);
    assert_eq!(
        d(Standing::Recorded(em)),
        Ok(Decision::Emergency { retry: true })
    );
    let em_changed = crate::record::Record {
        disclosure: Some(other),
        ..em
    };
    assert_eq!(d(Standing::Recorded(em_changed)), Err(Error::Conflict));
    // Records survive encoding.
    assert_eq!(crate::record::Record::decode(&em.encode()), Ok(Some(em)));
    assert_eq!(
        crate::record::Record::decode(&after.encode()),
        Ok(Some(after))
    );
}

#[test]
fn response_chunks() {
    let (req, _) = reviewed();
    let v = vault(test_seed());
    let cosig = [0x30u8; 71];
    let q = [0x02u8; 33];
    let mut all = Vec::new();
    let mut buf = [0u8; 255];
    for chunk in 0..crate::withdraw::CHUNKS {
        let n = read_chunk::<Soft>(&v, &req, &cosig, &q, chunk, &mut buf).unwrap();
        assert!(n <= 250);
        all.push(buf[..n].to_vec());
    }
    assert_eq!(all[0].len(), 160);
    assert_eq!(&all[0][..20], &v.table_secret::<Soft>(0)[..]);
    assert_eq!(all[1].len(), 160);
    assert_eq!(&all[1][..32], &v.table_round1::<Soft>(100)[..]);
    assert_eq!(all[2].len(), 128);
    assert_eq!(&all[2][96..], &v.table_round1::<Soft>(108)[..]);
    // Menu signatures, length-prefixed: stage 0 has a 32-byte r (72 or 73 bytes),
    // stages 1 and 2 the one-byte r 0x81 (41 bytes).
    let g = &all[3];
    let mut at = 0;
    for (stage, &p) in PICKS.iter().enumerate() {
        let len = g[at] as usize;
        let mut want = [0u8; 73];
        let n = v.menu_signature::<Soft>(stage, p as usize).write(&mut want);
        assert_eq!(&g[at + 1..at + 1 + len], &want[..n]);
        at += 1 + len;
    }
    assert_eq!(at, g.len());
    assert_eq!(all[4][0] as usize, cosig.len());
    assert_eq!(&all[4][72..], &q[..]);
    assert_eq!(
        read_chunk::<Soft>(&v, &req, &cosig, &q, 5, &mut buf).err(),
        Some(Error::BadData)
    );
}

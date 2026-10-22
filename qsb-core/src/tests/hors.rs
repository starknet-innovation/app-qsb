//! HORS derivation and the reveal guard. Expected values come from the Python
//! reference, tests/application_client/hors.py.

use std::vec::Vec;

use crate::error::Error;
use crate::guard::{self, Check, Entry, CAPACITY, TABLE_LEN};
use crate::hash::{hash160, soft::Soft, Hashes};
use crate::hors::{self, Vault, NET_MAINNET, NET_TEST};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// The reference vectors use K = 00 01 … 1f.
fn key() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

const MAIN0: Vault = Vault {
    net: NET_MAINNET,
    index: 0,
};
const MAIN7: Vault = Vault {
    net: NET_MAINNET,
    index: 7,
};

#[test]
fn hmac_is_rfc_4231() {
    // RFC 4231 test case 2, with the 4-byte key zero-padded to 32 bytes (HMAC pads short keys with zeros).
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(b"Jefe");
    assert_eq!(
        Soft::hmac_sha256(&k, b"what do ya want for nothing?").to_vec(),
        h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
}

#[test]
fn secrets_match_the_reference() {
    let k = key();
    for (vault, round, index, secret, commitment) in [
        (
            MAIN0,
            0,
            0,
            "df83cf4950602d2d3b90041023b941271bc7c494",
            "887b040fb41eb3cf514e3bd63986f08697b943c4",
        ),
        (
            MAIN0,
            1,
            149,
            "84f94456b5537fc0a7b922e056673e455d666c0a",
            "27567ff92caad5adb3484d58f93e4995262d78df",
        ),
        (
            MAIN7,
            0,
            3,
            "47ddd932d497ec0a108ed395d9cb35830f1a984e",
            "e7e455fde8b2a8e66143447aa166e72a1010c603",
        ),
        (
            Vault {
                net: NET_TEST,
                index: hors::MAX_VAULT_INDEX,
            },
            1,
            42,
            "e6af8e17907e54ca6d210d39042ed0575ba6bab4",
            "2171b247eacdb5dcb343450fbb22987a4f2a8f92",
        ),
    ] {
        let s = hors::secret::<Soft>(&k, vault, round, index);
        assert_eq!(s.to_vec(), h(secret));
        assert_eq!(hash160::<Soft>(&s).to_vec(), h(commitment));
        assert_eq!(
            hors::commitment::<Soft>(&k, vault, round, index).to_vec(),
            h(commitment)
        );
    }
}

#[test]
fn roots_and_fingerprints_match_the_reference() {
    let k = key();
    let root = hors::commitment_root::<Soft>(&k, MAIN0);
    assert_eq!(
        root.to_vec(),
        h("9b257b6acd00017b1488ed9d73d05bc8a5dbdd43c8aa54d1d37c7e807d65c515")
    );
    assert_eq!(&hors::fingerprint(&root), b"9b25 7b6a cd00 017b");
    let root7 = hors::commitment_root::<Soft>(&k, MAIN7);
    assert_eq!(
        root7.to_vec(),
        h("8ea0f0b0ac0db4db0405bedf47bd3c54fe946e5d1ed3a158fb11a72580940e11")
    );
    assert_eq!(&hors::fingerprint(&root7), b"8ea0 f0b0 ac0d b4db");
}

fn path_free_reveal(r1: [u16; 8], r2: [u16; 7], binding: [u8; 32], dest: &[u8]) -> Vec<u8> {
    let mut d = std::vec![NET_MAINNET, 0, 0, 0, 7];
    for i in r1.iter().chain(r2.iter()) {
        d.extend_from_slice(&i.to_be_bytes());
    }
    d.extend_from_slice(&binding);
    d.extend_from_slice(&92_083u64.to_be_bytes());
    d.push(dest.len() as u8);
    d.extend_from_slice(dest);
    d
}

const P2TR: &str = "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c";

#[test]
fn reveal_requests() {
    let r1 = [0, 1, 2, 3, 4, 5, 6, 7];
    let r2 = [140, 141, 142, 143, 144, 145, 146];
    let binding = [0xab; 32];
    let data = path_free_reveal(r1, r2, binding, &h(P2TR));
    let req = hors::parse_reveal::<Soft>(&data, NET_MAINNET).unwrap();
    assert_eq!(req.vault, MAIN7);
    assert_eq!(req.amount, 92_083);
    assert_eq!(req.destination.as_bytes(), &h(P2TR)[..]);
    assert_eq!(
        req.reveal_hash::<Soft>().to_vec(),
        h("498b1ea9b6c381e78fc76f0a9c2003b1d29ef25caf92d5a3b6a1d7dbc90f7d2c")
    );
    let revealed = req.revealed();
    assert_eq!(revealed[0], (0, 0));
    assert_eq!(revealed[7], (0, 7));
    assert_eq!(revealed[8], (1, 140));
    assert_eq!(revealed[14], (1, 146));
    assert_eq!(hors::chunk_range(0), Some(0..12));
    assert_eq!(hors::chunk_range(1), Some(12..15));
    assert_eq!(hors::chunk_range(2), None);

    // Order is kept, not normalised: the scriptSig order follows the GPU subset.
    let shuffled = hors::parse_reveal::<Soft>(
        &path_free_reveal([7, 6, 5, 4, 3, 2, 1, 0], r2, binding, &h(P2TR)),
        NET_MAINNET,
    )
    .unwrap();
    assert_eq!(shuffled.revealed()[0], (0, 7));
    assert_ne!(shuffled.reveal_hash::<Soft>(), req.reveal_hash::<Soft>());

    // Refusals, all before any screen.
    let bad = |d: &[u8]| hors::parse_reveal::<Soft>(d, NET_MAINNET).err();
    assert_eq!(
        bad(&path_free_reveal(
            [0, 1, 2, 3, 4, 5, 6, 150],
            r2,
            binding,
            &h(P2TR)
        )),
        Some(Error::BadData)
    );
    assert_eq!(
        bad(&path_free_reveal(
            [0, 1, 2, 3, 4, 5, 6, 0],
            r2,
            binding,
            &h(P2TR)
        )),
        Some(Error::BadData)
    );
    assert_eq!(
        bad(&path_free_reveal(
            r1,
            [1, 2, 3, 4, 5, 6, 6],
            binding,
            &h(P2TR)
        )),
        Some(Error::BadData)
    );
    assert_eq!(
        bad(&path_free_reveal(r1, r2, binding, &h("6a0100"))),
        Some(Error::BadData),
        "no address"
    );
    assert_eq!(
        bad(&path_free_reveal(r1, r2, binding, &[0x51; 35])),
        Some(Error::BadData),
        "too long"
    );
    let mut short = data.clone();
    short.pop();
    assert_eq!(bad(&short), Some(Error::BadData));
    let mut long = data.clone();
    long.push(0);
    assert_eq!(bad(&long), Some(Error::BadData));
    let mut big = data.clone();
    big[67..75].copy_from_slice(&(21_000_000u64 * 100_000_000 + 1).to_be_bytes());
    assert_eq!(bad(&big), Some(Error::BadData), "above 21M BTC");
    // The same request for a test network, against this mainnet build.
    let mut test = data.clone();
    test[0] = NET_TEST;
    assert_eq!(bad(&test), Some(Error::WrongNetwork));
    test[0] = 2;
    assert_eq!(bad(&test), Some(Error::BadData));
}

#[test]
fn commitment_and_vault_requests() {
    let ok = hors::parse_commitments(1, &[0, 0, 0, 0, 7, 0, 138, 12], NET_MAINNET).unwrap();
    assert_eq!(
        (ok.vault, ok.round, ok.start, ok.count),
        (MAIN7, 1, 138, 12)
    );
    for (round, data) in [
        (2, [0, 0, 0, 0, 7, 0, 0, 1]),    // no round 2
        (0, [0, 0, 0, 0, 7, 0, 139, 12]), // past index 149
        (0, [0, 0, 0, 0, 7, 0, 0, 13]),   // more than 12
        (0, [0, 0, 0, 0, 7, 0, 0, 0]),    // none
        (0, [0, 0x80, 0, 0, 0, 0, 0, 1]), // v ≥ 2^31
    ] {
        assert_eq!(
            hors::parse_commitments(round, &data, NET_MAINNET).err(),
            Some(Error::BadData)
        );
    }
    assert_eq!(
        hors::parse_commitments(0, &[1, 0, 0, 0, 7, 0, 0, 1], NET_MAINNET).err(),
        Some(Error::WrongNetwork)
    );
    assert_eq!(
        hors::parse_commitments(0, &[0, 0, 0, 0, 7, 0, 0], NET_MAINNET).err(),
        Some(Error::BadData)
    );
    assert_eq!(hors::parse_vault(&[0, 0, 0, 0, 7], NET_MAINNET), Ok(MAIN7));
    assert_eq!(
        hors::parse_vault(&[0, 0, 0, 7], NET_MAINNET).err(),
        Some(Error::BadData)
    );
    assert_eq!(
        hors::parse_vault(&[1, 0, 0, 0, 7], NET_TEST),
        Ok(Vault {
            net: NET_TEST,
            index: 7
        })
    );
}

fn record(table: &[u8; TABLE_LEN], new: Entry) -> [u8; TABLE_LEN] {
    let mut out = [0xffu8; TABLE_LEN];
    guard::record_into(table, new, &mut out).unwrap();
    out
}

/// Two wallets on one device: the seed, and the seed with a BIP-39 passphrase.
const ALICE: [u8; 8] = [0xa1; 8];
const BOB: [u8; 8] = [0xb0; 8];

fn entry(wallet: [u8; 8], index: u32, tag: u8) -> Entry {
    Entry {
        wallet,
        vault: Vault {
            net: NET_MAINNET,
            index,
        },
        reveal_hash: [tag; 32],
    }
}

#[test]
fn wallet_tag_matches_the_reference() {
    assert_eq!(
        hors::wallet_tag::<Soft>(&key()).to_vec(),
        h("84afaababacf1d87")
    );
}

#[test]
fn guard_records_and_refuses() {
    let empty = [0u8; TABLE_LEN];
    assert_eq!(
        guard::check(&empty, &ALICE, MAIN7, &[1; 32]),
        Ok(Check::New { evict: None })
    );
    let one = record(&empty, entry(ALICE, 7, 1));
    assert_eq!(
        guard::check(&one, &ALICE, MAIN7, &[1; 32]),
        Ok(Check::ReReveal)
    );
    assert_eq!(
        guard::check(&one, &ALICE, MAIN7, &[2; 32]),
        Ok(Check::Conflict)
    );
    assert_eq!(guard::revealed(&one, &ALICE, MAIN7), Ok(true));
    // Another vault, the same index on another network, or another wallet's vault #7
    // are separate records.
    assert_eq!(
        guard::check(&one, &ALICE, MAIN0, &[2; 32]),
        Ok(Check::New { evict: None })
    );
    let test7 = Vault {
        net: NET_TEST,
        index: 7,
    };
    assert_eq!(
        guard::check(&one, &ALICE, test7, &[2; 32]),
        Ok(Check::New { evict: None })
    );
    assert_eq!(
        guard::check(&one, &BOB, MAIN7, &[2; 32]),
        Ok(Check::New { evict: None })
    );
    assert_eq!(guard::revealed(&one, &BOB, MAIN7), Ok(false));
    let both = record(&one, entry(BOB, 7, 2));
    assert_eq!(
        guard::check(&both, &ALICE, MAIN7, &[1; 32]),
        Ok(Check::ReReveal)
    );
    assert_eq!(
        guard::check(&both, &BOB, MAIN7, &[2; 32]),
        Ok(Check::ReReveal)
    );
    assert_eq!(
        guard::check(&both, &BOB, MAIN7, &[1; 32]),
        Ok(Check::Conflict)
    );
}

#[test]
fn guard_full_drops_the_oldest() {
    let mut table = [0u8; TABLE_LEN];
    for v in 0..CAPACITY as u32 {
        let vault = Vault {
            net: NET_MAINNET,
            index: v,
        };
        assert_eq!(
            guard::check(&table, &ALICE, vault, &[9; 32]),
            Ok(Check::New { evict: None })
        );
        table = record(&table, entry(ALICE, v, v as u8));
    }
    assert_eq!(guard::entries(&table).unwrap().count(), CAPACITY);
    // Full: recording vault 1000 evicts vault 0, the oldest, and keeps the rest in order.
    let new = Vault {
        net: NET_MAINNET,
        index: 1000,
    };
    assert_eq!(
        guard::check(&table, &BOB, new, &[9; 32]),
        Ok(Check::New {
            evict: Some(entry(ALICE, 0, 0))
        })
    );
    let next = record(&table, entry(BOB, 1000, 0xee));
    let kept: Vec<u32> = guard::entries(&next)
        .unwrap()
        .map(|e| e.vault.index)
        .collect();
    assert_eq!(kept.len(), CAPACITY);
    assert_eq!(kept[0], 1);
    assert_eq!(*kept.last().unwrap(), 1000);
    assert_eq!(
        guard::check(&next, &ALICE, MAIN0, &[0; 32]),
        Ok(Check::New {
            evict: Some(entry(ALICE, 1, 1))
        })
    );
    assert_eq!(
        guard::check(&next, &ALICE, MAIN7, &[7; 32]),
        Ok(Check::ReReveal)
    );
}

#[test]
fn guard_fails_closed_on_unreadable_storage() {
    // Never written: all zeros, an empty table.
    assert_eq!(guard::entries(&[0u8; TABLE_LEN]).unwrap().count(), 0);
    let good = record(&[0u8; TABLE_LEN], entry(ALICE, 7, 1));
    let mut bad = Vec::new();
    // An unknown layout byte, garbage after a zero layout byte, a count over the
    // capacity, an entry whose state isn't "revealed".
    for (offset, value) in [(0, 0x02), (0, 0x00), (1, 65), (2 + 13, 0x00)] {
        let mut t = good;
        t[offset] = value;
        bad.push(t);
    }
    let mut garbage = [0u8; TABLE_LEN];
    garbage[100] = 1;
    bad.push(garbage);
    for t in &bad {
        assert_eq!(
            guard::check(t, &ALICE, MAIN0, &[1; 32]),
            Err(Error::GuardCorrupt)
        );
        assert_eq!(guard::revealed(t, &ALICE, MAIN7), Err(Error::GuardCorrupt));
        let mut out = [0u8; TABLE_LEN];
        assert_eq!(
            guard::record_into(t, entry(ALICE, 0, 0), &mut out),
            Err(Error::GuardCorrupt)
        );
    }
}

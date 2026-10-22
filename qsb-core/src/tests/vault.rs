use std::vec::Vec;

use crate::hash::{sha256, soft::Soft};
use crate::vault::{VaultMatcher, VAULT_SCRIPT_LEN};

pub fn script(name: &str) -> Vec<u8> {
    let text = match name {
        "seed2" => include_str!("../../../tests/fixtures/vault-seed2.hex"),
        "random" => include_str!("../../../tests/fixtures/vault-random.hex"),
        _ => unreachable!(),
    };
    hex::decode(text.trim()).unwrap()
}

/// The vault of qsb-app's first mainnet deposit, 1378dd5c…:0.
pub fn mainnet_script() -> Vec<u8> {
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
        &hex::decode(include_str!("../../../tests/fixtures/mainnet-deposit.hex").trim()).unwrap(),
    )
    .unwrap();
    tx.output[0].script_pubkey.to_bytes()
}

fn matches(s: &[u8], chunk: usize) -> Option<[u8; 32]> {
    let mut m = VaultMatcher::<Soft>::new(s.len() as u64);
    for c in s.chunks(chunk) {
        m.update(c);
    }
    m.finish()
}

#[test]
fn vault_scripts_match() {
    for s in [mainnet_script(), script("seed2"), script("random")] {
        assert_eq!(s.len() as u64, VAULT_SCRIPT_LEN);
        for chunk in [1, 20, 21, 255, 4096, s.len()] {
            assert_eq!(matches(&s, chunk), Some(sha256::<Soft>(&s)));
        }
    }
    // qsb-app's recorded scriptHash for that vault.
    assert_eq!(
        hex::encode(matches(&mainnet_script(), 255).unwrap()),
        "5f7a0bc1bf0fa932d95ad2dd9b60104dbbebb1f7b42ee5f1f2d58c344525290e"
    );
}

#[test]
fn only_commitments_may_vary() {
    let base = script("seed2");
    let commitment = |i: usize| {
        [62usize, 4999]
            .iter()
            .any(|&s| i >= s && i < s + 3150 && !(i - s).is_multiple_of(21))
    };
    let mut fixed = 0;
    for i in 0..base.len() {
        let mut s = base.clone();
        s[i] ^= 0x01;
        // Every fixed byte matters; any commitment byte can change.
        if commitment(i) {
            if i.is_multiple_of(97) {
                assert_eq!(
                    matches(&s, 255),
                    Some(sha256::<Soft>(&s)),
                    "commitment byte {i}"
                );
            }
        } else {
            fixed += 1;
            assert_eq!(matches(&s, 255), None, "fixed byte {i}");
        }
    }
    assert_eq!(fixed, 3923);

    // Shorter, longer and truncated scripts are refused.
    assert_eq!(matches(&base[..base.len() - 1], 255), None);
    let mut longer = base.clone();
    longer.push(0x51);
    assert_eq!(matches(&longer, 255), None);
    let mut m = VaultMatcher::<Soft>::new(VAULT_SCRIPT_LEN);
    m.update(&base[..9000]);
    assert_eq!(m.finish(), None);
}

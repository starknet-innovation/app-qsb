use std::vec::Vec;

use hmac::Mac;

use super::support::{h, h32, pqb_script, test_seed, vault, SoftCurve};
use crate::der;
use crate::hash::soft::Soft;
use crate::hash::{sha256, Hashes};
use crate::pqb::{self, child_entropy, fingerprint, key_from_bytes, vault_seed, Curve};
use crate::sha1::sha1;
use crate::template::{self, SCRIPT_LEN, TEMPLATE};
use crate::u256::{lift_x, on_curve_x, N, P, U256};

#[test]
fn sha1_vectors() {
    assert_eq!(
        hex::encode(sha1(b"")),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    assert_eq!(
        hex::encode(sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex::encode(sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    // Every length across the one- and two-block boundary.
    for n in 0..140usize {
        let data: Vec<u8> = (0..n as u8).collect();
        let want = bitcoin::hashes::sha1::Hash::hash(&data);
        assert_eq!(&sha1(&data)[..], &want[..], "length {n}");
    }
}

use bitcoin::hashes::Hash as _;

#[test]
fn modular_arithmetic() {
    let p = P.m;
    // Generator x is on the curve; its y parities come out right.
    let gx = U256::from_be(&h32(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ));
    let gy = h32("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    assert_eq!(lift_x(&gx, false).unwrap().to_be(), gy);
    assert_eq!(lift_x(&gx, true).unwrap(), p.sub(&U256::from_be(&gy)).0);
    assert!(!on_curve_x(&U256::ZERO));
    assert!(!on_curve_x(&p));
    // 1 has x^3 + 7 = 8, a square mod p? Compare with a brute check via k256.
    for x in 1..200u32 {
        let mut b = [0u8; 32];
        b[28..].copy_from_slice(&x.to_be_bytes());
        let mut sec1 = [0u8; 33];
        sec1[0] = 2;
        sec1[1..].copy_from_slice(&b);
        let k = k256::PublicKey::from_sec1_bytes(&sec1).is_ok();
        assert_eq!(on_curve_x(&U256([x, 0, 0, 0, 0, 0, 0, 0])), k, "x = {x}");
    }
    // Inverses mod n.
    for v in [1u32, 2, 0x81, 0xdead_beef] {
        let a = U256([v, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(N.mul(&a, &N.inv(&a)), U256::ONE);
    }
    let big = U256::from_be(&h32(
        "738f51ee63527009b0c7242e5f780d0cc03df71efd8e1ede08bb8254d61c4477",
    ));
    assert_eq!(N.mul(&big, &N.inv(&big)), U256::ONE);
    // key_from_bytes: int(b) mod (n-1) + 1.
    let n1 = N.m.sub(&U256::ONE).0.to_be();
    assert_eq!(key_from_bytes(&[0; 32]), U256::ONE.to_be());
    assert_eq!(key_from_bytes(&n1), U256::ONE.to_be());
    assert_eq!(
        key_from_bytes(&[0xff; 32]),
        U256::from_be(&[0xff; 32])
            .sub(&N.m.sub(&U256::ONE).0)
            .0
            .add(&U256::ONE)
            .0
            .to_be()
    );
}

/// BIP 32 private-key derivation along hardened steps, for the BIP 85 vector.
fn bip32_hardened(seed64: &[u8], path: &[u32]) -> [u8; 32] {
    let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
    mac.update(seed64);
    let i = mac.finalize().into_bytes();
    let mut k = k256::NonZeroScalar::try_from(&i[..32]).unwrap();
    let mut c: [u8; 32] = i[32..].try_into().unwrap();
    for &step in path {
        let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(&c).unwrap();
        mac.update(&[0]);
        mac.update(&k.to_bytes());
        mac.update(&step.to_be_bytes());
        let d = mac.finalize().into_bytes();
        let il = k256::NonZeroScalar::try_from(&d[..32]).unwrap();
        k = k256::NonZeroScalar::new(*il + *k).unwrap();
        c = d[32..].try_into().unwrap();
    }
    k.to_bytes().into()
}

#[test]
fn bip85_vault_seed() {
    // BIP 39 seed of "install scatter logic circle pencil average fall shoe quantum
    // disease suspect usage", empty passphrase (BIP 85's own test root).
    let seed64 = h("37483472a6af7fd107fb5f5aaaa7bddc89690353369229771c32812f711207c87398a8d44cfc763a8185ff346272e8f1455170decae712598f5990c1207d2f88");
    let k = bip32_hardened(&seed64, &pqb::bip85_path(0));
    let e = child_entropy::<Soft>(&k);
    assert_eq!(
        hex::encode(e),
        "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f"
    );
    assert_eq!(
        hex::encode(vault_seed::<Soft>(&e)),
        "b267680d8a1a370e5b7978c725873e36ab66005e6ed25bc0f09c7607e3a2f8f3"
    );
    assert_eq!(
        pqb::bip85_path(5),
        [
            0x84fd_1d48,
            0x8000_0027,
            0x8000_0000,
            0x8000_0018,
            0x8000_0005
        ]
    );
}

#[test]
fn bip_vectors() {
    let v = vault(test_seed());
    // Table entries 0, 1 and 108.
    for (j, s, w, c) in [
        (
            0,
            "f40d6eb40093ac0d520116902b07216bb1e3a2d1",
            "05227724eae56625de9b15a5fc2b04f96f1bd29b57b4c3f97eadd6f28bbcaeee",
            "be4e7023ab90e2e09e38891393626562c8feeae3",
        ),
        (
            1,
            "b7b68874cac5c40a8490a7b51cb294647ea63855",
            "b29d2e799950df83982f6f5329420354cef8ec4d70cf098897b66d2b4d62e8d6",
            "52a4e9595d2bdf26e0816014890da84c004dd5c9",
        ),
        (
            108,
            "501ae3f8c3e88f77a4a28e62229f39c714c53960",
            "776a14aaeacef40eb5fa4a18e843b20b93d5dc04405d7042eead8c1ec80cd054",
            "994314bca665098fec1ac67fba6803534241d126",
        ),
    ] {
        assert_eq!(hex::encode(v.table_secret::<Soft>(j)), s);
        assert_eq!(hex::encode(v.table_round1::<Soft>(j)), w);
        assert_eq!(hex::encode(v.table_commitment::<Soft>(j)), c);
    }
    // Menus: r, then first and last scalar, signature and commitment of each stage.
    let menus = [
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "07d91adc196ecf0ed7a8be20cc6d9a93e4a25b083c70f8730144f579179bf67a",
            "3025020101022007d91adc196ecf0ed7a8be20cc6d9a93e4a25b083c70f8730144f579179bf67a01",
            "efb6c32994a20a7e211c86d431e74f451f4fb4d2",
            "051b6eca14b1d35f5c941a8b9f3584d555abfac303266f37c2081b8e4c25734a",
            "d85f3d338692a6d30e99d0213f1f6e17d82c1a38",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000081",
            "059cdbf0e51a0a555e1b7693d161275b5e5c327dc4bf0c9d0cc4deba56b37c24",
            "3026020200810220059cdbf0e51a0a555e1b7693d161275b5e5c327dc4bf0c9d0cc4deba56b37c2401",
            "3ec9d852aa3df4d9eff3c9f787058f9ca361c278",
            "078c5d74482fc300e3d47122a23591f395e5b5f2b12e28e9384755209d194894",
            "766109b3e9d937e3bcf34200eb87b983548c6b3d",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000081",
            "07462276eab0ee7b79db83c591bb6ea4d87b596bf2b1c744d47d0aec5307073f",
            "302602020081022007462276eab0ee7b79db83c591bb6ea4d87b596bf2b1c744d47d0aec5307073f01",
            "09864f793adea4d1b7b96e72e01a71054adca2bb",
            "079d2b7fd40469981575353d2e2b66b7269f7d486f3dde329eb1f21225179d97",
            "68cc939fa8d49f05f10fcebd166249353a243cd9",
        ),
    ];
    for (stage, (r, x0, g0, m0, xl, ml)) in menus.iter().enumerate() {
        let last = pqb::MENU_WIDTHS[stage] - 1;
        assert_eq!(hex::encode(v.menu_r(stage).to_be()), *r);
        assert_eq!(hex::encode(v.menu_scalar::<Soft>(stage, 0)), *x0);
        let mut g = [0u8; 73];
        let n = v.menu_signature::<Soft>(stage, 0).write(&mut g);
        assert_eq!(hex::encode(&g[..n]), *g0);
        assert_eq!(
            hex::encode(v.menu_signature::<Soft>(stage, 0).commitment()),
            *m0
        );
        assert_eq!(hex::encode(v.menu_scalar::<Soft>(stage, last)), *xl);
        assert_eq!(
            hex::encode(v.menu_signature::<Soft>(stage, last).commitment()),
            *ml
        );
    }
    // Co-signing and deposit keys.
    let d = v.cosign_key::<Soft>();
    assert_eq!(
        hex::encode(d),
        "b8f081dcd6b2ac97521d8190c531fe36ad4cc971a2cc4abbdb598868d7c121ef"
    );
    assert_eq!(
        hex::encode(SoftCurve::pubkey(&d)),
        "029442ee174cb4a13c87eaa1bd44ef1c97d5cd6c653eb5892574f071fe676d1f15"
    );
    assert_eq!(
        hex::encode(v.commitment::<Soft>(153)),
        "e4fe5b5340de7ecf6189051dff97c380386fbebd"
    );
    assert_eq!(
        hex::encode(v.deposit_key::<Soft>()),
        "b384656fb00b475de0ffb0d0efd7cda86560a8b7842dd33111e47cbb15a566f1"
    );
    // Root and fingerprint.
    let root = v.root::<Soft>();
    assert_eq!(
        hex::encode(root),
        "48629f7b1de16b950bbd36124838bc887b0b1c9e6735bf6c8c6b9214a6a3590d"
    );
    assert_eq!(&fingerprint(&root), b"4862 9f7b 1de1 6b95");
    // 154 distinct commitments.
    let mut all: Vec<[u8; 20]> = (0..pqb::COMMITMENTS)
        .map(|i| v.commitment::<Soft>(i))
        .collect();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 154);
}

#[test]
fn script_matches_pqb() {
    let v = vault(test_seed());
    let want = pqb_script();
    assert_eq!(want.len(), SCRIPT_LEN);
    let mut got = Vec::new();
    v.script_into::<Soft>(|b| got.extend_from_slice(b));
    assert_eq!(got, want);
    assert_eq!(v.script_hash::<Soft>(), sha256::<Soft>(&want));
    assert_eq!(
        hex::encode(v.script_hash::<Soft>()),
        "7543fe1034af70cca89e7c824d729a217c859816b237bc86af73b1c3fdc3d9fb"
    );
    // Any chunking of GET_SCRIPT reassembles it.
    for size in [1usize, 19, 20, 21, 250] {
        let mut out = Vec::new();
        let mut off = 0;
        while off < SCRIPT_LEN {
            let mut buf = std::vec![0u8; size.min(SCRIPT_LEN - off)];
            v.script_chunk::<Soft>(off, &mut buf);
            out.extend_from_slice(&buf);
            off += buf.len();
        }
        assert_eq!(out, want, "chunk {size}");
    }
    // The template is the script with the 154 slots zeroed; nothing else.
    let mut zeroed = want.clone();
    for k in 0..template::SLOTS {
        let (at, i) = template::slot(k);
        assert_eq!(want[at - 1], 0x14);
        assert_eq!(&want[at..at + 20], &v.commitment::<Soft>(i)[..]);
        zeroed[at..at + 20].fill(0);
    }
    assert_eq!(&zeroed[..], &TEMPLATE[..]);
    // Another seed differs only in the slots.
    let other = vault([7; 32]);
    let mut b = Vec::new();
    other.script_into::<Soft>(|x| b.extend_from_slice(x));
    let diff = (0..SCRIPT_LEN).filter(|&i| b[i] != want[i]).count();
    assert!(diff > 154 * 15 && diff <= 154 * 20);
}

#[test]
fn menu_points_match_pqb_grind_export() {
    let v = vault(test_seed());
    // (stage, variant, first, last), as pqb's grind.stages_from_lock exports them (pqb v1).
    let want = [
        (
            0,
            0,
            "03fa3ab20d75c4ebef901a5e7df0acf0f5ffef8695809ceb7f69f43bfd9b2b72b6",
            "039cc050816776f55add87ac46a46fe813723333dbdee2dd4f0721ee7ead16ca55",
        ),
        (
            0,
            1,
            "02fa3ab20d75c4ebef901a5e7df0acf0f5ffef8695809ceb7f69f43bfd9b2b72b6",
            "029cc050816776f55add87ac46a46fe813723333dbdee2dd4f0721ee7ead16ca55",
        ),
        (
            1,
            0,
            "03d43be6d4886f9f161329e37d4af4b9a154c7671ab17ba90474f3133f451f7f8d",
            "033590997c415fe08ad6da1e73d0034fc2bb5cc8d14ab854201ec1cd5ddf01dbfb",
        ),
        (
            1,
            3,
            "0331faf07da950d8e11d8d3c196d396a49679b205013e7bdba40b8a54372a75241",
            "023c5d571ccf61efae6d914d4fa07e601995bb4796fe1d49a813d7e05f4cd0e51c",
        ),
        (
            2,
            2,
            "021fd3bb5d78af2cc6d1fa246459ed630d5d20b7d59742dced2b72e30397709e47",
            "0311297f744d0421f54b6f840c9e27856407a86bde4eb194a0b2eaa4fe94f0950a",
        ),
    ];
    for (stage, variant, first, last) in want {
        let w = pqb::MENU_WIDTHS[stage];
        assert_eq!(
            hex::encode(v.menu_point::<Soft, SoftCurve>(stage, variant, 0).unwrap()),
            first
        );
        assert_eq!(
            hex::encode(
                v.menu_point::<Soft, SoftCurve>(stage, variant, w - 1)
                    .unwrap()
            ),
            last
        );
    }
    // The pinning stage's r = 1: 1 + n is not on the curve, so variants 2 and 3 don't exist.
    assert!(v.menu_point::<Soft, SoftCurve>(0, 2, 0).is_none());
    assert!(v.menu_point::<Soft, SoftCurve>(0, 3, 0).is_none());
}

#[test]
fn wallet_id_and_device_seed() {
    // Speculos's seed, vault 0 (values from tests/application_client/pqb.py).
    let s0 = h32("5b6e76548c6812e82bd1036016d15ea91d87ce7d1fd27f5d581f8fa34f208aa5");
    assert_eq!(
        hex::encode(pqb::wallet_id::<Soft>(&s0)),
        "76d84aced6d909d41da0557e378886f3"
    );
    assert_eq!(
        hex::encode(vault(s0).root::<Soft>()),
        "d2cab469997de4f1640caacdb783c9249de3d6bcc05ee449c2a8251ad1ca1229"
    );
    assert_eq!(
        pqb::parse_index(&[0x7f, 0xff, 0xff, 0xff]),
        Some(0x7fff_ffff)
    );
    assert_eq!(pqb::parse_index(&[0x80, 0, 0, 0]), None);
    assert_eq!(pqb::parse_index(&[0, 0, 0]), None);
    let _ = Soft::ripemd160(b"");
}

/// Script pushes as (offset, data); `None` for a non-push opcode.
fn pushes(script: &[u8]) -> Vec<(usize, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        let (start, len) = match op {
            0x01..=0x4b => (i + 1, op as usize),
            0x4c => (i + 2, script[i + 1] as usize),
            0x4d => (
                i + 3,
                u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize,
            ),
            0x4e => panic!("no OP_PUSHDATA4 in the template"),
            _ => {
                let small = match op {
                    0x00 => Some(Vec::new()),
                    0x4f => Some(std::vec![0x81]),
                    0x51..=0x60 => Some(std::vec![op - 0x50]),
                    _ => None,
                };
                out.push((i, small));
                i += 1;
                continue;
            }
        };
        out.push((i, Some(script[start..start + len].to_vec())));
        i = start + len;
    }
    out
}

#[test]
fn der_is_strict() {
    // A menu signature with its hashtype is strict DER; so is a crafted 20-byte one.
    let v = vault(test_seed());
    let mut b = [0u8; 80];
    let n = v.menu_signature::<Soft>(1, 0).write(&mut b);
    assert!(der::is_strict(&b[..n]));
    let crafted = h("3011020601020304050602070102030405060701");
    assert_eq!(crafted.len(), 20);
    assert!(der::is_strict(&crafted));
    // Each of Core's rules, broken one at a time.
    for (at, byte) in [
        (0, 0x31),  // not a SEQUENCE
        (1, 0x12),  // wrong total length
        (2, 0x03),  // r not an INTEGER
        (3, 0x00),  // empty r
        (4, 0x81),  // negative r
        (10, 0x03), // s not an INTEGER
        (12, 0x81), // negative s
    ] {
        let mut bad = crafted.clone();
        bad[at] = byte;
        assert!(!der::is_strict(&bad), "byte {at} = {byte:#04x}");
    }
    let mut padded_r = crafted.clone();
    padded_r[4] = 0x00; // r = 00 02 ..: an unnecessary leading zero
    assert!(!der::is_strict(&padded_r));
    let mut padded_s = crafted.clone();
    padded_s[12] = 0x00;
    assert!(!der::is_strict(&padded_s));
    assert!(!der::is_strict(&crafted[..19]));
    assert!(!der::is_strict(&[0u8; 20]));
}

/// The device screens only the 154 commitment slots. That covers the BIP's DER
/// screen because the slots are the script's only 20-byte pushes and the item
/// under the table is a constant that does not parse as DER.
#[test]
fn der_screen_covers_the_script() {
    let script = pqb_script();
    let toks = pushes(&script);
    let mut push20: Vec<usize> = toks
        .iter()
        .filter(|(_, d)| d.as_ref().is_some_and(|d| d.len() == 20))
        .map(|&(off, _)| off + 1)
        .collect();
    let mut slots: Vec<usize> = (0..template::SLOTS).map(|k| template::slot(k).0).collect();
    push20.sort_unstable();
    slots.sort_unstable();
    assert_eq!(push20, slots);
    for (off, d) in &toks {
        if let Some(d) = d {
            if d.len() == 20 {
                assert!(!der::is_strict(d), "20-byte push at {off}");
            }
        }
    }
    // The first table commitment follows its dummy signature; under that is the
    // item directly under the table.
    let first = toks.iter().position(|&(off, _)| off == 306).unwrap();
    let dummy = toks[first - 1].1.as_ref().unwrap();
    assert!(
        der::is_strict(dummy),
        "the item before c[0] is its dummy signature"
    );
    let under = toks[first - 2].1.as_ref().expect("a script constant");
    assert!(!der::is_strict(under));
    // The test vaults pass, and screened_root agrees with root.
    let v = vault(test_seed());
    assert_eq!(v.screened_root::<Soft>(), Some(v.root::<Soft>()));
}

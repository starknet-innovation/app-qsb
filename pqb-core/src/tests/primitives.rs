use std::string::ToString;
use std::vec::Vec;

use bitcoin::hashes::Hash;
use k256::ecdsa::signature::hazmat::PrehashVerifier;

use crate::address;
use crate::amount::format_btc;
use crate::der::normalize_low_s;
use crate::error::Error;
use crate::hash::soft::Soft;
use crate::tx::PrevTxParser;
use crate::varint::{encode, VarIntReader};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn varint_roundtrip_and_canonical() {
    for n in [
        0u64,
        1,
        0xfc,
        0xfd,
        0xffff,
        0x1_0000,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX,
    ] {
        let (buf, len) = encode(n);
        // Feed one byte at a time to exercise resumption.
        let mut r = VarIntReader::new();
        let mut value = None;
        for (i, b) in buf[..len].iter().enumerate() {
            let (used, v) = r.feed(core::slice::from_ref(b)).unwrap();
            assert_eq!(used, 1);
            assert_eq!(v.is_some(), i == len - 1);
            value = v;
        }
        assert_eq!(value, Some(n));
    }
    assert_eq!(
        VarIntReader::new().feed(&[0xfd, 0xfc, 0x00]),
        Err(Error::Parse)
    );
    assert_eq!(
        VarIntReader::new().feed(&[0xfe, 0xff, 0xff, 0x00, 0x00]),
        Err(Error::Parse)
    );
}

#[test]
fn addresses_match_rust_bitcoin() {
    use bitcoin::{Address, Network, ScriptBuf};
    let scripts = [
        "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac", // P2PKH
        "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87",     // P2SH
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",       // P2WPKH
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", // P2WSH
        "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c", // P2TR
        "0014000000000000000000000000000000000000000000"
            .get(..44)
            .unwrap(),
    ];
    for s in scripts {
        let script = h(s);
        let ours = address::from_script::<Soft>(&script).unwrap();
        let theirs =
            Address::from_script(&ScriptBuf::from_bytes(script.clone()), Network::Bitcoin).unwrap();
        assert_eq!(ours.as_str(), theirs.to_string(), "{s}");
    }
    // Leading zero bytes in a hash become leading '1's in Base58.
    let zero = h("76a914000000000000000000000000000000000000000088ac");
    assert_eq!(
        address::from_script::<Soft>(&zero).unwrap().as_str(),
        "1111111111111111111114oLvT2"
    );
    // Unknown witness versions, OP_RETURN and bare multisig can't be shown.
    for s in [
        "5214751e76e8199196d454941c45d1b3a323f1433bd6",
        "6a0401020304",
        "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179851ae",
    ] {
        assert_eq!(
            address::from_script::<Soft>(&h(s)).unwrap_err(),
            Error::UnsupportedOutput
        );
    }
}

#[test]
fn amounts() {
    for (sats, text) in [
        (0, "0 BTC"),
        (1, "0.00000001 BTC"),
        (150_000, "0.0015 BTC"),
        (100_000_000, "1 BTC"),
        (123_456_789, "1.23456789 BTC"),
        (2_100_000_000_000_000, "21000000 BTC"),
        (u64::MAX, "184467440737.09551615 BTC"),
    ] {
        assert_eq!(format_btc(sats).as_str(), text);
    }
}

#[test]
fn der_low_s() {
    let key = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    for i in 0..64u8 {
        let digest = [i; 32];
        let (sig, _) = key.sign_prehash_recoverable(&digest).unwrap();
        // k256 already signs low-S: flip it to high-S to test normalisation.
        let high = k256::ecdsa::Signature::from_scalars(sig.r().to_bytes(), (-*sig.s()).to_bytes())
            .unwrap();
        for input in [sig.to_der(), high.to_der()] {
            let out = normalize_low_s(input.as_bytes()).unwrap();
            let parsed = k256::ecdsa::Signature::from_der(out.as_bytes()).unwrap();
            assert!(parsed.normalize_s().is_none(), "S must be low");
            assert_eq!(out.as_bytes(), sig.to_der().as_bytes());
            key.verifying_key()
                .verify_prehash(&digest, &parsed)
                .unwrap();
        }
    }
    assert_eq!(
        normalize_low_s(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]).unwrap_err(),
        Error::BadSignature
    );
    assert!(normalize_low_s(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_err());
}

#[test]
fn prev_tx_parser_on_real_transactions() {
    use bitcoin::consensus::encode::serialize;
    // Bitcoin block 170's spend: the first transaction between two people (legacy).
    let raw = h("0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000");
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
    for chunk in [1usize, 7, 255, raw.len()] {
        for vout in 0..2u32 {
            let mut p = PrevTxParser::<Soft>::new(vout);
            for c in raw.chunks(chunk) {
                p.feed(c).unwrap();
            }
            let out = p.finish().unwrap();
            assert_eq!(out.txid, tx.compute_txid().to_byte_array());
            assert_eq!(out.value, tx.output[vout as usize].value.to_sat());
            assert!(out.script.small.is_none() && out.script.vault_hash.is_none());
        }
    }
    // An output index past the end, trailing bytes and truncation are refused.
    let mut p = PrevTxParser::<Soft>::new(2);
    assert_eq!(p.feed(&raw), Err(Error::Parse));
    let mut p = PrevTxParser::<Soft>::new(0);
    let mut extra = raw.clone();
    extra.push(0);
    assert_eq!(p.feed(&extra), Err(Error::Parse));
    let mut p = PrevTxParser::<Soft>::new(0);
    p.feed(&raw[..raw.len() - 1]).unwrap();
    assert!(p.finish().is_err());

    // A SegWit transaction must arrive witness-stripped; its marker is refused.
    let segwit = crate::tests::deposit::funding_tx(
        &[
            0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ],
        50_000,
    );
    let with_witness = serialize(&segwit);
    assert!(!segwit.input[0].witness.is_empty());
    let mut p = PrevTxParser::<Soft>::new(0);
    assert_eq!(p.feed(&with_witness), Err(Error::Parse));
    let stripped = crate::tests::deposit::stripped(&segwit);
    let mut p = PrevTxParser::<Soft>::new(0);
    p.feed(&stripped).unwrap();
    let out = p.finish().unwrap();
    assert_eq!(out.txid, segwit.compute_txid().to_byte_array());
    assert_eq!(out.value, 50_000);
    assert_eq!(out.script.small.unwrap().as_bytes()[..2], [0x00, 0x14]);
}

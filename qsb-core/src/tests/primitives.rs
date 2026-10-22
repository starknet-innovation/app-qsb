use std::string::ToString;
use std::vec::Vec;

use bitcoin::hashes::Hash;
use k256::ecdsa::signature::hazmat::PrehashVerifier;

use crate::address;
use crate::amount::format_btc;
use crate::bip322;
use crate::der::normalize_low_s;
use crate::error::Error;
use crate::hash::soft::Soft;
use crate::path::{self, AddressType, HARDENED};
use crate::signin;
use crate::tx::PrevTxParser;
use crate::varint::{encode, VarIntReader};
use crate::wallet::Wallet;

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

fn path_bytes(elements: &[u32]) -> Vec<u8> {
    let mut v = std::vec![elements.len() as u8];
    for e in elements {
        v.extend_from_slice(&e.to_be_bytes());
    }
    v
}

#[test]
fn paths() {
    let ok = path_bytes(&[84 | HARDENED, HARDENED, HARDENED, 0, 0]);
    let (p, rest) = path::parse(&ok).unwrap();
    assert_eq!(p.address_type(), AddressType::P2wpkh);
    assert!(rest.is_empty());
    let nested = path_bytes(&[49 | HARDENED, HARDENED, 3 | HARDENED, 1, 50_000]);
    assert_eq!(
        path::parse(&nested).unwrap().0.address_type(),
        AddressType::P2shP2wpkh
    );
    for bad in [
        &[44 | HARDENED, HARDENED, HARDENED, 0, 0][..], // legacy purpose
        &[86 | HARDENED, HARDENED, HARDENED, 0, 0],     // taproot purpose
        &[84 | HARDENED, 1 | HARDENED, HARDENED, 0, 0], // testnet coin
        &[84 | HARDENED, HARDENED, 0, 0, 0],            // unhardened account
        &[84 | HARDENED, HARDENED, 101 | HARDENED, 0, 0],
        &[84 | HARDENED, HARDENED, HARDENED, 2, 0],
        &[84 | HARDENED, HARDENED, HARDENED, 0, 50_001],
        &[84 | HARDENED, HARDENED, HARDENED, 0, HARDENED],
        &[84 | HARDENED, HARDENED, HARDENED, 0],
    ] {
        assert!(path::parse(&path_bytes(bad)).is_err(), "{bad:x?}");
    }
}

/// The BIP-322 reference key, published in the BIP (gitleaks:allow): L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k.
fn bip322_key() -> k256::ecdsa::SigningKey {
    let wif = bitcoin::PrivateKey::from_wif("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k")
        .unwrap();
    k256::ecdsa::SigningKey::from_slice(&wif.inner.secret_bytes()).unwrap()
}

fn compressed(key: &k256::ecdsa::SigningKey) -> [u8; 33] {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

#[test]
fn bip322_vectors() {
    // Values from the BIP-322 specification.
    assert_eq!(
        bip322::message_hash::<Soft>(b"").to_vec(),
        h("c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1")
    );
    assert_eq!(
        bip322::message_hash::<Soft>(b"Hello World").to_vec(),
        h("f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a")
    );
    let key = bip322_key();
    let wallet = Wallet::new::<Soft>(compressed(&key), AddressType::P2wpkh);
    assert_eq!(
        wallet.address::<Soft>().as_str(),
        "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
    );
    let display = |mut id: [u8; 32]| {
        id.reverse();
        hex::encode(id)
    };
    assert_eq!(
        display(bip322::to_spend_txid::<Soft>(b"", wallet.script())),
        "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7"
    );
    assert_eq!(
        display(bip322::to_spend_txid::<Soft>(
            b"Hello World",
            wallet.script()
        )),
        "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b"
    );

    // The specification's signatures verify against our digests.
    use base64::Engine;
    for (message, encoded) in [
        (&b""[..], "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="),
        (&b"Hello World"[..], "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="),
    ] {
        let witness = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
        // [2 items] [len] signature||sighash [33] pubkey
        assert_eq!(witness[0], 2);
        let sig_len = witness[1] as usize;
        let der = &witness[2..1 + sig_len];
        assert_eq!(witness[1 + sig_len], 0x01);
        assert_eq!(&witness[3 + sig_len..], &wallet.pubkey[..]);
        let digest = bip322::sighash::<Soft>(message, wallet.script(), &wallet.pkh);
        let sig = k256::ecdsa::Signature::from_der(der).unwrap();
        key.verifying_key().verify_prehash(&digest, &sig).unwrap();
    }
}

#[test]
fn bip322_nested_matches_rust_bitcoin_sighash() {
    // For P2SH-P2WPKH only the to_spend script changes; check the full to_sign
    // digest against rust-bitcoin's BIP-143 implementation.
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Txid, Witness,
    };
    let key = bip322_key();
    let wallet = Wallet::new::<Soft>(compressed(&key), AddressType::P2shP2wpkh);
    assert!(wallet.address::<Soft>().as_str().starts_with('3'));
    let message = b"QSB";
    let to_spend = bip322::to_spend_txid::<Soft>(message, wallet.script());
    let to_sign = Transaction {
        version: transaction::Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: std::vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(to_spend),
                vout: 0
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0),
            witness: Witness::new(),
        }],
        output: std::vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(std::vec![0x6a])
        }],
    };
    let spk = ScriptBuf::from_bytes(crate::script::p2wpkh(&wallet.pkh).to_vec());
    let expected = bitcoin::sighash::SighashCache::new(&to_sign)
        .p2wpkh_signature_hash(0, &spk, Amount::ZERO, bitcoin::EcdsaSighashType::All)
        .unwrap();
    assert_eq!(
        bip322::sighash::<Soft>(message, wallet.script(), &wallet.pkh),
        expected.to_byte_array()
    );
}

const SIGNIN_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

fn signin_message(origin: &str, address: &str) -> std::string::String {
    std::format!(
        "QSB Vault sign-in\nOrigin: {origin}\nAddress: {address}\nNetwork: bitcoin-mainnet\nNonce: 3f2c1e9a-8b7d-4c6e-9f10-2a3b4c5d6e7f\nExpires: 2026-10-19T16:05:00.000Z\nThis signature authorizes this session only. It does not authorize a Bitcoin transaction."
    )
}

#[test]
fn signin_challenge() {
    let m = signin_message("https://qsb.example.org", SIGNIN_ADDRESS);
    let parsed = signin::parse(m.as_bytes(), SIGNIN_ADDRESS).unwrap();
    assert_eq!(parsed.origin, "https://qsb.example.org");
    assert_eq!(parsed.expires, "2026-10-19T16:05:00.000Z");
    assert!(m.len() <= signin::MESSAGE_MAX);

    // Local development servers may use plain http.
    for origin in [
        "http://localhost:5173",
        "http://127.0.0.1:8787",
        "https://qsb.example.org:8443",
    ] {
        let m = signin_message(origin, SIGNIN_ADDRESS);
        assert_eq!(
            signin::parse(m.as_bytes(), SIGNIN_ADDRESS).unwrap().origin,
            origin
        );
    }

    // Another address, a different network, extra lines, a tampered footer, or
    // an origin that isn't one are refused.
    let refused = [
        signin_message(
            "https://qsb.example.org",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        ),
        signin_message("https://qsb.example.org", SIGNIN_ADDRESS)
            .replace("bitcoin-mainnet", "bitcoin-testnet"),
        signin_message("https://qsb example.org", SIGNIN_ADDRESS),
        signin_message("qsb.example.org", SIGNIN_ADDRESS),
        signin_message("http://qsb.example.org", SIGNIN_ADDRESS),
        signin_message("https://qsb.app@evil.example", SIGNIN_ADDRESS),
        signin_message("https://evil.example/qsb.app", SIGNIN_ADDRESS),
        signin_message("https://evil.example?qsb.app", SIGNIN_ADDRESS),
        signin_message("https://QSB.example.org", SIGNIN_ADDRESS),
        signin_message("https://qsb.example.org:", SIGNIN_ADDRESS),
        signin_message("https://qsb.example.org:443443", SIGNIN_ADDRESS),
        signin_message("https://", SIGNIN_ADDRESS),
        signin_message("https://qsb.example.org", SIGNIN_ADDRESS) + "\n",
        signin_message("https://qsb.example.org", SIGNIN_ADDRESS).replace("only.", "only"),
        signin_message("https://qsb.example.org", SIGNIN_ADDRESS)
            .replace("Nonce: 3f2c", "Nonce: 3f2"),
        signin_message("https://qsb.example.org", SIGNIN_ADDRESS)
            .replace("Nonce: 3f2c", "Nonce: 3F2C"),
        signin_message("https://qsb.example.org", SIGNIN_ADDRESS).replace(".000Z", "Z"),
        "Hello World".to_string(),
    ];
    for m in refused {
        assert_eq!(
            signin::parse(m.as_bytes(), SIGNIN_ADDRESS),
            Err(Error::BadMessage),
            "{m}"
        );
    }
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
            assert!(out.script.small.is_none() && out.script.vault.is_none());
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
    let segwit = crate::tests::session::funding_tx(
        &[
            0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ],
        50_000,
    );
    let with_witness = serialize(&segwit);
    assert!(!segwit.input[0].witness.is_empty());
    let mut p = PrevTxParser::<Soft>::new(0);
    assert_eq!(p.feed(&with_witness), Err(Error::Parse));
    let stripped = crate::tests::session::stripped(&segwit);
    let mut p = PrevTxParser::<Soft>::new(0);
    p.feed(&stripped).unwrap();
    let out = p.finish().unwrap();
    assert_eq!(out.txid, segwit.compute_txid().to_byte_array());
    assert_eq!(out.value, 50_000);
    assert_eq!(out.script.small.unwrap().as_bytes()[..2], [0x00, 0x14]);
}

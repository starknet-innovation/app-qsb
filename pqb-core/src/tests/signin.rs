//! SIGN_IN: the challenge template, the message collector and BIP-322 digests.

use std::string::{String, ToString};
use std::vec::Vec;

use bitcoin::hashes::Hash;
use k256::ecdsa::signature::hazmat::PrehashVerifier;

use super::support::{h, test_seed, vault, SoftCurve};
use crate::address;
use crate::error::Error;
use crate::hash::hash160;
use crate::hash::soft::Soft;
use crate::pqb::Curve;
use crate::script::p2wpkh;
use crate::signin::{self, Collector};

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
        signin::message_hash::<Soft>(b"").to_vec(),
        h("c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1")
    );
    assert_eq!(
        signin::message_hash::<Soft>(b"Hello World").to_vec(),
        h("f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a")
    );
    let key = bip322_key();
    let pubkey = compressed(&key);
    let pkh = hash160::<Soft>(&pubkey);
    let script = p2wpkh(&pkh);
    assert_eq!(
        address::from_script::<Soft>(&script).unwrap().as_str(),
        "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
    );
    let display = |mut id: [u8; 32]| {
        id.reverse();
        hex::encode(id)
    };
    assert_eq!(
        display(signin::to_spend_txid::<Soft>(b"", &script)),
        "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7"
    );
    assert_eq!(
        display(signin::to_spend_txid::<Soft>(b"Hello World", &script)),
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
        assert_eq!(&witness[3 + sig_len..], &pubkey[..]);
        let digest = signin::sighash::<Soft>(message, &script, &pkh);
        let sig = k256::ecdsa::Signature::from_der(der).unwrap();
        key.verifying_key().verify_prehash(&digest, &sig).unwrap();
    }
}

#[test]
fn bip322_matches_rust_bitcoin_sighash() {
    // The deposit key of the test vault: check the full to_sign digest against
    // rust-bitcoin's BIP-143 implementation.
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Txid, Witness,
    };
    let dd = vault(test_seed()).deposit_key::<Soft>();
    let pkh = hash160::<Soft>(&SoftCurve::pubkey(&dd));
    let script = p2wpkh(&pkh);
    let message = challenge(
        "https://qsb.example.org",
        address::from_script::<Soft>(&script).unwrap().as_str(),
    );
    let to_spend = signin::to_spend_txid::<Soft>(message.as_bytes(), &script);
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
    let spk = ScriptBuf::from_bytes(script.to_vec());
    let expected = bitcoin::sighash::SighashCache::new(&to_sign)
        .p2wpkh_signature_hash(0, &spk, Amount::ZERO, bitcoin::EcdsaSighashType::All)
        .unwrap();
    assert_eq!(
        signin::sighash::<Soft>(message.as_bytes(), &script, &pkh),
        expected.to_byte_array()
    );
}

const ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

fn challenge(origin: &str, address: &str) -> String {
    std::format!(
        "QSB Vault sign-in\nOrigin: {origin}\nAddress: {address}\nNetwork: bitcoin-mainnet\nNonce: 3f2c1e9a-8b7d-4c6e-9f10-2a3b4c5d6e7f\nExpires: 2026-10-19T16:05:00.000Z\nThis signature authorizes this session only. It does not authorize a Bitcoin transaction."
    )
}

#[test]
fn challenge_template() {
    let m = challenge("https://qsb.example.org", ADDRESS);
    let parsed = signin::parse(m.as_bytes(), ADDRESS).unwrap();
    assert_eq!(parsed.origin, "https://qsb.example.org");
    assert_eq!(parsed.expires, "2026-10-19T16:05:00.000Z");
    assert!(m.len() <= signin::MESSAGE_MAX);

    // Local development servers may use plain http.
    for origin in [
        "http://localhost:5173",
        "http://127.0.0.1:8787",
        "https://qsb.example.org:8443",
    ] {
        let m = challenge(origin, ADDRESS);
        assert_eq!(signin::parse(m.as_bytes(), ADDRESS).unwrap().origin, origin);
    }

    // Another address, a different network, extra lines, a tampered footer, or
    // an origin that isn't one are refused.
    let base = challenge("https://qsb.example.org", ADDRESS);
    let refused = [
        challenge(
            "https://qsb.example.org",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        ),
        base.replace("bitcoin-mainnet", "bitcoin-testnet"),
        challenge("https://qsb example.org", ADDRESS),
        challenge("qsb.example.org", ADDRESS),
        challenge("http://qsb.example.org", ADDRESS),
        challenge("https://qsb.app@evil.example", ADDRESS),
        challenge("https://evil.example/qsb.app", ADDRESS),
        challenge("https://evil.example?qsb.app", ADDRESS),
        challenge("https://QSB.example.org", ADDRESS),
        challenge("https://qsb.example.org:", ADDRESS),
        challenge("https://qsb.example.org:443443", ADDRESS),
        challenge("https://", ADDRESS),
        base.clone() + "\n",
        base.replace("only.", "only"),
        base.replace("QSB Vault sign-in", "QSB Vault sign-in "),
        base.replace("Nonce: 3f2c", "Nonce: 3f2"),
        base.replace("Nonce: 3f2c", "Nonce: 3F2C"),
        base.replace(".000Z", "Z"),
        base.replace('\n', "\r\n"),
        "Hello World".to_string(),
    ];
    for m in refused {
        assert_eq!(
            signin::parse(m.as_bytes(), ADDRESS),
            Err(Error::BadData),
            "{m}"
        );
    }
    assert_eq!(signin::parse(&[0xff, 0xfe], ADDRESS), Err(Error::BadData));
}

#[test]
fn collector() {
    let v = 7u32.to_be_bytes();
    let message: Vec<u8> = std::vec![b'x'; 512];
    let mut first = v.to_vec();
    first.extend_from_slice(&512u16.to_be_bytes());
    first.extend_from_slice(&message[..100]);
    let mut c = Collector::start(&first).unwrap();
    assert_eq!(c.v, 7);
    assert!(!c.is_complete());
    c.push(&message[100..400]).unwrap();
    c.push(&message[400..]).unwrap();
    assert!(c.is_complete());
    assert_eq!(c.message(), &message[..]);
    assert_eq!(c.push(b"y"), Err(Error::BadLength));

    // Empty or oversized messages, a short header, too many bytes, and a vault
    // index out of range.
    for len in [0u16, 513] {
        let mut d = v.to_vec();
        d.extend_from_slice(&len.to_be_bytes());
        assert_eq!(Collector::start(&d).err(), Some(Error::BadData));
    }
    assert_eq!(Collector::start(&v).err(), Some(Error::BadLength));
    let mut d = v.to_vec();
    d.extend_from_slice(&[0, 4]);
    d.extend_from_slice(b"too long");
    assert_eq!(Collector::start(&d).err(), Some(Error::BadLength));
    let mut d = 0x8000_0000u32.to_be_bytes().to_vec();
    d.extend_from_slice(&[0, 1, b'x']);
    assert_eq!(Collector::start(&d).err(), Some(Error::BadData));
}

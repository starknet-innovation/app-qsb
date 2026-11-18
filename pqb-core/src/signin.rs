//! SIGN_IN: the QSB service's sign-in challenge, signed with a vault's deposit key.
//!
//! The QSB service authenticates an address with a BIP-322 signature over a fixed
//! message (`POST /v1/auth/challenge` in qsb-app):
//!
//! ```text
//! QSB Vault sign-in
//! Origin: <app origin>
//! Address: <wallet address>
//! Network: bitcoin-mainnet
//! Nonce: <uuid>
//! Expires: <ISO-8601 UTC time>
//! This signature authorizes this session only. It does not authorize a Bitcoin transaction.
//! ```
//!
//! The app signs nothing else. Every line is checked, the address must be the
//! vault's deposit address, and the origin is shown so the user can spot a
//! phishing site relaying the real service's challenge. The origin must look
//! like one (`https://host[:port]`), so nothing can be hidden in user info or a
//! path.
//!
//! The signature is over BIP-322's virtual `to_sign` transaction, which spends
//! an output that never existed: it can't be replayed as a spend of the deposit
//! address.

use crate::error::{Error, Result};
use crate::hash::{sha256, sha256d, Hashes, Sha256};
use crate::pqb;
use crate::sighash::{p2wpkh_sighash_all, Bip143Common};
use crate::varint;

pub const MESSAGE_MAX: usize = 512;
const ORIGIN_MAX: usize = 120;

const TITLE: &str = "QSB Vault sign-in";
const NETWORK: &str = "Network: bitcoin-mainnet";
const FOOTER: &str =
    "This signature authorizes this session only. It does not authorize a Bitcoin transaction.";

/// What the review shows of a checked challenge.
#[derive(Debug, PartialEq, Eq)]
pub struct SignIn<'a> {
    pub origin: &'a str,
    pub expires: &'a str,
}

fn field<'a>(line: Option<&'a str>, label: &str) -> Result<&'a str> {
    line.and_then(|l| l.strip_prefix(label))
        .ok_or(Error::BadData)
}

/// A lowercase UUID, as `crypto.randomUUID` writes it.
fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// `YYYY-MM-DDTHH:MM:SS.sssZ`, as JavaScript's `Date.toISOString` writes it.
fn is_iso_time(s: &str) -> bool {
    const SHAPE: &[u8; 24] = b"dddd-dd-ddTdd:dd:dd.dddZ";
    s.len() == 24
        && s.bytes().zip(SHAPE.iter()).all(|(c, &p)| {
            if p == b'd' {
                c.is_ascii_digit()
            } else {
                c == p
            }
        })
}

/// A web origin as the server records it: `https://host[:port]`, lowercase,
/// with no user info, path, query or fragment. Plain `http` only for a local
/// development server.
fn is_origin(s: &str) -> bool {
    let (secure, authority) = match (s.strip_prefix("https://"), s.strip_prefix("http://")) {
        (Some(a), _) => (true, a),
        (_, Some(a)) => (false, a),
        _ => return false,
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let host_ok = !host.is_empty()
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host
            .bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'));
    let port_ok =
        port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()));
    let local = host == "localhost" || host == "127.0.0.1";
    s.len() <= ORIGIN_MAX && host_ok && port_ok && (secure || local)
}

/// Check `message` is a sign-in challenge for `address` and return what to show.
pub fn parse<'a>(message: &'a [u8], address: &str) -> Result<SignIn<'a>> {
    let text = core::str::from_utf8(message).map_err(|_| Error::BadData)?;
    let mut lines = text.split('\n');
    if lines.next() != Some(TITLE) {
        return Err(Error::BadData);
    }
    let origin = field(lines.next(), "Origin: ")?;
    let signer = field(lines.next(), "Address: ")?;
    let network_ok = lines.next() == Some(NETWORK);
    let nonce = field(lines.next(), "Nonce: ")?;
    let expires = field(lines.next(), "Expires: ")?;
    let footer_ok = lines.next() == Some(FOOTER);
    if !is_origin(origin)
        || signer != address
        || !network_ok
        || !is_uuid(nonce)
        || !is_iso_time(expires)
        || !footer_ok
        || lines.next().is_some()
    {
        return Err(Error::BadData);
    }
    Ok(SignIn { origin, expires })
}

/// Collects a challenge sent over several APDUs.
pub struct Collector {
    pub v: u32,
    len: usize,
    got: usize,
    buf: [u8; MESSAGE_MAX],
}

impl Collector {
    /// First chunk: `v (4) || message length (2) || message bytes…`.
    pub fn start(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(Error::BadLength);
        }
        let v = pqb::parse_index(&data[..4]).ok_or(Error::BadData)?;
        let len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if len == 0 || len > MESSAGE_MAX {
            return Err(Error::BadData);
        }
        let mut c = Collector {
            v,
            len,
            got: 0,
            buf: [0; MESSAGE_MAX],
        };
        c.push(&data[6..])?;
        Ok(c)
    }

    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        if self.got + data.len() > self.len {
            return Err(Error::BadLength);
        }
        self.buf[self.got..self.got + data.len()].copy_from_slice(data);
        self.got += data.len();
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.got == self.len
    }

    pub fn message(&self) -> &[u8] {
        &self.buf[..self.got]
    }
}

const TAG: &[u8] = b"BIP0322-signed-message";

/// BIP-322's tagged hash of `message`.
pub fn message_hash<H: Hashes>(message: &[u8]) -> [u8; 32] {
    let tag = sha256::<H>(TAG);
    let mut h = H::Sha256::new();
    h.update(&tag);
    h.update(&tag);
    h.update(message);
    h.finalize()
}

/// The txid, in internal byte order, of BIP-322's virtual `to_spend` transaction.
pub fn to_spend_txid<H: Hashes>(message: &[u8], script_pubkey: &[u8]) -> [u8; 32] {
    let mut h = H::Sha256::new();
    h.update(&0u32.to_le_bytes()); // version
    h.update(&[1]); // one input
    h.update(&[0u8; 32]);
    h.update(&0xffff_ffffu32.to_le_bytes());
    h.update(&[34, 0x00, 0x20]); // scriptSig: OP_0 PUSH32 message_hash
    h.update(&message_hash::<H>(message));
    h.update(&0u32.to_le_bytes()); // sequence
    h.update(&[1]); // one output
    h.update(&0u64.to_le_bytes());
    let (len, n) = varint::encode(script_pubkey.len() as u64);
    h.update(&len[..n]);
    h.update(script_pubkey);
    h.update(&0u32.to_le_bytes()); // locktime
    sha256::<H>(&h.finalize())
}

/// The digest `pkh`'s key signs for `message`: BIP-143 SIGHASH_ALL of input 0
/// of BIP-322's `to_sign`, which spends `to_spend` (locked to `script_pubkey`)
/// with amount 0 into a single `OP_RETURN` output.
pub fn sighash<H: Hashes>(message: &[u8], script_pubkey: &[u8], pkh: &[u8; 20]) -> [u8; 32] {
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&to_spend_txid::<H>(message, script_pubkey));
    let common = Bip143Common {
        version: 0,
        hash_prevouts: sha256d::<H>(&outpoint),
        hash_sequence: sha256d::<H>(&0u32.to_le_bytes()),
        // One output: value 0, script OP_RETURN.
        hash_outputs: sha256d::<H>(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0x6a]),
        locktime: 0,
    };
    p2wpkh_sighash_all::<H>(&common, &outpoint, pkh, 0, 0)
}

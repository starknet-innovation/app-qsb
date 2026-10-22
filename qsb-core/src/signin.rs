//! The QSB sign-in challenge.
//!
//! The QSB service authenticates a wallet with a BIP-322 signature over a fixed
//! message (`POST /api/auth/challenge` in qsb-app `server/app.ts`):
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
//! The app signs nothing else. Every line is checked, the address must be the one
//! the signing key controls, and the origin is shown so the user can spot a
//! phishing site relaying the real service's challenge. The origin must look
//! like one (`https://host[:port]`), so nothing can be hidden in user info or a
//! path.

use crate::error::{Error, Result};

pub const MESSAGE_MAX: usize = 512;
const ORIGIN_MAX: usize = 120;

const TITLE: &str = "QSB Vault sign-in";
const NETWORK: &str = "Network: bitcoin-mainnet";
const FOOTER: &str =
    "This signature authorizes this session only. It does not authorize a Bitcoin transaction.";

#[derive(Debug, PartialEq, Eq)]
pub struct SignIn<'a> {
    pub origin: &'a str,
    pub expires: &'a str,
}

fn field<'a>(line: Option<&'a str>, label: &str) -> Result<&'a str> {
    line.and_then(|l| l.strip_prefix(label))
        .ok_or(Error::BadMessage)
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
    let text = core::str::from_utf8(message).map_err(|_| Error::BadMessage)?;
    let mut lines = text.split('\n');
    if lines.next() != Some(TITLE) {
        return Err(Error::BadMessage);
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
        return Err(Error::BadMessage);
    }
    Ok(SignIn { origin, expires })
}

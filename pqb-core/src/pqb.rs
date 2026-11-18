//! The `PQB-v1` derivation profile (BIP "PQB Vault Secret Management"), for
//! pqb's construction version `v1` (pqb commit `82c7cba`).
//!
//! ```text
//! k    = BIP 32 private key at m/83696968'/39'/0'/24'/v'          (from the OS)
//! E    = HMAC-SHA512("bip-entropy-from-k", k)[0:32]                (BIP 85, 24 words)
//! S    = HMAC-SHA256(E, "pqb/vault-seed|hybrid|PQB|v1|real|main")
//! F(l) = SHA256("pqb/v1|" || S || "|" || l)
//!
//! s[j] = F("r2g4-hors-" || dec(j))[0:20]     w[j] = SHA256(s[j])     c[j] = RIPEMD160(w[j])
//! u    = F("r5close-indep-menu-" || tag)
//! x[i] = (int(SHA256(u || "|" || dec(i))) >> 6) | 2^250
//! g[i] = DER(r, x[i]) || 0x01                m[i] = SHA1(g[i])
//!        r = 1 for the pinning menu, 0x81 for the round-0 and round-1 menus
//! d    = int(F("cosig-key")) mod (n-1) + 1   q = HASH160(d·G)
//! dd   = int(HMAC-SHA512(S, "pqb/deposit-key/v1")[0:32]) mod (n-1) + 1
//! R    = SHA256("PQB-v1/root" || c[0..109] || m_pin || m_round0 || m_round1 || q)
//! ```
//!
//! This build serves `main` only. The BIP also binds seeds to `testnet4` and
//! `regtest`; the app leaves those to software wallets.

use crate::der::{self, DerSignature};
use crate::hash::{Hashes, Sha256};
use crate::sha1::sha1;
use crate::template::{self, SCRIPT_LEN, SLOTS, TEMPLATE};
use crate::u256::{lift_x, N, P, U256};

pub const PROFILE: &[u8] = b"PQB-v1";
pub const TABLE: usize = 109;
pub const COMMITMENTS: usize = 154;
pub const ROUND0: usize = 8;
pub const ROUND1: usize = 9;
pub const STAGES: usize = 3;
pub const MENU_WIDTHS: [usize; STAGES] = [12, 16, 16];
const MENU_TAGS: [&[u8]; STAGES] = [b"pin", b"round0", b"round1"];
/// Root index of each stage's first menu commitment.
const MENU_ROOT: [usize; STAGES] = [109, 121, 137];
const COSIG_ROOT: usize = 153;
/// Each menu stage's `r`: pinning, round 0, round 1.
pub const MENU_R: [u8; STAGES] = [1, 0x81, 0x81];
pub const NETWORK: &str = "main";
pub const MAX_VAULT_INDEX: u32 = 0x7fff_ffff;

const H: u32 = 0x8000_0000;
/// m/83696968'/39'/0'/24': the BIP 85 BIP 39 application, English, 24 words. The
/// vault index v' follows.
pub const BIP85_PREFIX: [u32; 4] = [83_696_968 | H, 39 | H, H, 24 | H];

const SEED_TAG: &[u8] = b"pqb/vault-seed|hybrid|PQB|v1|real|main";

/// Overwrite secret material. This crate has no `unsafe`; `black_box` keeps the
/// stores from being optimised away. The device crate wipes its own buffers.
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    core::hint::black_box(buf);
}

/// The full BIP 32 path of vault `v`.
pub fn bip85_path(v: u32) -> [u32; 5] {
    let [a, b, c, d] = BIP85_PREFIX;
    [a, b, c, d, v | H]
}

/// E, BIP 85 child entropy, from the private key `k` at the vault's path.
pub fn child_entropy<Hs: Hashes>(k: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hs::hmac_sha512(b"bip-entropy-from-k", k);
    let mut e = [0u8; 32];
    e.copy_from_slice(&mac[..32]);
    wipe(&mut mac);
    e
}

/// The 32-byte vault seed `S` for the network this build serves.
pub fn vault_seed<Hs: Hashes>(e: &[u8; 32]) -> [u8; 32] {
    Hs::hmac_sha256(e, SEED_TAG)
}

/// The device's record key for a seed: SHA256("PQB-v1/wallet" || S of vault 0)[0..16).
/// It names one BIP 32 root (passphrases give other roots) and says nothing about it.
pub fn wallet_id<Hs: Hashes>(seed0: &[u8; 32]) -> [u8; 16] {
    let mut h = Hs::Sha256::new();
    h.update(PROFILE);
    h.update(b"/wallet");
    h.update(seed0);
    let full = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// The elliptic-curve operations the secure element supplies.
pub trait Curve {
    /// The compressed public key of the private key `d` (1 <= d < n).
    fn pubkey(d: &[u8; 32]) -> [u8; 33];
    /// k·P for an uncompressed point `04 || x || y`, uncompressed.
    fn mul(point: &[u8; 65], k: &[u8; 32]) -> Option<[u8; 65]>;
}

/// ASCII decimal of `i`, without leading zeros.
fn dec(i: usize, buf: &mut [u8; 3]) -> &[u8] {
    if i >= 100 {
        buf[0] = b'0' + (i / 100) as u8;
        buf[1] = b'0' + (i / 10 % 10) as u8;
        buf[2] = b'0' + (i % 10) as u8;
        &buf[..3]
    } else if i >= 10 {
        buf[0] = b'0' + (i / 10) as u8;
        buf[1] = b'0' + (i % 10) as u8;
        &buf[..2]
    } else {
        buf[0] = b'0' + i as u8;
        &buf[..1]
    }
}

/// `int(b) mod (n - 1) + 1`, as 32 big-endian bytes.
pub fn key_from_bytes(b: &[u8; 32]) -> [u8; 32] {
    let n1 = N.m.sub(&U256::ONE).0;
    let v = U256::from_be(b);
    let (d, borrow) = v.sub(&n1);
    let v = if borrow { v } else { d };
    v.add(&U256::ONE).0.to_be()
}

/// The menu signature `g = DER(r, x) || 0x01`.
#[derive(Clone, Copy)]
pub struct MenuSig {
    der: DerSignature,
}

impl MenuSig {
    pub fn len(&self) -> usize {
        self.der.as_bytes().len() + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Write `g` into `out` (at least 73 bytes); returns its length.
    pub fn write(&self, out: &mut [u8]) -> usize {
        let d = self.der.as_bytes();
        out[..d.len()].copy_from_slice(d);
        out[d.len()] = 0x01;
        d.len() + 1
    }

    pub fn commitment(&self) -> [u8; 20] {
        let mut buf = [0u8; 73];
        let n = self.write(&mut buf);
        let c = sha1(&buf[..n]);
        wipe(&mut buf);
        c
    }
}

/// One vault key set: the seed and the co-signing key's hash, which takes a
/// curve multiplication.
pub struct Vault {
    seed: [u8; 32],
    q: [u8; 20],
}

impl Drop for Vault {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

impl Vault {
    /// Takes ownership of `seed` and wipes it on drop.
    pub fn new<Hs: Hashes, C: Curve>(seed: [u8; 32]) -> Vault {
        let mut v = Vault { seed, q: [0; 20] };
        let mut d = v.cosign_key::<Hs>();
        let q = C::pubkey(&d);
        wipe(&mut d);
        v.q = crate::hash::hash160::<Hs>(&q);
        v
    }

    /// F(label) for a label given in parts.
    fn f<Hs: Hashes>(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Hs::Sha256::new();
        h.update(b"pqb/v1|");
        h.update(&self.seed);
        h.update(b"|");
        for p in parts {
            h.update(p);
        }
        h.finalize()
    }

    /// The round-0 preimage s[j].
    pub fn table_secret<Hs: Hashes>(&self, j: usize) -> [u8; 20] {
        let mut d = [0u8; 3];
        let mut full = self.f::<Hs>(&[b"r2g4-hors-", dec(j, &mut d)]);
        let mut s = [0u8; 20];
        s.copy_from_slice(&full[..20]);
        wipe(&mut full);
        s
    }

    /// The round-1 preimage w[j] = SHA256(s[j]).
    pub fn table_round1<Hs: Hashes>(&self, j: usize) -> [u8; 32] {
        let mut s = self.table_secret::<Hs>(j);
        let w = crate::hash::sha256::<Hs>(&s);
        wipe(&mut s);
        w
    }

    pub fn table_commitment<Hs: Hashes>(&self, j: usize) -> [u8; 20] {
        let mut w = self.table_round1::<Hs>(j);
        let c = Hs::ripemd160(&w);
        wipe(&mut w);
        c
    }

    /// The `r` every menu signature of `stage` shares.
    pub fn menu_r(&self, stage: usize) -> U256 {
        U256([MENU_R[stage] as u32, 0, 0, 0, 0, 0, 0, 0])
    }

    /// The menu scalar x[i] of `stage`, in [2^250, 2^251).
    pub fn menu_scalar<Hs: Hashes>(&self, stage: usize, i: usize) -> [u8; 32] {
        let mut u = self.f::<Hs>(&[b"r5close-indep-menu-", MENU_TAGS[stage]]);
        let mut d = [0u8; 3];
        let mut h = Hs::Sha256::new();
        h.update(&u);
        h.update(b"|");
        h.update(dec(i, &mut d));
        wipe(&mut u);
        let mut x = h.finalize();
        // >> 6 on the big-endian bytes, then set bit 250.
        for k in (1..32).rev() {
            x[k] = (x[k] >> 6) | (x[k - 1] << 2);
        }
        x[0] = (x[0] >> 6) | 0x04;
        x
    }

    pub fn menu_signature<Hs: Hashes>(&self, stage: usize, i: usize) -> MenuSig {
        let mut x = self.menu_scalar::<Hs>(stage, i);
        let sig = MenuSig {
            der: der::encode(&self.menu_r(stage).to_be(), &x),
        };
        wipe(&mut x);
        sig
    }

    /// The private co-signing key d.
    pub fn cosign_key<Hs: Hashes>(&self) -> [u8; 32] {
        let mut f = self.f::<Hs>(&[b"cosig-key"]);
        let d = key_from_bytes(&f);
        wipe(&mut f);
        d
    }

    /// The private key dd of the vault's P2WPKH deposit address.
    pub fn deposit_key<Hs: Hashes>(&self) -> [u8; 32] {
        let mut mac = Hs::hmac_sha512(&self.seed, b"pqb/deposit-key/v1");
        let mut b = [0u8; 32];
        b.copy_from_slice(&mac[..32]);
        wipe(&mut mac);
        let d = key_from_bytes(&b);
        wipe(&mut b);
        d
    }

    /// Commitment `i` in root order: c[0..109], m_pin, m_round0, m_round1, q.
    pub fn commitment<Hs: Hashes>(&self, i: usize) -> [u8; 20] {
        if i < TABLE {
            return self.table_commitment::<Hs>(i);
        }
        if i == COSIG_ROOT {
            return self.q;
        }
        let stage = (0..STAGES).rev().find(|&k| i >= MENU_ROOT[k]).unwrap_or(0);
        self.menu_signature::<Hs>(stage, i - MENU_ROOT[stage])
            .commitment()
    }

    /// The commitment root R.
    pub fn root<Hs: Hashes>(&self) -> [u8; 32] {
        self.root_and_screen::<Hs>().0
    }

    /// The commitment root R, or `None` when the vault fails the BIP's DER
    /// screen: one of its commitments, each a 20-byte push in the script,
    /// parses as a strict DER signature (about 2^-33 per vault). Such a vault
    /// must never be funded; allocation skips its index. The template's other
    /// 20-byte pushes and the item under the table are constants, checked once
    /// by the host tests.
    pub fn screened_root<Hs: Hashes>(&self) -> Option<[u8; 32]> {
        match self.root_and_screen::<Hs>() {
            (root, true) => Some(root),
            (_, false) => None,
        }
    }

    fn root_and_screen<Hs: Hashes>(&self) -> ([u8; 32], bool) {
        let mut h = Hs::Sha256::new();
        h.update(PROFILE);
        h.update(b"/root");
        let mut clean = true;
        for i in 0..COMMITMENTS {
            let c = self.commitment::<Hs>(i);
            clean &= !der::is_strict(&c);
            h.update(&c);
        }
        (h.finalize(), clean)
    }

    /// Feed the locking script, in order, to `sink`.
    pub fn script_into<Hs: Hashes>(&self, mut sink: impl FnMut(&[u8])) {
        let mut pos = 0;
        for k in 0..SLOTS {
            let (at, i) = template::slot(k);
            sink(&TEMPLATE[pos..at]);
            sink(&self.commitment::<Hs>(i));
            pos = at + 20;
        }
        sink(&TEMPLATE[pos..]);
    }

    /// SHA-256 of the locking script (the "script hash" of the BIP's records).
    pub fn script_hash<Hs: Hashes>(&self) -> [u8; 32] {
        let mut h = Hs::Sha256::new();
        self.script_into::<Hs>(|b| h.update(b));
        h.finalize()
    }

    /// Bytes `offset..offset + out.len()` of the locking script.
    pub fn script_chunk<Hs: Hashes>(&self, offset: usize, out: &mut [u8]) {
        let end = offset + out.len();
        out.copy_from_slice(&TEMPLATE[offset..end]);
        for k in 0..SLOTS {
            let (at, i) = template::slot(k);
            if at + 20 <= offset || at >= end {
                continue;
            }
            let c = self.commitment::<Hs>(i);
            for (b, &cb) in c.iter().enumerate() {
                let p = at + b;
                if p >= offset && p < end {
                    out[p - offset] = cb;
                }
            }
        }
    }

    /// The solver's menu point (r^-1 · x[i]) · R for `stage`, where R is the point
    /// with x-coordinate r + n·(variant >> 1) and y parity (variant & 1).
    /// `None` when that point does not exist.
    pub fn menu_point<Hs: Hashes, C: Curve>(
        &self,
        stage: usize,
        variant: u8,
        i: usize,
    ) -> Option<[u8; 33]> {
        let r = self.menu_r(stage);
        let x = if variant & 2 != 0 {
            let (x, carry) = r.add(&N.m);
            if carry {
                return None;
            }
            x
        } else {
            r
        };
        if !x.lt(&P.m) {
            return None;
        }
        let y = lift_x(&x, variant & 1 == 1)?;
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x.to_be());
        point[33..].copy_from_slice(&y.to_be());
        let mut s = self.menu_scalar::<Hs>(stage, i);
        let mut k = N.mul(&N.inv(&r), &U256::from_be(&s)).to_be();
        wipe(&mut s);
        let out = C::mul(&point, &k);
        wipe(&mut k);
        let out = out?;
        let mut c = [0u8; 33];
        c[0] = 0x02 | (out[64] & 1);
        c[1..].copy_from_slice(&out[1..33]);
        Some(c)
    }
}

/// The root's first 8 bytes as four groups of four hex digits, e.g. "6c37 5dd4 d49e 27a6".
pub fn fingerprint(root: &[u8; 32]) -> [u8; 19] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [b' '; 19];
    for (i, b) in root[..8].iter().enumerate() {
        let at = i * 2 + i / 2;
        out[at] = HEX[(b >> 4) as usize];
        out[at + 1] = HEX[(b & 15) as usize];
    }
    out
}

/// A vault index from 4 big-endian bytes, below 2^31.
pub fn parse_index(b: &[u8]) -> Option<u32> {
    let v = u32::from_be_bytes(b.try_into().ok()?);
    (v <= MAX_VAULT_INDEX).then_some(v)
}

/// Length of the locking script, for callers that don't import the template.
pub const SCRIPT_LENGTH: usize = SCRIPT_LEN;

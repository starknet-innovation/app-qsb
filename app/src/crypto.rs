//! The secure element's hashes, key derivation, curve arithmetic and signing.

use ledger_device_sdk::ecc::{bip32_derive, CurvesId, EcPoint, Secp256k1, Secret};
use ledger_device_sdk::hash::{ripemd::Ripemd160, sha2::Sha2_256, HashInit};
use ledger_device_sdk::hmac::{
    sha2::Sha2_256 as HmacSha256, sha2::Sha2_512 as HmacSha512, HMACInit,
};
use ledger_device_sdk::sys;
use pqb_core::der::{normalize_low_s, DerSignature};
use pqb_core::hash::{Hashes, Sha256};
use pqb_core::pqb::{self, Curve, Vault};

use crate::AppSW;

// The cx hash calls only fail on invalid arguments (a bad context or output
// length), which this code never passes. Should one fail anyway, the app panics:
// the panic handler answers 0xE000 and exits, so nothing is signed or released.

pub struct DeviceSha256(Sha2_256);

// A context keeps the last message block it hashed, which can be a secret:
// wipe it however it ends.
impl Drop for DeviceSha256 {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Sha256 for DeviceSha256 {
    fn new() -> Self {
        DeviceSha256(Sha2_256::new())
    }

    fn update(&mut self, data: &[u8]) {
        if self.0.update(data).is_err() {
            panic!("sha256");
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if self.0.finalize(&mut out).is_err() {
            panic!("sha256");
        }
        out
    }
}

pub struct DeviceHashes;

impl Hashes for DeviceHashes {
    type Sha256 = DeviceSha256;

    fn ripemd160(data: &[u8]) -> [u8; 20] {
        let mut out = [0u8; 20];
        let mut h = Ripemd160::new();
        let ok = h.hash(data, &mut out).is_ok();
        wipe(&mut h);
        if !ok {
            panic!("ripemd160");
        }
        out
    }

    fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new(key);
        // A shorter buffer would be filled without an error: always 32 bytes.
        let mut out = [0u8; 32];
        let ok = mac.update(message).is_ok() && mac.finalize(&mut out) == Ok(32);
        // The context holds the key XORed with the pad and has no Drop: wipe it.
        wipe(&mut mac);
        if !ok {
            panic!("hmac");
        }
        out
    }

    fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
        let mut mac = HmacSha512::new(key);
        let mut out = [0u8; 64];
        let ok = mac.update(message).is_ok() && mac.finalize(&mut out) == Ok(64);
        wipe(&mut mac);
        if !ok {
            panic!("hmac");
        }
        out
    }
}

/// The secure element's secp256k1.
pub struct DeviceCurve;

impl Curve for DeviceCurve {
    fn pubkey(d: &[u8; 32]) -> [u8; 33] {
        let key = Secp256k1::from(d);
        let Ok(point) = key.public_key() else {
            panic!("pubkey");
        };
        let p = point.pubkey;
        // 0x04 || X || Y → (0x02 | parity of Y) || X
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02 | (p[64] & 1);
        compressed[1..].copy_from_slice(&p[1..33]);
        compressed
    }

    fn mul(point: &[u8; 65], k: &[u8; 32]) -> Option<[u8; 65]> {
        let mut p = EcPoint::new(CurvesId::Secp256k1).ok()?;
        p.init(&point[1..33], &point[33..]).ok()?;
        // Randomised: the scalar is derived from a menu secret.
        p.rnd_scalarmul(k).ok()?;
        let mut out = [0u8; 65];
        out[0] = 0x04;
        let (x, y) = out[1..].split_at_mut(32);
        p.export(x, y).ok()?;
        Some(out)
    }
}

/// Overwrite `value` with zeros in a way the compiler can't drop.
pub fn wipe<T>(value: &mut T) {
    // SAFETY: `value` is a valid, exclusive reference to `size_of::<T>()` bytes.
    unsafe { sys::explicit_bzero((value as *mut T).cast(), core::mem::size_of::<T>()) };
}

/// The vault seed S of vault `v`: BIP 85 child entropy at m/83696968'/39'/0'/24'/v',
/// bound to mainnet. The path prefix is declared in the install parameters.
pub fn vault_seed(v: u32) -> Result<[u8; 32], AppSW> {
    let mut node = Secret::<64>::new();
    bip32_derive(
        CurvesId::Secp256k1,
        &pqb::bip85_path(v),
        node.as_mut(),
        None,
    )
    .map_err(|_| AppSW::KeyDeriveFail)?;
    let mut k = [0u8; 32];
    k.copy_from_slice(&node.as_ref()[..32]);
    // The OS throws (and the app exits) on a failed derivation; a key of zeros
    // would still mean something went wrong.
    if k.iter().all(|&b| b == 0) {
        return Err(AppSW::KeyDeriveFail);
    }
    let mut e = pqb::child_entropy::<DeviceHashes>(&k);
    wipe(&mut k);
    let s = pqb::vault_seed::<DeviceHashes>(&e);
    wipe(&mut e);
    Ok(s)
}

/// Vault `v`'s key set.
pub fn vault(v: u32) -> Result<Vault, AppSW> {
    Ok(Vault::new::<DeviceHashes, DeviceCurve>(vault_seed(v)?))
}

/// This seed's record key.
pub fn wallet_id() -> Result<[u8; 16], AppSW> {
    let mut s0 = vault_seed(0)?;
    let id = pqb::wallet_id::<DeviceHashes>(&s0);
    wipe(&mut s0);
    Ok(id)
}

/// ECDSA (RFC 6979) signature of `digest` by the private key `d`, DER, low S.
pub fn sign(d: &[u8; 32], digest: &[u8; 32]) -> Result<DerSignature, AppSW> {
    let key = Secp256k1::from(d);
    let (sig, len, _) = key
        .deterministic_sign(digest)
        .map_err(|_| AppSW::SignFail)?;
    let der = sig.get(..len as usize).ok_or(AppSW::SignFail)?;
    normalize_low_s(der).map_err(|_| AppSW::SignFail)
}

//! The secure element's hashes, key derivation and signing.

use ledger_device_sdk::ecc::{Secp256k1, Secret, SeedDerive};
use ledger_device_sdk::hash::{ripemd::Ripemd160, sha2::Sha2_256, HashInit};
use ledger_device_sdk::hmac::{sha2::Sha2_256 as HmacSha256, HMACInit};
use ledger_device_sdk::sys;
use qsb_core::der::{normalize_low_s, DerSignature};
use qsb_core::hash::{Hashes, Sha256};
use qsb_core::path::Path;
use qsb_core::wallet::Wallet;

use crate::AppSW;

// The cx hash calls only fail on invalid arguments (a bad context or output
// length), which this code never passes. Should one fail anyway, the app panics:
// the panic handler answers 0xE000 and exits, so nothing is signed.

pub struct DeviceSha256(Sha2_256);

// A context keeps the last message block it hashed, which can be a HORS secret:
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
}

/// Overwrite `value` with zeros in a way the compiler can't drop.
pub fn wipe<T>(value: &mut T) {
    // SAFETY: `value` is a valid, exclusive reference to `size_of::<T>()` bytes.
    unsafe { sys::explicit_bzero((value as *mut T).cast(), core::mem::size_of::<T>()) };
}

/// The SLIP-0021 path for the label "QSB-HORS": `0x00 || label`.
const HORS_LABEL: &[u8] = b"\x00QSB-HORS";

/// `K`, the SLIP-0021 key the HORS secrets are derived from (`qsb_core::hors`).
/// The label is declared in the install parameters (`path_slip21`); the OS
/// refuses any other. Zeroized when dropped.
pub fn hors_key() -> Result<Secret<32>, AppSW> {
    // The OS reads the path as u32s and checks 4 bytes per path byte: keep it
    // aligned and that long.
    let mut path = [0u32; HORS_LABEL.len()];
    // SAFETY: `path` holds 4 × 9 bytes, more than the 9 copied.
    unsafe {
        core::ptr::copy_nonoverlapping(
            HORS_LABEL.as_ptr(),
            path.as_mut_ptr().cast::<u8>(),
            HORS_LABEL.len(),
        );
    }
    // The OS writes SLIP-0021's Key(N), the node's last 32 bytes, to the first
    // 32 bytes of a 64-byte buffer (as Speculos and the Ledger Bitcoin app agree).
    let mut node = Secret::<64>::new();
    // SAFETY: the buffers are as long as the OS requires; the curve is ignored for SLIP-21.
    unsafe {
        sys::os_perso_derive_node_with_seed_key(
            sys::HDW_SLIP21,
            sys::CX_CURVE_SECP256K1,
            path.as_ptr(),
            HORS_LABEL.len() as u32,
            node.as_mut().as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        );
    }
    let mut key = Secret::<32>::new();
    key.as_mut().copy_from_slice(&node.as_ref()[..32]);
    // The OS throws (and the app exits) on a failed derivation; a key of zeros
    // would still mean something went wrong.
    if key.as_ref().iter().all(|&b| b == 0) {
        return Err(AppSW::KeyDeriveFail);
    }
    Ok(key)
}

/// The wallet at `path`, which `qsb_core::path::parse` has already validated:
/// the SDK's derivation does not report errors.
pub fn wallet(path: &Path) -> Result<Wallet, AppSW> {
    let key = Secp256k1::derive_from_path(&path.elements);
    let point = key.public_key().map_err(|_| AppSW::KeyDeriveFail)?.pubkey;
    // 0x04 || X || Y → (0x02 | parity of Y) || X
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02 | (point[64] & 1);
    compressed[1..].copy_from_slice(&point[1..33]);
    Ok(Wallet::new::<DeviceHashes>(compressed, path.address_type()))
}

/// ECDSA (RFC 6979) signature of `digest` by the key at `path`, DER, low S.
pub fn sign(path: &Path, digest: &[u8; 32]) -> Result<DerSignature, AppSW> {
    let (sig, len, _) = Secp256k1::derive_from_path(&path.elements)
        .deterministic_sign(digest)
        .map_err(|_| AppSW::SignFail)?;
    let der = sig.get(..len as usize).ok_or(AppSW::SignFail)?;
    normalize_low_s(der).map_err(|_| AppSW::SignFail)
}

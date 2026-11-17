//! Hash primitives the core needs, supplied by the caller.
//!
//! On the device they are backed by the secure element's `cx` library; host tests
//! use pure-Rust implementations. Keeping them behind a trait keeps this crate free
//! of any SDK dependency.

/// An incremental SHA-256 context.
pub trait Sha256: Sized {
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; 32];
}

/// The set of hash functions the core uses.
pub trait Hashes {
    type Sha256: Sha256;
    fn ripemd160(data: &[u8]) -> [u8; 20];
    fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32];
    fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64];
}

pub fn sha256<H: Hashes>(data: &[u8]) -> [u8; 32] {
    let mut h = H::Sha256::new();
    h.update(data);
    h.finalize()
}

/// SHA-256 applied twice, as Bitcoin uses for txids and sighashes.
pub fn sha256d<H: Hashes>(data: &[u8]) -> [u8; 32] {
    sha256::<H>(&sha256::<H>(data))
}

/// Finish a running SHA-256 and hash the result once more.
pub fn finalize_double<H: Hashes>(h: H::Sha256) -> [u8; 32] {
    sha256::<H>(&h.finalize())
}

/// RIPEMD-160 of SHA-256.
pub fn hash160<H: Hashes>(data: &[u8]) -> [u8; 20] {
    H::ripemd160(&sha256::<H>(data))
}

#[cfg(test)]
pub mod soft {
    //! Pure-Rust hashes for host tests.
    use sha2::Digest;

    pub struct SoftSha256(sha2::Sha256);

    impl super::Sha256 for SoftSha256 {
        fn new() -> Self {
            SoftSha256(sha2::Sha256::new())
        }
        fn update(&mut self, data: &[u8]) {
            self.0.update(data)
        }
        fn finalize(self) -> [u8; 32] {
            self.0.finalize().into()
        }
    }

    pub struct Soft;

    impl super::Hashes for Soft {
        type Sha256 = SoftSha256;
        fn ripemd160(data: &[u8]) -> [u8; 20] {
            ripemd::Ripemd160::digest(data).into()
        }
        fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
            use hmac::Mac;
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("any key length");
            mac.update(message);
            mac.finalize().into_bytes().into()
        }
        fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
            use hmac::Mac;
            let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key).expect("any key length");
            mac.update(message);
            mac.finalize().into_bytes().into()
        }
    }
}

//! Host tests. Vectors come from the BIP's reference.py and vectors.json, from
//! tests/application_client/pqb.py, and from the pqb implementation's scripts
//! (tests/fixtures).

mod deposit;
mod pqb;
mod primitives;
mod record;
mod withdraw;

pub mod support {
    use std::vec::Vec;

    use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use k256::elliptic_curve::PrimeField;

    use crate::hash::soft::Soft;
    use crate::pqb::{Curve, Vault};

    /// k256 in place of the secure element.
    pub struct SoftCurve;

    impl Curve for SoftCurve {
        fn pubkey(d: &[u8; 32]) -> [u8; 33] {
            let key = k256::SecretKey::from_slice(d).unwrap();
            key.public_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap()
        }

        fn mul(point: &[u8; 65], k: &[u8; 32]) -> Option<[u8; 65]> {
            let ep = k256::EncodedPoint::from_bytes(point).ok()?;
            let p: Option<k256::AffinePoint> = k256::AffinePoint::from_encoded_point(&ep).into();
            let s: Option<k256::Scalar> = k256::Scalar::from_repr((*k).into()).into();
            let r = (k256::ProjectivePoint::from(p?) * s?).to_affine();
            r.to_encoded_point(false).as_bytes().try_into().ok()
        }
    }

    pub fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    pub fn h32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    /// The BIP's test seed 00 01 .. 1f.
    pub fn test_seed() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    pub fn vault(seed: [u8; 32]) -> Vault {
        Vault::new::<Soft, SoftCurve>(seed)
    }

    /// pqb's script for the test seed.
    pub fn pqb_script() -> Vec<u8> {
        h(include_str!("../../../tests/fixtures/pqb-script-seed0123.hex").trim())
    }
}

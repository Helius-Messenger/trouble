//! `embassy-crypto` P-256 ECDH driver backed by `p256-cortex-m4`.
//!
//! LESC pairing does two P-256 scalar multiplications (public key + ECDH). With
//! the generic software `p256` each takes ~310 ms on a 64 MHz Cortex-M4
//! (nRF52840), blocking the BLE executor for ~0.9 s per pairing; the
//! hand-written ARMv7E-M assembly of `p256-cortex-m4` does them in ~6 ms and
//! ~18 ms. Enabled by the `security-p256-cortex-m4` feature, which registers
//! [`Driver`] as the global `embassy_crypto::driver::P256Ecdh`. Off Cortex-M4/M33
//! the crate falls back to the generic `p256` with the same API.

use embassy_crypto::driver::{P256Ecdh, P256Point, P256Scalar};
use embassy_crypto::Error;
use p256_cortex_m4::{PublicKey, SecretKey};
// The asm types derive `Zeroize` but do not wipe on drop; the fallback wraps
// RustCrypto types that do.
#[cfg(all(target_arch = "arm", target_os = "none"))]
use zeroize::Zeroize;

pub(crate) struct Driver;

impl P256Ecdh for Driver {
    fn public_key(k: &P256Scalar) -> Result<P256Point, Error> {
        // `from_bytes` rejects 0 and anything >= n.
        #[allow(unused_mut)]
        let mut sk = SecretKey::from_bytes(k.0).map_err(|_| Error::InvalidKey)?;
        let pk = sk.public_key();
        #[cfg(all(target_arch = "arm", target_os = "none"))]
        sk.zeroize();
        Ok(P256Point { x: pk.x(), y: pk.y() })
    }

    fn shared_secret(k: &P256Scalar, peer: &P256Point) -> Result<[u8; 32], Error> {
        let mut xy = [0u8; 64];
        xy[..32].copy_from_slice(&peer.x);
        xy[32..].copy_from_slice(&peer.y);
        // Validates that the untrusted peer point is on the curve.
        let peer = PublicKey::from_untagged_bytes(&xy).map_err(|_| Error::InvalidKey)?;
        #[allow(unused_mut)]
        let mut sk = SecretKey::from_bytes(k.0).map_err(|_| Error::InvalidKey)?;
        #[allow(unused_mut)]
        let mut shared = sk.agree(&peer);
        let out = *shared.as_bytes();
        #[cfg(all(target_arch = "arm", target_os = "none"))]
        {
            sk.zeroize();
            shared.zeroize();
        }
        Ok(out)
    }
}

// Unit tests link `embassy-crypto-rustcrypto`'s P-256 ECDH driver; registering
// this one too would be a duplicate symbol. The tests below call `Driver`
// directly and compare it against that reference.
#[cfg(not(test))]
embassy_crypto::p256_ecdh_impl!(Driver);

#[cfg(test)]
mod tests {
    use embassy_crypto::p256 as ec;

    use super::*;

    #[test]
    fn matches_reference_driver() {
        let a = [0x11u8; 32];
        let b = [0x5au8; 32];
        let ref_a = ec::SecretKey::from_bytes(&a).unwrap();
        let ref_b = ec::SecretKey::from_bytes(&b).unwrap();
        let ref_pub_a = ref_a.public_key().unwrap();
        let ref_pub_b = ref_b.public_key().unwrap();

        let pub_a = Driver::public_key(&P256Scalar(a)).unwrap();
        assert_eq!(&pub_a.x, ref_pub_a.x());
        assert_eq!(&pub_a.y, ref_pub_a.y());

        let pub_b = Driver::public_key(&P256Scalar(b)).unwrap();
        let shared = Driver::shared_secret(&P256Scalar(a), &pub_b).unwrap();
        assert_eq!(&shared, ref_a.diffie_hellman(&ref_pub_b).unwrap().as_bytes());
        assert_eq!(shared, Driver::shared_secret(&P256Scalar(b), &pub_a).unwrap());
    }

    #[test]
    fn rejects_off_curve_peer() {
        // Only the peer point is untrusted here: `embassy_crypto` rejects zero or
        // out-of-range private scalars before calling a driver (the asm also
        // range-checks them; the host `p256` 0.9 fallback just debug-asserts).
        let mut off_curve = Driver::public_key(&P256Scalar([0x11; 32])).unwrap();
        off_curve.y[31] ^= 1;
        assert_eq!(
            Driver::shared_secret(&P256Scalar([0x22; 32]), &off_curve),
            Err(Error::InvalidKey)
        );
    }
}

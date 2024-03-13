//! Cryptography dispatch for the lakers crate
//!
//! This crate is used by lakers to decide which cryptographic back-end to use. Its presence
//! avoids the need for all lakers types to be generic over a back-end, which would then be
//! provided by the user at initialization time. On the long run, its type may turn into a
//! default associated type.
#![no_std]

/// Convenience re-export
pub use lakers_shared::Crypto as CryptoTrait;

#[cfg(feature = "hacspec")]
pub type Crypto = lakers_crypto_hacspec::Crypto;

#[cfg(feature = "hacspec")]
pub const fn default_crypto() -> Crypto {
    lakers_crypto_hacspec::Crypto
}

// FIXME: Does not work with crypto-as-trait yet
#[cfg(feature = "cc2538")]
pub use lakers_crypto_cc2538::*;

#[cfg(any(feature = "psa", feature = "psa-rust",))]
pub type Crypto = lakers_crypto_psa::Crypto;

#[cfg(any(feature = "psa", feature = "psa-rust",))]
pub const fn default_crypto() -> Crypto {
    lakers_crypto_psa::Crypto
}

#[cfg(feature = "rustcrypto")]
pub type Crypto = lakers_crypto_rustcrypto::Crypto<rand_core::OsRng>;

#[cfg(feature = "rustcrypto")]
pub const fn default_crypto() -> Crypto {
    lakers_crypto_rustcrypto::Crypto::new(rand_core::OsRng)
}

#[cfg(any(feature = "cryptocell310", feature = "cryptocell310-rust"))]
pub type Crypto = lakers_crypto_cryptocell310::Crypto;

#[cfg(any(feature = "cryptocell310", feature = "cryptocell310-rust"))]
pub const fn default_crypto() -> Crypto {
    lakers_crypto_cryptocell310::Crypto
}

/// See test_implements_crypto
#[allow(dead_code)]
fn test_helper<T: CryptoTrait>() {}

/// Ensure at build time that whichever type as selected for Crypto actually implements the Crypto
/// trait, and that one is actually defined.
#[allow(dead_code)]
fn test_implements_crypto() {
    test_helper::<Crypto>()
}

#[cfg(test)]
mod tests {
    use hexlit::hex;
    use lakers_shared::*;

    use super::*;

    // Test vectors from RFC 5869 (TV1 = test vector for Test Case 1)
    pub const PRK_TV1: &[u8] =
        &hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    pub const INFO_TV1: &[u8] = &hex!("f0f1f2f3f4f5f6f7f8f9");
    pub const L_TV1: usize = 42;
    pub const OKM_TV1: &[u8] = &hex!(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );

    #[test]
    fn test_hkdf_expand_basic() {
        let mut crypto = default_crypto();

        let mut prk = [0; SHA256_DIGEST_LEN];
        prk[..PRK_TV1.len()].copy_from_slice(PRK_TV1);
        let mut info = [0; MAX_INFO_LEN];
        info[..INFO_TV1.len()].copy_from_slice(INFO_TV1);

        let mut okm_tv: BytesMaxBuffer = [0; MAX_BUFFER_LEN];
        okm_tv[..OKM_TV1.len()].copy_from_slice(OKM_TV1);

        let okm = crypto.hkdf_expand(&prk, &info, INFO_TV1.len(), L_TV1);
        assert_eq!(okm, okm_tv);
    }

    pub const PRK_TV2: &[u8] =
        &hex!("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    pub const INFO_TV2: &[u8] = &hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    pub const L_TV2: usize = 82;
    pub const OKM_TV2: &[u8] = &hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");

    #[test]
    fn test_hkdf_expand_long() {
        let mut crypto = default_crypto();

        let mut prk = [0; SHA256_DIGEST_LEN];
        prk[..PRK_TV2.len()].copy_from_slice(PRK_TV2);
        let mut info = [0; MAX_INFO_LEN];
        info[..INFO_TV2.len()].copy_from_slice(INFO_TV2);

        let mut okm_tv: BytesMaxBuffer = [0; MAX_BUFFER_LEN];
        okm_tv[..OKM_TV2.len()].copy_from_slice(OKM_TV2);

        let okm = crypto.hkdf_expand(&prk, &info, INFO_TV2.len(), L_TV2);
        assert_eq!(okm, okm_tv);
    }
}

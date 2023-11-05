//! Cryptography dispatch for the edhoc-rs crate
//!
//! This crate is used by edhoc-rs to decide which cryptographic back-end to use. Its presence
//! avoids the need for all edhoc-rs types to be generic over a back-end, which would then be
//! provided by the user at initialization time. On the long run, its type may turn into a
//! default associated type.
#![no_std]

/// Convenience re-export
pub use edhoc_crypto_trait::Crypto as CryptoTrait;

#[cfg(feature = "hacspec")]
pub type Crypto = edhoc_crypto_hacspec::Crypto;

#[cfg(feature = "hacspec")]
pub const fn default_crypto() -> Crypto {
    edhoc_crypto_hacspec::Crypto
}

// FIXME: Does not work with crypto-as-trait yet
#[cfg(feature = "cc2538")]
pub use edhoc_crypto_cc2538::*;

#[cfg(any(feature = "psa", feature = "psa-rust",))]
pub type Crypto = edhoc_crypto_psa::Crypto;

#[cfg(any(feature = "psa", feature = "psa-rust",))]
pub const fn default_crypto() -> Crypto {
    edhoc_crypto_psa::Crypto
}

#[cfg(any(feature = "cryptocell310", feature = "cryptocell310-rust"))]
pub type Crypto = edhoc_crypto_cryptocell310::Crypto;

#[cfg(any(feature = "cryptocell310", feature = "cryptocell310-rust"))]
pub const fn default_crypto() -> Crypto {
    edhoc_crypto_cryptocell310::Crypto
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

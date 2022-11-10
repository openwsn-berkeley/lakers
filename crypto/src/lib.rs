#![no_std]

#[cfg(feature = "hacspec")]
pub use edhoc_crypto_hacspec::*;

#[cfg(feature = "cc2538")]
pub use edhoc_crypto_cc2538::*;

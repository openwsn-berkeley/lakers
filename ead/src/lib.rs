#![no_std]

#[cfg(feature = "ead-none")]
pub use edhoc_ead_none::*;

#[cfg(feature = "ead-zeroconf")]
pub use edhoc_ead_zeroconf::*;

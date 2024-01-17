#![no_std]

// compile with:
// cargo build --target='thumbv7em-none-eabihf' --no-default-features --features="crypto-cryptocell310"

use edhoc_rs::*;
use lakers_crypto::{default_crypto, CryptoTrait};

// Panic handler for cortex-m targets
#[cfg(any(feature = "crypto-cryptocell310", feature = "crypto-psa-baremetal"))]
use panic_semihosting as _;

// This function is mainly used to test the C wrapper
#[no_mangle]
pub extern "C" fn p256_generate_key_pair_from_c(out_private_key: *mut u8, out_public_key: *mut u8) {
    let (private_key, public_key) = default_crypto().p256_generate_key_pair();

    unsafe {
        // copy the arrays to the pointers received from C
        // this makes sure that data is not dropped when the function returns
        core::ptr::copy_nonoverlapping(private_key.as_ptr(), out_private_key, P256_ELEM_LEN);
        core::ptr::copy_nonoverlapping(public_key.as_ptr(), out_public_key, P256_ELEM_LEN);
    }
}

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

static CRYPTO: lakers_crypto::Crypto = default_crypto();

/// functions compatible with the C FFI
#[no_mangle]
pub unsafe extern "C" fn initiator_prepare_message_1(
    // input params
    c_i: *mut u8,
    ead_1_c: *mut EADItemC,
    // output params
    initiator_c: *mut EdhocInitiatorWaitM2C,
    message_1: *mut EdhocMessageBuffer,
) -> i8 {
    let c_i = if c_i.is_null() {
        Some(generate_connection_identifier_cbor(&mut default_crypto()))
    } else {
        Some(*c_i)
    };

    let ead_1 = if ead_1_c.is_null() {
        None
    } else {
        let ead_1 = (*ead_1_c).to_rust();
        Some(ead_1)
    };

    let initiator = EdhocInitiator::new(default_crypto());

    let result = match initiator.prepare_message_1(c_i, &ead_1) {
        Ok((init, msg_1)) => {
            *message_1 = msg_1;
            *initiator_c = init.to_c();
            0
        }
        Err(err) => err as i8,
    };

    result
}

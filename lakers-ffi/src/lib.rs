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

// static mut CRYPTO: lakers_crypto::Crypto = default_crypto();

pub unsafe extern "C" fn initiator_new() -> EdhocInitiatorC {
    // we only support a single cipher suite which is already CBOR-encoded
    let mut suites_i: BytesSuites = [0x0; SUITES_LEN];
    let suites_i_len = EDHOC_SUPPORTED_SUITES.len();
    suites_i[0..suites_i_len].copy_from_slice(&EDHOC_SUPPORTED_SUITES[..]);
    let (x, g_x) = default_crypto().p256_generate_key_pair();

    EdhocInitiatorC {
        state: InitiatorStart {
            x,
            g_x,
            suites_i,
            suites_i_len,
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn initiator_prepare_message_1(
    // input params
    c_i: *mut u8,
    ead_1_c: *mut EADItemC,
    // output params
    initiator_c_out: *mut EdhocInitiatorWaitM2C,
    message_1: *mut EdhocMessageBuffer,
) -> i8 {
    let c_i = if c_i.is_null() {
        generate_connection_identifier_cbor(&mut default_crypto())
    } else {
        *c_i
    };

    let ead_1 = if ead_1_c.is_null() {
        None
    } else {
        let ead_1 = (*ead_1_c).to_rust();
        Some(ead_1)
    };

    let initiator_c = initiator_new();

    let result = match i_prepare_message_1(initiator_c.state, &mut default_crypto(), c_i, &ead_1) {
        Ok((state, msg_1)) => {
            *message_1 = msg_1;
            *initiator_c_out = EdhocInitiatorWaitM2C { state };
            0
        }
        Err(err) => err as i8,
    };

    result
}

#[no_mangle]
pub unsafe extern "C" fn initiator_parse_message_2(
    // input params
    initiator_c: *mut EdhocInitiatorWaitM2C,
    message_2: *const EdhocMessageBuffer,
    // output params
    initiator_c_out: *mut EdhocInitiatorProcessingM2C,
    c_r_out: *mut u8,
    // id_cred_r_c_out: *mut IdCredOwnedC,
    valid_cred_r_out: *mut CredentialRPK,
    ead_2_c_out: *mut EADItemC,
) -> i8 {
    // manually take `state` because Rust cannot move out of a dereferenced raw pointer directly
    // raw pointers do not have ownership information, requiring manual handling of the data
    let state = core::ptr::read(&(*initiator_c).state);

    let result = match i_parse_message_2(state, &mut default_crypto(), &(*message_2)) {
        Ok((state, c_r, id_cred_r, ead_2)) => {
            *initiator_c_out = EdhocInitiatorProcessingM2C { state };
            *c_r_out = c_r;

            // NOTE: this is just to avoid having IdCredOwnedC being passed across the ffi boundary
            let valid_cred_r = credential_check_or_fetch(None, id_cred_r).unwrap();
            (*valid_cred_r_out).value = valid_cred_r.value;
            (*valid_cred_r_out).public_key = valid_cred_r.public_key;
            (*valid_cred_r_out).kid = valid_cred_r.kid;

            if let Some(mut ead_2) = ead_2 {
                (*ead_2_c_out).label = ead_2.label;
                (*ead_2_c_out).is_critical = ead_2.is_critical;
                (*ead_2_c_out).value = ead_2
                    .value
                    .as_mut()
                    .map_or(core::ptr::null_mut(), |v| v as *mut EdhocMessageBuffer)
            }
            0
        }
        Err(err) => err as i8,
    };

    result
}

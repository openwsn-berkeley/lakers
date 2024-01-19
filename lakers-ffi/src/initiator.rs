use core::ffi::c_void;
use core::slice;

use edhoc_rs::*;
use lakers_crypto::{default_crypto, CryptoTrait};

use crate::*;

/// structs compatible with the C FFI
/// some of them have state as `*mut c_void` to hide fields that are not
/// compatible with C, such as `Option<..>`

#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiatorC {
    pub state: InitiatorStart,
}

#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiatorWaitM2C {
    pub state: WaitM2,
}

#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiatorProcessingM2C {
    pub state: *mut c_void, // ProcessingM2
}

#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiatorProcessedM2C {
    state: *mut c_void, // ProcessedM2
    cred_i: CredentialRPK,
}

#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiatorDoneC {
    state: Completed,
}

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
    valid_cred_r_out: *mut CredentialRPK,
    ead_2_c_out: *mut EADItemC,
) -> i8 {
    // manually take `state` because Rust cannot move out of a dereferenced raw pointer directly
    // raw pointers do not have ownership information, requiring manual handling of the data
    let state = core::ptr::read(&(*initiator_c).state);

    let result = match i_parse_message_2(state, &mut default_crypto(), &(*message_2)) {
        Ok((mut state, c_r, id_cred_r, ead_2)) => {
            *initiator_c_out = EdhocInitiatorProcessingM2C {
                state: &mut state as *mut _ as *mut c_void,
            };
            *c_r_out = c_r;

            // NOTE: this is just to avoid having IdCredOwnedC being passed across the ffi boundary
            let valid_cred_r = credential_check_or_fetch(None, id_cred_r).unwrap();
            *valid_cred_r_out = valid_cred_r;

            if let Some(ead_2) = ead_2 {
                EADItemC::from_rust_to_c(ead_2, ead_2_c_out);
            }
            0
        }
        Err(err) => err as i8,
    };

    result
}

#[no_mangle]
pub unsafe extern "C" fn initiator_verify_message_2(
    // input params
    initiator_c: *mut EdhocInitiatorProcessingM2C,
    i: *const u8,
    i_len: usize,
    cred_i: CredentialRPK,
    valid_cred_r: CredentialRPK,
    // output params
    initiator_c_out: *mut EdhocInitiatorProcessedM2C,
) -> i8 {
    let state = core::ptr::read((*initiator_c).state as *mut ProcessingM2);
    let i = slice::from_raw_parts(i, i_len);

    match i_verify_message_2(
        state,
        &mut default_crypto(),
        valid_cred_r,
        i.try_into().expect("Wrong length of initiator private key"),
    ) {
        Ok(mut state) => {
            *initiator_c_out = EdhocInitiatorProcessedM2C {
                state: &mut state as *mut _ as *mut c_void,
                cred_i,
            };
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn initiator_prepare_message_3(
    // input params
    initiator_c: *mut EdhocInitiatorProcessedM2C,
    cred_transfer: CredentialTransfer,
    ead_3_c: *mut EADItemC,
    // output params
    initiator_c_out: *mut EdhocInitiatorDoneC,
    message_3: *mut EdhocMessageBuffer,
    prk_out_c: *mut [u8; SHA256_DIGEST_LEN],
) -> i8 {
    let mut state = core::ptr::read((*initiator_c).state as *mut ProcessedM2);

    let ead_3 = if ead_3_c.is_null() {
        None
    } else {
        let ead_3 = (*ead_3_c).to_rust();
        Some(ead_3)
    };

    match i_prepare_message_3(
        &mut state,
        &mut default_crypto(),
        (*initiator_c).cred_i,
        cred_transfer,
        &ead_3,
    ) {
        Ok((state, msg_3, prk_out)) => {
            *initiator_c_out = EdhocInitiatorDoneC { state };
            *message_3 = msg_3;
            *prk_out_c = prk_out;
            0
        }
        Err(err) => err as i8,
    }
}

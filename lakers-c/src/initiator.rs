use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};

use crate::*;

/// structs compatible with the C FFI

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
    pub state: ProcessingM2C,
}

#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiatorProcessedM2C {
    state: ProcessedM2,
    cred_i: CredentialRPK,
}

#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiatorDoneC {
    state: Completed,
}

#[no_mangle]
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
    initiator_c: *mut EdhocInitiatorC,
    // input params
    c_i: *mut u8,
    ead_1_c: *mut EADItemC,
    // output params
    initiator_c_out: *mut EdhocInitiatorWaitM2C,
    message_1: *mut EdhocMessageBuffer,
) -> i8 {
    if initiator_c_out.is_null() || message_1.is_null() {
        return -1;
    }

    let state = core::ptr::read(&(*initiator_c).state);

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

    let result = match i_prepare_message_1(&state, &mut default_crypto(), c_i, &ead_1) {
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
    expected_cred_r: CredentialRPK,
    // output params
    initiator_c_out: *mut EdhocInitiatorProcessingM2C,
    c_r_out: *mut u8,
    valid_cred_r_out: *mut CredentialRPK,
    ead_2_c_out: *mut EADItemC,
) -> i8 {
    // this is a parsing function, so all output parameters are mandatory
    if initiator_c.is_null()
        || message_2.is_null()
        || initiator_c_out.is_null()
        || c_r_out.is_null()
        || valid_cred_r_out.is_null()
        || ead_2_c_out.is_null()
    {
        return -1;
    }

    // manually take `state` because Rust cannot move out of a dereferenced raw pointer directly
    // raw pointers do not have ownership information, requiring manual handling of the data
    let state = core::ptr::read(&(*initiator_c).state);

    let result = match i_parse_message_2(&state, &mut default_crypto(), &(*message_2)) {
        Ok((state, c_r, id_cred_r, ead_2)) => {
            ProcessingM2C::copy_into_c(state, &mut (*initiator_c_out).state);
            *c_r_out = c_r;

            // NOTE: checking here to avoid having IdCredOwnedC being passed across the ffi boundary
            let Ok(valid_cred_r) = credential_check_or_fetch(Some(expected_cred_r), id_cred_r)
            else {
                return -1;
            };
            *valid_cred_r_out = valid_cred_r;

            if let Some(ead_2) = ead_2 {
                EADItemC::copy_into_c(ead_2, ead_2_c_out);
                (*initiator_c_out).state.ead_2 = ead_2_c_out;
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
    i: *const BytesP256ElemLen,
    // i_len: usize,
    cred_i: CredentialRPK,
    valid_cred_r: CredentialRPK,
    // output params
    initiator_c_out: *mut EdhocInitiatorProcessedM2C,
) -> i8 {
    if initiator_c.is_null() || i.is_null() || initiator_c_out.is_null() {
        return -1;
    }

    let state = core::ptr::read(&(*initiator_c).state).to_rust();

    match i_verify_message_2(&state, &mut default_crypto(), valid_cred_r, &(*i)) {
        Ok(state) => {
            *initiator_c_out = EdhocInitiatorProcessedM2C { state, cred_i };
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
    if initiator_c.is_null()
        || initiator_c_out.is_null()
        || message_3.is_null()
        || prk_out_c.is_null()
    {
        return -1;
    }

    let mut state = core::ptr::read(&(*initiator_c).state);

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

#[no_mangle]
pub unsafe extern "C" fn initiator_compute_ephemeral_secret(
    initiator_c: *const EdhocInitiatorC,
    g_a: *const BytesP256ElemLen,
    secret_c_out: *mut BytesP256ElemLen,
) -> i8 {
    if initiator_c.is_null() || g_a.is_null() || secret_c_out.is_null() {
        return -1;
    }

    let state = core::ptr::read(&(*initiator_c).state);

    let secret = default_crypto().p256_ecdh(&state.x, &(*g_a));
    core::ptr::copy_nonoverlapping(secret.as_ptr(), secret_c_out as *mut u8, secret.len());

    0
}

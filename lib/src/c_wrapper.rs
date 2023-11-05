use crate::*;
use core::{slice, str};
use edhoc_consts::*;
use hexlit::hex;

use edhoc_crypto::{default_crypto, CryptoTrait};

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

#[repr(C)]
pub struct EdhocInitiatorC {
    pub state: State,
    pub i: *const u8,
    pub i_len: usize,
    pub cred_i: *const u8,
    pub cred_i_len: usize,
    pub cred_r: *const u8,
    pub cred_r_len: usize,
}

impl EdhocInitiatorC {
    pub fn to_rust(&self) -> EdhocInitiator {
        EdhocInitiator::new(
            self.state,
            unsafe { slice::from_raw_parts(self.i, self.i_len) },
            unsafe { slice::from_raw_parts(self.cred_i, self.cred_i_len) },
            unsafe { Some(slice::from_raw_parts(self.cred_r, self.cred_r_len)) },
        )
    }
}

#[repr(C)]
pub struct EdhocResponderC {
    pub state: State,
    pub r: *const u8,
    pub r_len: usize,
    pub cred_i: *const u8,
    pub cred_i_len: usize,
    pub cred_r: *const u8,
    pub cred_r_len: usize,
}

impl EdhocResponderC {
    pub fn to_rust(&self) -> EdhocResponder {
        EdhocResponder::new(
            self.state,
            unsafe { slice::from_raw_parts(self.r, self.r_len) },
            unsafe { slice::from_raw_parts(self.cred_r, self.cred_r_len) },
            unsafe { Some(slice::from_raw_parts(self.cred_i, self.cred_i_len)) },
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn responder_new(
    r: *const u8,
    r_len: usize,
    cred_r: *const u8,
    cred_r_len: usize,
    cred_i: *const u8,
    cred_i_len: usize,
) -> EdhocResponderC {
    EdhocResponder::new(
        State::default(),
        slice::from_raw_parts(r, r_len),
        slice::from_raw_parts(cred_r, cred_r_len),
        Some(slice::from_raw_parts(cred_i, cred_i_len)),
    )
    .to_c()
}

#[no_mangle]
pub unsafe extern "C" fn initiator_new(
    i: *const u8,
    i_len: usize,
    cred_i: *const u8,
    cred_i_len: usize,
    cred_r: *const u8,
    cred_r_len: usize,
) -> EdhocInitiatorC {
    EdhocInitiator::new(
        State::default(),
        slice::from_raw_parts(i, i_len),
        slice::from_raw_parts(cred_i, cred_i_len),
        Some(slice::from_raw_parts(cred_r, cred_r_len)),
    )
    .to_c()
}

#[no_mangle]
pub unsafe extern "C" fn initiator_prepare_message_1(
    initiator_c: *mut EdhocInitiatorC,
    message_1: *mut EdhocMessageBuffer,
) -> i8 {
    let mut initiator = (*initiator_c).to_rust();

    let c_i: u8 = generate_connection_identifier_cbor().into();
    let result = match initiator.prepare_message_1(c_i) {
        Ok(msg_1) => {
            *message_1 = msg_1;
            0
        }
        Err(err) => err as i8,
    };

    *initiator_c = initiator.to_c();

    result
}

#[no_mangle]
pub unsafe extern "C" fn responder_process_message_1(
    responder_c: *mut EdhocResponderC,
    message_1: *const EdhocMessageBuffer,
) -> i8 {
    let mut responder = (*responder_c).to_rust();

    let result = match responder.process_message_1(&*message_1) {
        Ok(_) => 0,
        Err(err) => err as i8,
    };

    *responder_c = responder.to_c();

    result
}

#[no_mangle]
pub unsafe extern "C" fn responder_prepare_message_2(
    responder_c: *mut EdhocResponderC,
    message_2: *mut EdhocMessageBuffer,
    c_r: *mut u8,
) -> i8 {
    let mut responder = (*responder_c).to_rust();

    let c_r_chosen: u8 = generate_connection_identifier_cbor().into();
    let result = match responder.prepare_message_2(c_r_chosen) {
        Ok(msg_2) => {
            *message_2 = msg_2;
            *c_r = c_r_chosen;
            0
        }
        Err(err) => err as i8,
    };

    *responder_c = responder.to_c();

    result
}

#[no_mangle]
pub unsafe extern "C" fn initiator_process_message_2(
    initiator_c: *mut EdhocInitiatorC,
    message_2: *const EdhocMessageBuffer,
    c_r: *mut u8,
) -> i8 {
    let mut initiator = (*initiator_c).to_rust();

    let result = match initiator.process_message_2(&*message_2) {
        Ok(c_r_res) => {
            *c_r = c_r_res;
            0
        }
        Err(err) => err as i8,
    };

    *initiator_c = initiator.to_c();

    result
}

#[no_mangle]
pub unsafe extern "C" fn initiator_prepare_message_3(
    initiator_c: *mut EdhocInitiatorC,
    message_3: *mut EdhocMessageBuffer,
    prk_out: *mut [u8; SHA256_DIGEST_LEN],
) -> i8 {
    let mut initiator = (*initiator_c).to_rust();

    let result = match initiator.prepare_message_3() {
        Ok((msg_3, prk_out_res)) => {
            *message_3 = msg_3;
            *prk_out = prk_out_res;
            0
        }
        Err(err) => err as i8,
    };

    *initiator_c = initiator.to_c();

    result
}

#[no_mangle]
pub unsafe extern "C" fn responder_process_message_3(
    responder_c: *mut EdhocResponderC,
    message_3: *const EdhocMessageBuffer,
    prk_out: *mut [u8; SHA256_DIGEST_LEN],
) -> i8 {
    let mut responder = (*responder_c).to_rust();

    let result = match responder.process_message_3(&*message_3) {
        Ok(prk_out_res) => {
            *prk_out = prk_out_res;
            0
        }
        Err(err) => err as i8,
    };

    *responder_c = responder.to_c();

    result
}

#[cfg(test)]
mod test_c {
    use super::*;

    #[test]
    fn test_new_responder() {
        const ID_CRED_I: &[u8] = &hex!("a104412b");
        const ID_CRED_R: &[u8] = &hex!("a104410a");
        const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
        const G_I: &[u8] =
            &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
        const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
        const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");

        let resp = unsafe {
            responder_new(
                R.as_ptr(),
                R.len(),
                CRED_I.as_ptr(),
                CRED_I.len(),
                CRED_R.as_ptr(),
                CRED_R.len(),
            )
        };
    }
}

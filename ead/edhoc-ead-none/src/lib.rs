#![no_std]

use edhoc_consts::*;

// TODO: the function signatures should not be necessarily the same as the zeroconf version
//       find a way to be generic on this part.

// initiator side
pub fn i_prepare_ead_1(
    _crypto: &mut impl Crypto,
    _x: &BytesP256ElemLen,
    _ss: u8,
) -> Option<EADItem> {
    None
}

pub fn i_process_ead_2(
    _crypto: &mut impl Crypto,
    _ead_2: EADItem,
    _cred_v_u8: &[u8],
    _h_message_1: &BytesHashLen,
) -> Result<(), ()> {
    Ok(())
}

pub fn i_prepare_ead_3() -> Option<EADItem> {
    None
}

// responder side
pub fn r_process_ead_1(
    _crypto: &mut impl Crypto,
    _ead_1: &EADItem,
    _message_1: &BufferMessage1,
) -> Result<(), ()> {
    Ok(())
}

pub fn r_prepare_ead_2() -> Option<EADItem> {
    None
}

pub fn r_process_ead_3(_ead_3: EADItem) -> Result<(), ()> {
    Ok(())
}

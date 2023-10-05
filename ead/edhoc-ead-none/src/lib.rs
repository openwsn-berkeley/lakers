#![no_std]

use edhoc_consts::*;

// initiator side
pub fn i_prepare_ead_1(x: &BytesP256ElemLen, ss: u8) -> Option<EADItem> {
    None
}

pub fn i_process_ead_2(ead_2: EADItem) -> Result<(), ()> {
    Ok(())
}

pub fn i_prepare_ead_3() -> Option<EADItem> {
    None
}

// responder side
pub fn r_process_ead_1(ead_1: EADItem) -> Result<(), ()> {
    Ok(())
}

pub fn r_prepare_ead_2() -> Option<EADItem> {
    None
}

pub fn r_process_ead_3(ead_3: EADItem) -> Result<(), ()> {
    Ok(())
}

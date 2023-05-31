#![no_std]

use edhoc_consts::*;

// initiator side
pub fn i_prepare_ead_1() -> EADMessageBuffer {
    let mut ead_1 = EADMessageBuffer::new();

    // add the label to the buffer, tagged as critical,
    // which means encoding it as a negative value, i.e., -label
    ead_1.content[0] = CBOR_NEG_INT_1BYTE_START + EAD_ZEROCONF_LABEL;
    ead_1.len = 1;

    // TODO: build Voucher_Info (LOC_W, ENC_ID), and append it to the buffer

    // state.protocol_state = EADInitiatorProtocolState::WaitEAD2;

    ead_1
}

pub fn i_process_ead_2(ead_2: EADMessageBuffer) -> Result<(), ()> {
    // TODO: verify the label
    // TODO: verify the voucher

    // state.protocol_state = EADInitiatorProtocolState::Completed;

    Ok(())
}

pub fn i_prepare_ead_3() -> EADMessageBuffer {
    EADMessageBuffer::new()
}

// responder side
pub fn r_process_ead_1(ead_1: EADMessageBuffer) -> Result<(), ()> {
    // TODO: parse and verify the label
    // TODO: trigger the voucher request to W

    // state.protocol_state = EADResponderProtocolState::ProcessedEAD1;

    Ok(())
}

pub fn r_prepare_ead_2() -> EADMessageBuffer {
    let mut ead_2 = EADMessageBuffer::new();

    // add the label to the buffer (non-critical)
    ead_2.content[0] = EAD_ZEROCONF_LABEL;
    ead_2.len = 1;

    // TODO: append Voucher (H(message_1), CRED_V) to the buffer

    // // NOTE: see the note in lib.rs::test_ead
    // // state.protocol_state = EADResponderProtocolState::WaitMessage3;
    // state.protocol_state = EADResponderProtocolState::Completed;

    ead_2
}

pub fn r_process_ead_3(ead_3: EADMessageBuffer) -> Result<(), ()> {
    // TODO: maybe retrive CRED_U from a Credential Database

    // state.protocol_state = EADResponderProtocolState::Completed;

    Ok(())
}

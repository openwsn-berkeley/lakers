#![no_std]

use edhoc_consts::*;

#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EADInitiatorProtocolState {
    #[default]
    Start,
    WaitEAD2,
    Completed, // TODO[ead]: check if it is really ok to consider Completed after processing EAD_2
}

pub struct EADState {
    pub protocol_state: EADInitiatorProtocolState,
}

impl EADState {
    pub fn new() -> Self {
        EADState {
            protocol_state: EADInitiatorProtocolState::Start,
        }
    }
}

// shared mutable global state for EAD
// NOTE: this is not thread-safe
static mut EAD_GLOBAL_STATE: EADState = EADState {
    protocol_state: EADInitiatorProtocolState::Start,
};
pub fn ead_get_global_state() -> &'static EADState {
    unsafe { &EAD_GLOBAL_STATE }
}
pub fn ead_set_global_state(new_state: EADState) {
    unsafe {
        EAD_GLOBAL_STATE = new_state;
    }
}

// initiator side
pub fn i_prepare_ead_1() -> EADItem {
    let mut ead_1 = EADItem::new();

    // this ead item is critical
    ead_1.label = EAD_ZEROCONF_LABEL;
    ead_1.is_critical = true;

    // TODO: build Voucher_Info (LOC_W, ENC_ID), and append it to the buffer

    ead_set_global_state(EADState {
        protocol_state: EADInitiatorProtocolState::WaitEAD2,
    });

    ead_1
}

pub fn i_process_ead_2(ead_2: EADItem) -> Result<(), ()> {
    // TODO: verify the label
    // TODO: verify the voucher

    // state.protocol_state = EADInitiatorProtocolState::Completed;

    Ok(())
}

pub fn i_prepare_ead_3() -> EADItem {
    EADItem::new()
}

// responder side
pub fn r_process_ead_1(ead_1: EADItem) -> Result<(), ()> {
    // TODO: parse and verify the label
    // TODO: trigger the voucher request to W

    // state.protocol_state = EADResponderProtocolState::ProcessedEAD1;

    Ok(())
}

pub fn r_prepare_ead_2() -> EADItem {
    let mut ead_2 = EADItem::new();

    // add the label to the buffer (non-critical)
    ead_2.label = EAD_ZEROCONF_LABEL;
    ead_2.is_critical = true;

    // TODO: append Voucher (H(message_1), CRED_V) to the buffer

    // // NOTE: see the note in lib.rs::test_ead
    // // state.protocol_state = EADResponderProtocolState::WaitMessage3;
    // state.protocol_state = EADResponderProtocolState::Completed;

    ead_2
}

pub fn r_process_ead_3(ead_3: EADItem) -> Result<(), ()> {
    // TODO: maybe retrive CRED_U from a Credential Database

    // state.protocol_state = EADResponderProtocolState::Completed;

    Ok(())
}

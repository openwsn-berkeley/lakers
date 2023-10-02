#![no_std]

use edhoc_consts::*;

// initiator side
#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EADInitiatorProtocolState {
    #[default]
    Start,
    WaitEAD2,
    Completed, // TODO[ead]: check if it is really ok to consider Completed after processing EAD_2
}

pub struct EADInitiatorState {
    pub protocol_state: EADInitiatorProtocolState,
}

impl EADInitiatorState {
    pub fn new() -> Self {
        EADInitiatorState {
            protocol_state: EADInitiatorProtocolState::Start,
        }
    }
}

// shared mutable global state for EAD
// NOTE: this is not thread-safe
static mut EAD_INITIATOR_GLOBAL_STATE: EADInitiatorState = EADInitiatorState {
    protocol_state: EADInitiatorProtocolState::Start,
};
pub fn ead_initiator_get_global_state() -> &'static EADInitiatorState {
    unsafe { &EAD_INITIATOR_GLOBAL_STATE }
}
pub fn ead_initiator_set_global_state(new_state: EADInitiatorState) {
    unsafe {
        EAD_INITIATOR_GLOBAL_STATE = new_state;
    }
}

pub fn i_prepare_ead_1() -> Option<EADItem> {
    // TODO: build Voucher_Info (LOC_W, ENC_ID), and append it to the buffer
    let mut ead_1 = EADItem::new(EAD_ZEROCONF_LABEL, true, None)
        // Const propagation will remove this.
        .unwrap();

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::WaitEAD2,
    });

    Some(ead_1)
}

pub fn i_process_ead_2(ead_2: EADItem) -> Result<(), ()> {
    // TODO: verify the label
    // TODO: verify the voucher

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::Completed,
    });

    Ok(())
}

pub fn i_prepare_ead_3() -> Option<EADItem> {
    Some(EADItem::new(0, false, None).unwrap())
}

// responder side
#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EADResponderProtocolState {
    #[default]
    Start,
    ProcessedEAD1,
    WaitEAD3,
    Completed,
}

pub struct EADResponderState {
    pub protocol_state: EADResponderProtocolState,
}

impl EADResponderState {
    pub fn new() -> Self {
        EADResponderState {
            protocol_state: EADResponderProtocolState::Start,
        }
    }
}

// shared mutable global state for EAD
// NOTE: this is not thread-safe
static mut EAD_RESPONDER_GLOBAL_STATE: EADResponderState = EADResponderState {
    protocol_state: EADResponderProtocolState::Start,
};
pub fn ead_responder_get_global_state() -> &'static EADResponderState {
    unsafe { &EAD_RESPONDER_GLOBAL_STATE }
}
pub fn ead_responder_set_global_state(new_state: EADResponderState) {
    unsafe {
        EAD_RESPONDER_GLOBAL_STATE = new_state;
    }
}

pub fn r_process_ead_1(ead_1: EADItem) -> Result<(), ()> {
    // TODO: parse and verify the label
    // TODO: trigger the voucher request to W

    ead_responder_set_global_state(EADResponderState {
        protocol_state: EADResponderProtocolState::ProcessedEAD1,
    });

    Ok(())
}

pub fn r_prepare_ead_2() -> Option<EADItem> {
    // TODO: append Voucher (H(message_1), CRED_V) to the buffer
    let ead_2 = EADItem::new(EAD_ZEROCONF_LABEL, true, None).unwrap();

    // NOTE: see the note in lib.rs::test_ead
    // state.protocol_state = EADResponderProtocolState::WaitMessage3;
    ead_responder_set_global_state(EADResponderState {
        protocol_state: EADResponderProtocolState::Completed,
    });

    Some(ead_2)
}

pub fn r_process_ead_3(ead_3: EADItem) -> Result<(), ()> {
    // TODO: maybe retrive CRED_U from a Credential Database

    // state.protocol_state = EADResponderProtocolState::Completed;

    Ok(())
}

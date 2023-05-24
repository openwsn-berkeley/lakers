#![no_std]

pub mod ead_zeroconf_initiator {
    use edhoc_consts::*;

    pub fn new_handler() -> EADInitiatorZeroConfHandler {
        EADInitiatorZeroConfHandler {
            prepare_ead1_cb: prepare_ead_1,
            process_ead2_cb: process_ead_2,
            ..Default::default()
        }
    }

    pub fn prepare_ead_1(
        mut buffer: EdhocMessageBuffer,
        mut state: EADInitiatorZeroConfState,
    ) -> (EdhocMessageBuffer, EADInitiatorZeroConfState) {
        // TODO: append the label to the buffer
        // TODO: build Voucher_Info (LOC_W, ENC_ID), and append it to the buffer

        state.ead_state = EADInitiatorProtocolState::WaitEAD2;

        (buffer, state)
    }

    pub fn process_ead_2(
        buffer: EdhocMessageBuffer,
        mut state: EADInitiatorZeroConfState,
    ) -> EADInitiatorZeroConfState {
        // TODO: verify the label
        // TODO: verify the voucher

        state.ead_state = EADInitiatorProtocolState::Completed;

        state
    }
}

pub mod ead_zeroconf_responder {
    use edhoc_consts::*;

    pub fn new_handler() -> EADResponderZeroConfHandler {
        EADResponderZeroConfHandler {
            process_ead1_cb: process_ead_1,
            prepare_ead2_cb: prepare_ead_2,
            process_ead3_cb: process_ead_3,
            ..Default::default()
        }
    }

    pub fn process_ead_1(
        buffer: EdhocMessageBuffer,
        mut state: EADResponderZeroConfState,
    ) -> EADResponderZeroConfState {
        // TODO: verify the label
        // TODO: trigger the voucher request to W

        state.ead_state = EADResponderProtocolState::ProcessedEAD1;

        state
    }

    pub fn prepare_ead_2(
        mut state: EADResponderZeroConfState,
    ) -> (EdhocMessageBuffer, EADResponderZeroConfState) {
        // TODO: append the label to the buffer
        // TODO: append Voucher (H(message_1), CRED_V) to the buffer

        state.ead_state = EADResponderProtocolState::WaitMessage3;

        (EdhocMessageBuffer::new(), state)
    }

    pub fn process_ead_3(
        buffer: EdhocMessageBuffer,
        mut state: EADResponderZeroConfState,
    ) -> EADResponderZeroConfState {
        // TODO: maybe retrive CRED_U from a Credential Database

        state.ead_state = EADResponderProtocolState::Completed;

        state
    }
}

#![no_std]

pub mod ead_zeroconf_initiator {
    use edhoc_consts::*;

    pub fn new_handler() -> EADInitiatorZeroConfHandler {
        EADInitiatorZeroConfHandler {
            prepare_ead1_cb: prepare_ead_1,
            ..Default::default()
        }
    }

    pub fn prepare_ead_1(
        mut buffer: EdhocMessageBuffer,
        mut state: EADInitiatorZeroConfState
    ) -> (EdhocMessageBuffer, EADInitiatorZeroConfState) {
        // TODO: append the label to the buffer
        // buffer.content[buffer.len] = state.label;
        // buffer.len += 1;

        // TODO: build Voucher_Info (LOC_W, ENC_ID), and append it to the buffer

        state.ead_state = EADInitiatorProtocolState::WaitEAD2;

        (buffer, state)
    }

}

pub mod ead_zeroconf_responder {
    use edhoc_consts::*;

    pub fn new_handler() -> EADResponderZeroConfHandler {
        EADResponderZeroConfHandler {
            process_ead1_cb: process_ead_1,
            ..Default::default()
        }
    }

    pub fn process_ead_1(
        buffer: EdhocMessageBuffer,
        mut state: EADResponderZeroConfState
    ) -> EADResponderZeroConfState {
        // TODO: trigger the voucher request to W

        state.ead_state = EADResponderProtocolState::ProcessedEAD1;

        state
    }

}

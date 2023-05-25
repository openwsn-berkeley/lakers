#![no_std]

pub mod ead_zeroconf_initiator {
    use edhoc_consts::*;

    pub fn new_handler() -> EADInitiatorZeroConfHandler {
        EADInitiatorZeroConfHandler {
            prepare_ead_1_cb: prepare_ead_1,
            process_ead_2_cb: process_ead_2,
            ..Default::default()
        }
    }

    pub fn prepare_ead_1(
        mut state: EADInitiatorZeroConfState,
    ) -> (EdhocMessageBuffer, EADInitiatorZeroConfState) {
        let mut ead_1 = EdhocMessageBuffer::new();

        // add the label to the buffer, tagged as critical,
        // which means encoding it as a negative value, i.e., -label
        ead_1.content[0] = CBOR_NEG_INT_RANGE_START + EAD_ZEROCONF_LABEL;
        ead_1.len = 1;

        // TODO: build Voucher_Info (LOC_W, ENC_ID), and append it to the buffer

        state.ead_state = EADInitiatorProtocolState::WaitEAD2;

        (ead_1, state)
    }

    pub fn process_ead_2(
        buffer: EdhocMessageBuffer,
        mut state: EADInitiatorZeroConfState,
    ) -> (Result<(), ()>, EADInitiatorZeroConfState) {
        // TODO: verify the label
        // TODO: verify the voucher

        state.ead_state = EADInitiatorProtocolState::Completed;

        (Ok(()), state)
    }
}

pub mod ead_zeroconf_responder {
    use edhoc_consts::*;

    pub fn new_handler() -> EADResponderZeroConfHandler {
        EADResponderZeroConfHandler {
            process_ead_1_cb: process_ead_1,
            prepare_ead_2_cb: prepare_ead_2,
            process_ead_3_cb: process_ead_3,
            ..Default::default()
        }
    }

    pub fn process_ead_1(
        buffer: EdhocMessageBuffer,
        mut state: EADResponderZeroConfState,
    ) -> (Result<(), ()>, EADResponderZeroConfState) {
        // TODO: parse and verify the label
        // TODO: trigger the voucher request to W

        state.ead_state = EADResponderProtocolState::ProcessedEAD1;

        (Ok(()), state)
    }

    pub fn prepare_ead_2(
        mut state: EADResponderZeroConfState,
    ) -> (EdhocMessageBuffer, EADResponderZeroConfState) {
        let mut ead_2 = EdhocMessageBuffer::new();

        // add the label to the buffer (non-critical)
        ead_2.content[0] = EAD_ZEROCONF_LABEL;
        ead_2.len = 1;

        // TODO: append Voucher (H(message_1), CRED_V) to the buffer

        // NOTE: see the note in lib.rs::test_ead
        // state.ead_state = EADResponderProtocolState::WaitMessage3;
        state.ead_state = EADResponderProtocolState::Completed;

        (ead_2, state)
    }

    pub fn process_ead_3(
        buffer: EdhocMessageBuffer,
        mut state: EADResponderZeroConfState,
    ) -> (Result<(), ()>, EADResponderZeroConfState) {
        // TODO: maybe retrive CRED_U from a Credential Database

        state.ead_state = EADResponderProtocolState::Completed;

        (Ok(()), state)
    }
}

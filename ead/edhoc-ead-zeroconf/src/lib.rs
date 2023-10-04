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

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EADInitiatorState {
    pub protocol_state: EADInitiatorProtocolState,
    pub(crate) loc_w: EdhocMessageBuffer,
}

impl EADInitiatorState {
    pub fn new(loc_w: EdhocMessageBuffer) -> Self {
        EADInitiatorState {
            protocol_state: EADInitiatorProtocolState::Start,
            loc_w,
        }
    }
}

// shared mutable global state for EAD
// NOTE: this is not thread-safe
static mut EAD_INITIATOR_GLOBAL_STATE: EADInitiatorState = EADInitiatorState {
    protocol_state: EADInitiatorProtocolState::Start,
    loc_w: EdhocMessageBuffer {
        content: [0u8; MAX_MESSAGE_SIZE_LEN],
        len: 0,
    },
};
pub fn ead_initiator_get_global_state() -> &'static EADInitiatorState {
    unsafe { &EAD_INITIATOR_GLOBAL_STATE }
}
pub fn ead_initiator_get_global_state_own() -> EADInitiatorState {
    unsafe { EAD_INITIATOR_GLOBAL_STATE }
}
pub fn ead_initiator_set_global_state(new_state: EADInitiatorState) {
    unsafe {
        EAD_INITIATOR_GLOBAL_STATE = new_state;
    }
}

pub fn i_prepare_ead_1() -> Option<EADItem> {
    let mut ead_1 = EADItem::new();

    // this ead item is critical
    ead_1.label = EAD_ZEROCONF_LABEL;
    ead_1.is_critical = true;

    let loc_w = ead_initiator_get_global_state().loc_w;
    let enc_id = build_enc_id();
    ead_1.value = Some(encode_ead_1(loc_w, enc_id));

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::WaitEAD2,
        ..ead_initiator_get_global_state_own()
    });

    Some(ead_1)
}

pub fn i_process_ead_2(_ead_2: EADItem) -> Result<(), ()> {
    // TODO: verify the label
    // TODO: verify the voucher

    ead_initiator_set_global_state(EADInitiatorState {
        protocol_state: EADInitiatorProtocolState::Completed,
        ..ead_initiator_get_global_state_own()
    });

    Ok(())
}

pub fn i_prepare_ead_3() -> Option<EADItem> {
    Some(EADItem::new())
}

// TODO: actually implement this function
use hexlit::hex;
const ENC_ID: &[u8] = &hex!("4545452E4545452E4545452E");
fn build_enc_id() -> EdhocMessageBuffer {
    let enc_id: EdhocMessageBuffer = ENC_ID.try_into().unwrap();

    enc_id
}

fn encode_ead_1(loc_w: EdhocMessageBuffer, enc_id: EdhocMessageBuffer) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[0] = CBOR_TEXT_STRING;
    output.content[1] = loc_w.len as u8;
    output.content[2..2 + loc_w.len].copy_from_slice(&loc_w.content[..loc_w.len]);

    output.content[2 + loc_w.len] = CBOR_MAJOR_BYTE_STRING + enc_id.len as u8;
    output.content[3 + loc_w.len..3 + loc_w.len + enc_id.len]
        .copy_from_slice(&enc_id.content[..enc_id.len]);

    output.len = 3 + loc_w.len + enc_id.len;

    output
}

#[cfg(test)]
mod test_initiator {
    use super::*;
    use edhoc_consts::*;
    use hexlit::hex;

    const LOC_W: &[u8] = &hex!("636F61703A2F2F656E726F6C6C6D656E742E736572766572");

    // voucher_info
    const VOUCHER_INFO_TV: &[u8] =
        &hex!("7818636F61703A2F2F656E726F6C6C6D656E742E7365727665724C4545452E4545452E4545452E");

    #[test]
    fn test_prepare_ead_1() {
        let ead_1_value_tv: EdhocMessageBuffer = VOUCHER_INFO_TV.try_into().unwrap();
        let loc_w: EdhocMessageBuffer = LOC_W.try_into().unwrap();

        ead_initiator_set_global_state(EADInitiatorState::new(loc_w));
        let ead_initiator_state = ead_initiator_get_global_state();

        let ead_1 = i_prepare_ead_1().unwrap();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );
        assert_eq!(ead_1.label, EAD_ZEROCONF_LABEL);
        assert_eq!(ead_1.is_critical, true);
        assert_eq!(ead_1.value.unwrap().content, ead_1_value_tv.content);
    }
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

pub fn r_process_ead_1(_ead_1: EADItem) -> Result<(), ()> {
    // TODO: parse and verify the label
    // TODO: trigger the voucher request to W

    ead_responder_set_global_state(EADResponderState {
        protocol_state: EADResponderProtocolState::ProcessedEAD1,
    });

    Ok(())
}

pub fn r_prepare_ead_2() -> Option<EADItem> {
    let mut ead_2 = EADItem::new();

    // add the label to the buffer (non-critical)
    ead_2.label = EAD_ZEROCONF_LABEL;
    ead_2.is_critical = true;

    // TODO: append Voucher (H(message_1), CRED_V) to the buffer

    // NOTE: see the note in lib.rs::test_ead
    // state.protocol_state = EADResponderProtocolState::WaitMessage3;
    ead_responder_set_global_state(EADResponderState {
        protocol_state: EADResponderProtocolState::Completed,
    });

    Some(ead_2)
}

pub fn r_process_ead_3(_ead_3: EADItem) -> Result<(), ()> {
    // TODO: maybe retrive CRED_U from a Credential Database

    // state.protocol_state = EADResponderProtocolState::Completed;

    Ok(())
}

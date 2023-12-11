use super::shared::*;
use lakers_shared::{Crypto as CryptoTrait, *};

#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum ZeroTouchAuthenticatorState {
    #[default]
    Start,
    ProcessedEAD1,
    WaitEAD3,
    Completed,
    Error,
}

pub struct ZeroTouchAuthenticator {
    pub current_state: ZeroTouchAuthenticatorState,
}

impl ZeroTouchAuthenticator {
    pub fn new() -> Self {
        ZeroTouchAuthenticator {
            current_state: ZeroTouchAuthenticatorState::Start,
        }
    }

    pub fn process_ead_1(
        &mut self,
        ead_1: &EADItem,
        message_1: &EdhocMessageBuffer,
    ) -> Result<(EdhocMessageBuffer, EdhocMessageBuffer), EDHOCError> {
        let opaque_state: Option<EdhocMessageBuffer> = None; // TODO: receive as parameter

        if ead_1.label != EAD_ZEROCONF_LABEL || ead_1.value.is_none() {
            return Err(EDHOCError::EADError);
        }

        let (loc_w, _enc_id) = parse_ead_1_value(&ead_1.value.unwrap())?;
        let voucher_request = encode_voucher_request(message_1, &opaque_state);
        self.current_state = ZeroTouchAuthenticatorState::ProcessedEAD1;

        Ok((loc_w, voucher_request))
    }

    // FIXME: this and the other *_prepare_* functions should return a `Result<>`
    pub fn prepare_ead_2(&mut self, voucher_response: &EdhocMessageBuffer) -> Option<EADItem> {
        let (_message_1, voucher, _opaque_state) =
            parse_voucher_response(&voucher_response).unwrap();

        self.current_state = ZeroTouchAuthenticatorState::Completed;

        Some(EADItem {
            label: EAD_ZEROCONF_LABEL,
            is_critical: true,
            value: Some(voucher[..].try_into().unwrap()),
        })
    }

    pub fn process_ead_3(_ead_3: EADItem) -> Result<(), ()> {
        // TODO: maybe retrive CRED_U from a Credential Database

        // self.current_state = ZeroTouchAuthenticatorState::Completed;

        Ok(())
    }
}

pub fn encode_voucher_request(
    message_1: &EdhocMessageBuffer,
    opaque_state: &Option<EdhocMessageBuffer>,
) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[1] = CBOR_BYTE_STRING;
    output.content[2] = message_1.len as u8;
    output.content[3..3 + message_1.len].copy_from_slice(message_1.as_slice());

    if let Some(opaque_state) = opaque_state {
        output.content[0] = CBOR_MAJOR_ARRAY | 2;

        output.content[3 + message_1.len] = CBOR_BYTE_STRING;
        output.content[4 + message_1.len] = opaque_state.len as u8;
        output.content[5 + message_1.len..5 + message_1.len + opaque_state.len]
            .copy_from_slice(opaque_state.as_slice());

        output.len = 5 + message_1.len + opaque_state.len;
    } else {
        output.content[0] = CBOR_MAJOR_ARRAY | 1;
        output.len = 3 + message_1.len;
    }

    output
}

fn parse_voucher_response(
    voucher_response: &EdhocMessageBuffer,
) -> Result<
    (
        EdhocMessageBuffer,
        BytesEncodedVoucher,
        Option<EdhocMessageBuffer>,
    ),
    EDHOCError,
> {
    let mut decoder = CBORDecoder::new(voucher_response.as_slice());

    let array_size = decoder.array()?;
    if !(2..=3).contains(&array_size) {
        return Err(EDHOCError::EADError);
    }

    let message_1: EdhocMessageBuffer = decoder.bytes()?.try_into().unwrap();
    let voucher: BytesEncodedVoucher = decoder
        .bytes_sized(ENCODED_VOUCHER_LEN)?
        .try_into()
        .unwrap();

    if array_size == 3 {
        let opaque_state: EdhocMessageBuffer = decoder.bytes()?.try_into().unwrap();
        return Ok((message_1, voucher, Some(opaque_state)));
    } else {
        return Ok((message_1, voucher, None));
    }
}

#[cfg(test)]
mod test_authenticator {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_parse_ead_1_value() {
        let ead_1_value_tv: EdhocMessageBuffer = EAD1_VALUE_TV.try_into().unwrap();
        let loc_w_tv: EdhocMessageBuffer = LOC_W_TV.try_into().unwrap();
        let enc_id_tv: EdhocMessageBuffer = ENC_ID_TV.try_into().unwrap();

        let res = parse_ead_1_value(&ead_1_value_tv);
        assert!(res.is_ok());
        let (loc_w, enc_id) = res.unwrap();
        assert_eq!(loc_w.content, loc_w_tv.content);
        assert_eq!(enc_id.content, enc_id_tv.content);
    }

    #[test]
    fn test_encode_voucher_request() {
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_request_tv: EdhocMessageBuffer = VOUCHER_REQUEST_TV.try_into().unwrap();

        let voucher_request = encode_voucher_request(&message_1_tv, &None);
        assert_eq!(voucher_request.content, voucher_request_tv.content);
    }

    #[test]
    fn test_process_ead_1() {
        let ead_1_value_tv: EdhocMessageBuffer = EAD1_VALUE_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();

        let ead_1 = EADItem {
            label: EAD_ZEROCONF_LABEL,
            is_critical: true,
            value: Some(ead_1_value_tv),
        };

        let mut ead_authz = ZeroTouchAuthenticator::new();

        // mock_ead_server_set_global_state(ZeroTouchServer::new(
        //     CRED_V_TV,
        //     W_TV.try_into().unwrap(),
        //     None,
        // ));

        let res = ead_authz.process_ead_1(&ead_1, &message_1_tv);
        assert!(res.is_ok());
        assert_eq!(
            ead_authz.current_state,
            ZeroTouchAuthenticatorState::ProcessedEAD1
        );
    }

    #[test]
    fn test_parse_voucher_response() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_tv: BytesEncodedVoucher = VOUCHER_TV.try_into().unwrap();

        let res = parse_voucher_response(&voucher_response_tv);
        assert!(res.is_ok());
        let (message_1, voucher, opaque_state) = res.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert_eq!(voucher, voucher_tv);
        assert!(opaque_state.is_none());
    }

    #[test]
    fn test_r_prepare_ead_2() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();
        let ead_2_value_tv: EdhocMessageBuffer = EAD2_VALUE_TV.try_into().unwrap();

        let mut ead_authz = ZeroTouchAuthenticator::new();

        let ead_2 = ead_authz.prepare_ead_2(&voucher_response_tv).unwrap();
        assert_eq!(
            ead_authz.current_state,
            ZeroTouchAuthenticatorState::Completed
        );
        assert_eq!(ead_2.label, EAD_ZEROCONF_LABEL);
        assert_eq!(ead_2.is_critical, true);
        assert_eq!(ead_2.value.unwrap().content, ead_2_value_tv.content);
    }
}

#[cfg(test)]
mod test_responder_stateless_operation {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_slo_encode_voucher_request() {
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = SLO_OPAQUE_STATE_TV.try_into().unwrap();
        let voucher_request_tv: EdhocMessageBuffer = SLO_VOUCHER_REQUEST_TV.try_into().unwrap();

        let voucher_request = encode_voucher_request(&message_1_tv, &Some(opaque_state_tv));
        assert_eq!(voucher_request.content, voucher_request_tv.content);
    }

    #[test]
    fn test_slo_parse_voucher_response() {
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_tv: BytesEncodedVoucher = VOUCHER_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = SLO_OPAQUE_STATE_TV.try_into().unwrap();

        let res = parse_voucher_response(&voucher_response_tv);
        assert!(res.is_ok());
        let (message_1, voucher, opaque_state) = res.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert_eq!(voucher, voucher_tv);
        assert_eq!(opaque_state.unwrap().content, opaque_state_tv.content);
    }
}

use crate::shared::*;
use defmt_or_log::trace;
use lakers_shared::{Crypto as CryptoTrait, *};

/// This server also stores an ACL
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct ZeroTouchServer {
    w: BytesP256ElemLen,            // private key of the enrollment server (W)
    pub cred_v: EdhocMessageBuffer, // credential of the authenticator (V)
    // access control list, each device identified by an u8 kid (this is arbitrary, it is not specified in the draft)
    pub acl: Option<EdhocMessageBuffer>,
}

impl ZeroTouchServer {
    pub fn new(w: BytesP256ElemLen, cred_v: &[u8], acl: Option<EdhocMessageBuffer>) -> Self {
        trace!("Initializing ZeroTouchServer");
        let cred_v: EdhocMessageBuffer = cred_v.try_into().unwrap();
        ZeroTouchServer { w, cred_v, acl }
    }

    pub fn authorized(self, kid: u8) -> bool {
        if let Some(acl) = self.acl {
            acl.content.contains(&kid)
        } else {
            // if no acl then allow it
            true
        }
    }

    pub fn handle_voucher_request<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        vreq: &EdhocMessageBuffer,
    ) -> Result<EdhocMessageBuffer, EDHOCError> {
        trace!("Enter handle_voucher_request");
        let (message_1, opaque_state) = parse_voucher_request(vreq)?;
        let (_method, _suites_i, g_x, _c_i, ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        let (_loc_w, enc_id) = parse_ead_1_value(&ead_1.unwrap().value.unwrap())?;
        let id_u_encoded = decrypt_enc_id(crypto, &prk, &enc_id, EDHOC_SUPPORTED_SUITES[0])?;
        let id_u = decode_id_u(id_u_encoded)?;

        if self.acl.is_none() || self.authorized(id_u.content[3]) {
            // compute hash
            let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
            message_1_buf[..message_1.len].copy_from_slice(message_1.as_slice());
            let h_message_1 = crypto.sha256_digest(&message_1_buf, message_1.len);

            let voucher = prepare_voucher(crypto, &h_message_1, &self.cred_v.as_slice(), &prk);
            let voucher_response = encode_voucher_response(&message_1, &voucher, &opaque_state);
            Ok(voucher_response)
        } else {
            Err(EDHOCError::AccessDenied)
        }
    }
}

/// This server can be used when the ACL is stored in the application layer
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct ZeroTouchServerUserAcl {
    w: BytesP256ElemLen,            // private key of the enrollment server (W)
    pub cred_v: EdhocMessageBuffer, // credential of the authenticator (V)
}

impl ZeroTouchServerUserAcl {
    pub fn new(w: BytesP256ElemLen, cred_v: &[u8]) -> Self {
        trace!("Initializing ZeroTouchServerUserAcl");
        let cred_v: EdhocMessageBuffer = cred_v.try_into().unwrap();
        Self { w, cred_v }
    }

    pub fn decode_voucher_request<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        vreq: &EdhocMessageBuffer,
    ) -> Result<EdhocMessageBuffer, EDHOCError> {
        trace!("Enter decode_voucher_request");
        let (message_1, _opaque_state) = parse_voucher_request(vreq)?;
        let (_method, _suites_i, g_x, _c_i, ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        let (_loc_w, enc_id) = parse_ead_1_value(&ead_1.unwrap().value.unwrap())?;
        let id_u_encoded = decrypt_enc_id(crypto, &prk, &enc_id, EDHOC_SUPPORTED_SUITES[0])?;

        decode_id_u(id_u_encoded)
    }

    pub fn prepare_voucher<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        vreq: &EdhocMessageBuffer,
    ) -> Result<EdhocMessageBuffer, EDHOCError> {
        trace!("Enter prepare_voucher");
        let (message_1, opaque_state) = parse_voucher_request(vreq)?;
        let (_method, _suites_i, g_x, _c_i, _ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        // compute hash
        let mut message_1_buf: BytesMaxBuffer = [0x00; MAX_BUFFER_LEN];
        message_1_buf[..message_1.len].copy_from_slice(message_1.as_slice());
        let h_message_1 = crypto.sha256_digest(&message_1_buf, message_1.len);

        let voucher = prepare_voucher(crypto, &h_message_1, &self.cred_v.as_slice(), &prk);
        let voucher_response = encode_voucher_response(&message_1, &voucher, &opaque_state);
        Ok(voucher_response)
    }
}

fn parse_voucher_request(
    vreq: &EdhocMessageBuffer,
) -> Result<(EdhocMessageBuffer, Option<EdhocMessageBuffer>), EDHOCError> {
    let mut decoder = CBORDecoder::new(vreq.as_slice());
    let array_size = decoder.array()?;
    if array_size != 1 && array_size != 2 {
        return Err(EDHOCError::EADUnprocessable);
    }

    let message_1: EdhocMessageBuffer = decoder.bytes()?.try_into().unwrap();

    if array_size == 2 {
        let opaque_state: EdhocMessageBuffer = decoder.bytes()?.try_into().unwrap();
        Ok((message_1, Some(opaque_state)))
    } else {
        Ok((message_1, None))
    }
}

fn decrypt_enc_id<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    enc_id: &EdhocMessageBuffer,
    ss: u8,
) -> Result<EdhocMessageBuffer, EDHOCError> {
    let (k_1, iv_1) = compute_k_1_iv_1(crypto, &prk);

    // external_aad = (SS: int)
    let enc_structure = encode_enc_structure(ss);

    // ENC_ID = 'ciphertext' of COSE_Encrypt0
    crypto.aes_ccm_decrypt_tag_8(&k_1, &iv_1, &enc_structure[..], &enc_id)
}

fn decode_id_u(id_u_bstr: EdhocMessageBuffer) -> Result<EdhocMessageBuffer, EDHOCError> {
    // id_u is encoded as bstr
    let mut decoder = CBORDecoder::new(id_u_bstr.as_slice());
    let id_u: EdhocMessageBuffer = decoder.bytes()?.try_into().unwrap();
    Ok(id_u)
}

fn encode_voucher_response(
    message_1: &EdhocMessageBuffer,
    voucher: &BytesEncodedVoucher,
    opaque_state: &Option<EdhocMessageBuffer>,
) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[1] = CBOR_BYTE_STRING;
    output.content[2] = message_1.len as u8;
    output.content[3..3 + message_1.len].copy_from_slice(message_1.as_slice());

    output.content[3 + message_1.len] = CBOR_MAJOR_BYTE_STRING + ENCODED_VOUCHER_LEN as u8;
    output.content[4 + message_1.len..4 + message_1.len + ENCODED_VOUCHER_LEN]
        .copy_from_slice(&voucher[..]);

    if let Some(opaque_state) = opaque_state {
        output.content[0] = CBOR_MAJOR_ARRAY | 3;

        output.content[4 + message_1.len + ENCODED_VOUCHER_LEN] = CBOR_BYTE_STRING;
        output.content[5 + message_1.len + ENCODED_VOUCHER_LEN] = opaque_state.len as u8;
        output.content[6 + message_1.len + ENCODED_VOUCHER_LEN
            ..6 + message_1.len + ENCODED_VOUCHER_LEN + opaque_state.len]
            .copy_from_slice(opaque_state.as_slice());

        output.len = 6 + message_1.len + ENCODED_VOUCHER_LEN + opaque_state.len;
    } else {
        output.content[0] = CBOR_MAJOR_ARRAY | 2;
        output.len = 4 + message_1.len + ENCODED_VOUCHER_LEN;
    }

    output
}

#[cfg(test)]
mod test_enrollment_server {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_decrypt_enc_id() {
        let mut prk_tv: BytesHashLen = Default::default();
        prk_tv[..].copy_from_slice(PRK_TV);
        let id_u_encoded_tv: EdhocMessageBuffer = ID_U_ENCODED_TV.try_into().unwrap();

        let id_u_res = decrypt_enc_id(
            &mut default_crypto(),
            &prk_tv,
            &ENC_ID_TV.try_into().unwrap(),
            SS_TV,
        );
        assert!(id_u_res.is_ok());
        assert_eq!(id_u_res.unwrap().content, id_u_encoded_tv.content);
    }

    #[test]
    fn test_prepare_voucher() {
        let h_message_1: BytesHashLen = H_MESSAGE_1_TV.try_into().unwrap();
        let prk: BytesHashLen = PRK_TV.try_into().unwrap();
        let voucher_tv: BytesEncodedVoucher = VOUCHER_TV.try_into().unwrap();

        let voucher = prepare_voucher(&mut default_crypto(), &h_message_1, &CRED_V_TV, &prk);
        assert_eq!(voucher, voucher_tv);
    }

    #[test]
    fn test_encode_voucher_response() {
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let voucher_tv: BytesEncodedVoucher = VOUCHER_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = SLO_OPAQUE_STATE_TV.try_into().unwrap();
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();

        let voucher_response =
            encode_voucher_response(&message_1_tv, &voucher_tv, &Some(opaque_state_tv));
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }

    #[test]
    fn test_parse_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = VOUCHER_REQUEST_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();

        let voucher_request = parse_voucher_request(&voucher_request_tv);
        assert!(voucher_request.is_ok());
        let (message_1, opaque_state) = voucher_request.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert!(opaque_state.is_none());
    }

    #[test]
    fn test_handle_voucher_request_acl_none() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();

        let ead_server = ZeroTouchServer::new(W_TV.try_into().unwrap(), CRED_V_TV, None);

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }

    #[test]
    fn test_handle_voucher_request_acl_ok() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();

        let ead_server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_V_TV,
            Some(ACL_TV.try_into().unwrap()),
        );

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }

    #[test]
    fn test_handle_voucher_request_acl_invalid() {
        let ead_server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_V_TV,
            Some(ACL_INVALID_TV.try_into().unwrap()),
        );

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert_eq!(res.unwrap_err(), EDHOCError::AccessDenied);
    }
}

#[cfg(test)]
mod test_enrollment_server_acl_user {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_split_voucher_request_handling() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();
        let id_u_tv: EdhocMessageBuffer = ID_U_TV.try_into().unwrap();

        let ead_server = ZeroTouchServerUserAcl::new(W_TV.try_into().unwrap(), CRED_V_TV);

        let res = ead_server.decode_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let id_u = res.unwrap();
        assert_eq!(id_u.content, id_u_tv.content);

        let res = ead_server.prepare_voucher(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }
}

#[cfg(test)]
mod test_server_stateless_operation {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_slo_parse_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = SLO_VOUCHER_REQUEST_TV.try_into().unwrap();
        let message_1_tv: EdhocMessageBuffer = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = SLO_OPAQUE_STATE_TV.try_into().unwrap();

        let voucher_request = parse_voucher_request(&voucher_request_tv);
        assert!(voucher_request.is_ok());
        let (message_1, opaque_state) = voucher_request.unwrap();
        assert_eq!(message_1.content, message_1_tv.content);
        assert_eq!(opaque_state.unwrap().content, opaque_state_tv.content);
    }

    #[test]
    fn test_slo_handle_voucher_request() {
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();

        let ead_server = ZeroTouchServer::new(W_TV.try_into().unwrap(), CRED_V_TV, None);

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &SLO_VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response.content, voucher_response_tv.content);
    }
}

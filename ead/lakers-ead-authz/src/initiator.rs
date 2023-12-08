use super::shared::*;
use lakers_shared::{Crypto as CryptoTrait, *};

#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EADInitiatorProtocolState {
    #[default]
    NonInitialized,
    Start,
    WaitEAD2,
    Completed, // TODO[ead]: check if it is really ok to consider Completed after processing EAD_2
    Error,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EADInitiatorState {
    pub protocol_state: EADInitiatorProtocolState,
    pub(crate) id_u: EdhocMessageBuffer, // identifier of the device (U), equivalent to ID_CRED_I in EDHOC
    pub(crate) g_w: BytesP256ElemLen,    // public key of the enrollment server (W)
    pub(crate) loc_w: EdhocMessageBuffer, // address of the enrollment server (W)
    pub(crate) prk: BytesHashLen,
    pub(crate) voucher: BytesMac,
}

impl EADInitiatorState {
    pub fn new(id_u: EdhocMessageBuffer, g_w: BytesP256ElemLen, loc_w: EdhocMessageBuffer) -> Self {
        EADInitiatorState {
            protocol_state: EADInitiatorProtocolState::Start,
            id_u,
            g_w,
            loc_w,
            prk: [0u8; SHA256_DIGEST_LEN],
            voucher: [0u8; MAC_LENGTH],
        }
    }

    pub fn i_prepare_ead_1<Crypto: CryptoTrait>(
        &mut self,
        crypto: &mut Crypto,
        x: &BytesP256ElemLen,
        ss: u8,
    ) -> Option<EADItem> {
        if self.protocol_state != EADInitiatorProtocolState::Start {
            return None;
        }

        // PRK = EDHOC-Extract(salt, IKM)
        let prk = compute_prk(crypto, x, &self.g_w);

        // plaintext = (ID_U: bstr)
        let encoded_id_u = encode_id_u(&self.id_u);
        let enc_id = encrypt_enc_id(crypto, &prk, &encoded_id_u, ss);
        let value = Some(encode_ead_1_value(&self.loc_w, &enc_id));

        let ead_1 = EADItem {
            label: EAD_ZEROCONF_LABEL,
            is_critical: true,
            value,
        };

        self.prk = prk;
        self.protocol_state = EADInitiatorProtocolState::WaitEAD2;

        Some(ead_1)
    }

    pub fn i_process_ead_2<Crypto: CryptoTrait>(
        &mut self,
        crypto: &mut Crypto,
        ead_2: EADItem,
        cred_v_u8: &[u8],
        h_message_1: &BytesHashLen,
    ) -> Result<(), ()> {
        if ead_2.label != EAD_ZEROCONF_LABEL || ead_2.value.is_none() {
            return Err(());
        }
        let mut ead_2_value: BytesEncodedVoucher = Default::default();
        ead_2_value[..].copy_from_slice(&ead_2.value.unwrap().content[..ENCODED_VOUCHER_LEN]);

        // TODO: this conversion can be avoided if we change the type of cred_v to &[u8] troughout the code
        let mut cred_v = EdhocMessageBuffer::new();
        cred_v.fill_with_slice(cred_v_u8).unwrap();

        match verify_voucher(crypto, &ead_2_value, h_message_1, &cred_v, &self.prk) {
            Ok(voucher) => {
                self.voucher = voucher;
                self.protocol_state = EADInitiatorProtocolState::Completed;
                Ok(())
            }
            Err(_) => {
                self.protocol_state = EADInitiatorProtocolState::Error;
                Err(())
            }
        }
    }

    pub fn i_prepare_ead_3() -> Option<EADItem> {
        Some(EADItem::new())
    }
}

fn encode_id_u(id_u: &EdhocMessageBuffer) -> EdhocMessageBuffer {
    // plaintext = (ID_U: bstr)
    let mut plaintext = EdhocMessageBuffer::new();
    plaintext.content[0] = CBOR_MAJOR_BYTE_STRING + id_u.len as u8;
    plaintext.content[1..1 + id_u.len].copy_from_slice(id_u.as_slice());
    plaintext.len = 1 + id_u.len;

    plaintext
}

fn encrypt_enc_id<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    plaintext: &EdhocMessageBuffer,
    ss: u8,
) -> EdhocMessageBuffer {
    let (k_1, iv_1) = compute_k_1_iv_1(crypto, &prk);

    // external_aad = (SS: int)
    let enc_structure = encode_enc_structure(ss);

    // ENC_ID = 'ciphertext' of COSE_Encrypt0
    crypto.aes_ccm_encrypt_tag_8(&k_1, &iv_1, &enc_structure[..], plaintext)
}

fn encode_ead_1_value(
    loc_w: &EdhocMessageBuffer,
    enc_id: &EdhocMessageBuffer,
) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[0] = CBOR_BYTE_STRING;
    // put length at output.content[1] after other sizes are known

    output.content[2] = CBOR_TEXT_STRING;
    output.content[3] = loc_w.len as u8;
    output.content[4..4 + loc_w.len].copy_from_slice(loc_w.as_slice());

    output.content[4 + loc_w.len] = CBOR_MAJOR_BYTE_STRING + enc_id.len as u8;
    output.content[5 + loc_w.len..5 + loc_w.len + enc_id.len].copy_from_slice(enc_id.as_slice());

    output.len = 5 + loc_w.len + enc_id.len;
    output.content[1] = (output.len - 2) as u8;

    output
}

#[cfg(test)]
mod test_initiator {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_encrypt_enc_id() {
        let enc_id_tv: EdhocMessageBuffer = ENC_ID_TV.try_into().unwrap();

        let enc_id = encrypt_enc_id(
            &mut default_crypto(),
            &PRK_TV.try_into().unwrap(),
            &ID_U_ENCODED_TV.try_into().unwrap(),
            SS_TV,
        );
        assert_eq!(enc_id.content, enc_id_tv.content);
    }

    #[test]
    fn test_prepare_ead_1() {
        let ead_1_value_tv: EdhocMessageBuffer = EAD1_VALUE_TV.try_into().unwrap();

        let mut ead_authz = EADInitiatorState::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );

        let ead_1 = ead_authz
            .i_prepare_ead_1(&mut default_crypto(), &X_TV.try_into().unwrap(), SS_TV)
            .unwrap();
        assert_eq!(
            ead_authz.protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );
        assert_eq!(ead_1.label, EAD_ZEROCONF_LABEL);
        assert_eq!(ead_1.is_critical, true);
        assert_eq!(ead_1.value.unwrap().content, ead_1_value_tv.content);
    }

    #[test]
    fn test_verify_voucher() {
        let voucher_tv = VOUCHER_TV.try_into().unwrap();
        let h_message_1_tv = H_MESSAGE_1_TV.try_into().unwrap();
        let cred_v_tv = CRED_V_TV.try_into().unwrap();
        let prk_tv = PRK_TV.try_into().unwrap();
        let voucher_mac_tv: BytesMac = VOUCHER_MAC_TV.try_into().unwrap();

        let res = verify_voucher(
            &mut default_crypto(),
            &voucher_tv,
            &h_message_1_tv,
            &cred_v_tv,
            &prk_tv,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), voucher_mac_tv);
    }

    #[test]
    fn test_process_ead_2() {
        let ead_2_value_tv: EdhocMessageBuffer = EAD2_VALUE_TV.try_into().unwrap();
        let cred_v_tv: &[u8] = CRED_V_TV.try_into().unwrap();
        let h_message_1_tv = H_MESSAGE_1_TV.try_into().unwrap();

        let ead_2_tv = EADItem {
            label: EAD_ZEROCONF_LABEL,
            is_critical: true,
            value: Some(ead_2_value_tv),
        };

        let mut ead_authz = EADInitiatorState::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        ead_authz.prk = PRK_TV.try_into().unwrap();

        let res =
            ead_authz.i_process_ead_2(&mut default_crypto(), ead_2_tv, cred_v_tv, &h_message_1_tv);
        assert!(res.is_ok());
        assert_eq!(
            ead_authz.protocol_state,
            EADInitiatorProtocolState::Completed
        );
    }
}

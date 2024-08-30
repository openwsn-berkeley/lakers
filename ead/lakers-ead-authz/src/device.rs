use crate::consts::*;
use crate::shared::*;
use crate::ZeroTouchError;
use defmt_or_log::trace;
use lakers_shared::{Crypto as CryptoTrait, *};

#[derive(Default, Debug)]
#[repr(C)]
pub struct ZeroTouchDevice {
    pub id_u: EdhocMessageBuffer, // identifier of the device (U), equivalent to ID_CRED_I in EDHOC
    pub g_w: BytesP256ElemLen,    // public key of the enrollment server (W)
    pub loc_w: EdhocMessageBuffer, // address of the enrollment server (W)
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ZeroTouchDeviceWaitEAD2 {
    prk: BytesHashLen,
    pub h_message_1: BytesHashLen,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ZeroTouchDeviceDone {
    pub voucher: BytesMac,
}

impl ZeroTouchDevice {
    pub fn new(id_u: EdhocMessageBuffer, g_w: BytesP256ElemLen, loc_w: EdhocMessageBuffer) -> Self {
        trace!("Initializing ZeroTouchDevice");
        ZeroTouchDevice { id_u, g_w, loc_w }
    }

    pub fn prepare_ead_1<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        secret: BytesP256ElemLen,
        ss: u8,
    ) -> (ZeroTouchDeviceWaitEAD2, EADItem) {
        trace!("Enter prepare_ead_1");
        // PRK = EDHOC-Extract(salt, IKM)
        let prk = compute_prk_from_secret(crypto, &secret);

        // plaintext = (ID_U: bstr)
        let encoded_id_u = encode_id_u(&self.id_u);
        let enc_id = encrypt_enc_id(crypto, &prk, &encoded_id_u, ss);
        let value = Some(encode_ead_1_value(&self.loc_w, &enc_id));

        let ead_1 = EADItem {
            label: EAD_AUTHZ_LABEL,
            is_critical: true,
            value,
        };

        (
            ZeroTouchDeviceWaitEAD2 {
                prk,
                h_message_1: [0; SHA256_DIGEST_LEN],
            },
            ead_1,
        )
    }
}

impl ZeroTouchDeviceWaitEAD2 {
    pub fn set_h_message_1(&mut self, h_message_1: BytesHashLen) {
        trace!("Enter set_h_message_1");
        self.h_message_1 = h_message_1;
    }

    pub fn process_ead_2<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        ead_2: EADItem,
        cred_v: &[u8],
    ) -> Result<ZeroTouchDeviceDone, ZeroTouchError> {
        trace!("Enter process_ead_2");
        if ead_2.label != EAD_AUTHZ_LABEL {
            return Err(ZeroTouchError::InvalidEADLabel);
        }
        let Some(ead_2_value_buffer) = ead_2.value else {
            return Err(ZeroTouchError::EmptyEADValue);
        };
        let mut ead_2_value: BytesEncodedVoucher = Default::default();
        ead_2_value[..].copy_from_slice(&ead_2_value_buffer.content[..ENCODED_VOUCHER_LEN]);

        match verify_voucher(crypto, &ead_2_value, &self.h_message_1, cred_v, &self.prk) {
            Ok(voucher) => Ok(ZeroTouchDeviceDone { voucher }),
            Err(error) => Err(error),
        }
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

pub(crate) fn verify_voucher<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    received_voucher: &BytesEncodedVoucher,
    h_message_1: &BytesHashLen,
    cred_v: &[u8],
    prk: &BytesHashLen,
) -> Result<BytesMac, ZeroTouchError> {
    let prepared_voucher = &prepare_voucher(crypto, h_message_1, cred_v, prk);
    if received_voucher == prepared_voucher {
        let mut voucher_mac: BytesMac = Default::default();
        voucher_mac[..MAC_LENGTH].copy_from_slice(&prepared_voucher[1..1 + MAC_LENGTH]);
        return Ok(voucher_mac);
    } else {
        return Err(ZeroTouchError::VoucherVerificationFailed);
    }
}

#[cfg(test)]
mod test_device {
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

        let ead_device = ZeroTouchDevice::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );

        let (_ead_device, ead_1) =
            ead_device.prepare_ead_1(&mut default_crypto(), G_XW_TV.try_into().unwrap(), SS_TV);
        assert_eq!(ead_1.label, EAD_AUTHZ_LABEL);
        assert_eq!(ead_1.is_critical, true);
        assert_eq!(ead_1.value.unwrap().content, ead_1_value_tv.content);
    }

    #[test]
    fn test_verify_voucher() {
        let mut voucher_tv = VOUCHER_TV.try_into().unwrap();
        let h_message_1_tv = H_MESSAGE_1_TV.try_into().unwrap();
        let prk_tv = PRK_TV.try_into().unwrap();
        let voucher_mac_tv: BytesMac = VOUCHER_MAC_TV.try_into().unwrap();

        let res = verify_voucher(
            &mut default_crypto(),
            &voucher_tv,
            &h_message_1_tv,
            &CRED_V_TV,
            &prk_tv,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), voucher_mac_tv);

        voucher_tv[0] ^= 0x01; // change a byte to make the voucher invalid
        let res = verify_voucher(
            &mut default_crypto(),
            &voucher_tv,
            &h_message_1_tv,
            &CRED_V_TV,
            &prk_tv,
        );
        assert_eq!(res, Err(ZeroTouchError::VoucherVerificationFailed));
    }

    #[test]
    fn test_process_ead_2() {
        let ead_2_tv = EADItem {
            label: EAD_AUTHZ_LABEL,
            is_critical: true,
            value: Some(EAD2_VALUE_TV.try_into().unwrap()),
        };

        let ead_device = ZeroTouchDeviceWaitEAD2 {
            prk: PRK_TV.try_into().unwrap(),
            h_message_1: H_MESSAGE_1_TV.try_into().unwrap(),
        };

        let res = ead_device.process_ead_2(
            &mut default_crypto(),
            ead_2_tv,
            CRED_V_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let ead_device = res.unwrap();
        assert_eq!(ead_device.voucher, VOUCHER_MAC_TV); // TODO: maybe should use the encoded voucher instead?
    }
}

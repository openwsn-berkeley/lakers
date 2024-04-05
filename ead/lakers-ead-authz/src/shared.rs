use crate::consts::*;
use lakers_shared::{Crypto as CryptoTrait, *};

pub(crate) fn compute_prk<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    a: &BytesP256ElemLen,
    g_b: &BytesP256ElemLen,
) -> BytesHashLen {
    // NOTE: salt should be h'' (the zero-length byte string), but crypto backends are hardcoded to salts of size SHA256_DIGEST_LEN (32).
    //       nevertheless, using a salt of HashLen zeros works as well (see RFC 5869, Section 2.2).
    let salt: BytesHashLen = [0u8; SHA256_DIGEST_LEN];
    let g_ab = crypto.p256_ecdh(a, g_b);
    crypto.hkdf_extract(&salt, &g_ab)
}

pub(crate) fn compute_prk_from_secret<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    g_ab: &BytesP256ElemLen,
) -> BytesHashLen {
    // NOTE: salt should be h'' (the zero-length byte string), but crypto backends are hardcoded to salts of size SHA256_DIGEST_LEN (32).
    //       nevertheless, using a salt of HashLen zeros works as well (see RFC 5869, Section 2.2).
    let salt: BytesHashLen = [0u8; SHA256_DIGEST_LEN];
    crypto.hkdf_extract(&salt, &g_ab)
}

pub(crate) fn prepare_voucher<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    h_message_1: &BytesHashLen,
    cred_v: &[u8],
    prk: &BytesP256ElemLen,
) -> BytesEncodedVoucher {
    let voucher_input = encode_voucher_input(&h_message_1, &cred_v);
    let voucher_mac = compute_voucher_mac(crypto, &prk, &voucher_input);
    encode_voucher(&voucher_mac)
}

pub(crate) fn compute_k_1_iv_1<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_1 = EDHOC-Expand(PRK, info = (0, h'', AES_CCM_KEY_LEN), length)
    let mut k_1: BytesCcmKeyLen = [0x00; AES_CCM_KEY_LEN];
    let k_1_buf = edhoc_kdf_expand(
        crypto,
        prk,
        EAD_AUTHZ_INFO_K_1_LABEL,
        &[0x00; MAX_KDF_CONTEXT_LEN],
        0,
        AES_CCM_KEY_LEN,
    );
    k_1[..].copy_from_slice(&k_1_buf[..AES_CCM_KEY_LEN]);

    // IV_1 = EDHOC-Expand(PRK, info = (1, h'', AES_CCM_IV_LEN), length)
    let mut iv_1: BytesCcmIvLen = [0x00; AES_CCM_IV_LEN];
    let iv_1_buf = edhoc_kdf_expand(
        crypto,
        prk,
        EAD_AUTHZ_INFO_IV_1_LABEL,
        &[0x00; MAX_KDF_CONTEXT_LEN],
        0,
        AES_CCM_IV_LEN,
    );
    iv_1[..].copy_from_slice(&iv_1_buf[..AES_CCM_IV_LEN]);

    (k_1, iv_1)
}

pub(crate) fn parse_ead_1_value(
    value: &EdhocMessageBuffer,
) -> Result<(EdhocMessageBuffer, EdhocMessageBuffer), EDHOCError> {
    let mut outer_decoder = CBORDecoder::new(value.as_slice());
    let voucher_info_seq = outer_decoder.bytes()?;
    let mut seq_decoder = CBORDecoder::new(voucher_info_seq);
    Ok((
        seq_decoder.str()?.try_into().unwrap(),
        seq_decoder.bytes()?.try_into().unwrap(),
    ))
}

pub(crate) fn encode_enc_structure(ss: u8) -> [u8; EAD_AUTHZ_ENC_STRUCTURE_LEN] {
    let mut encrypt0: Bytes8 = [0x00; 8];
    encrypt0[0] = 0x45u8; // 'E'
    encrypt0[1] = 0x6eu8; // 'n'
    encrypt0[2] = 0x63u8; // 'c'
    encrypt0[3] = 0x72u8; // 'r'
    encrypt0[4] = 0x79u8; // 'y'
    encrypt0[5] = 0x70u8; // 'p'
    encrypt0[6] = 0x74u8; // 't'
    encrypt0[7] = 0x30u8; // '0'

    let mut enc_structure: [u8; EAD_AUTHZ_ENC_STRUCTURE_LEN] = [0x00; EAD_AUTHZ_ENC_STRUCTURE_LEN];

    // encode Enc_structure from rfc9052 Section 5.3
    enc_structure[0] = CBOR_MAJOR_ARRAY | 3 as u8; // 3 is the fixed number of elements in the array
    enc_structure[1] = CBOR_MAJOR_TEXT_STRING | encrypt0.len() as u8;
    enc_structure[2..2 + encrypt0.len()].copy_from_slice(&encrypt0[..]);
    enc_structure[encrypt0.len() + 2] = CBOR_MAJOR_BYTE_STRING | 0x00 as u8; // 0 for zero-length byte string (empty Header)
    enc_structure[encrypt0.len() + 3] = CBOR_MAJOR_BYTE_STRING | 0x01 as u8; // 1 for the `ss` value
    enc_structure[encrypt0.len() + 4] = ss;

    enc_structure
}

// private functions

fn encode_voucher_input(h_message_1: &BytesHashLen, cred_v: &[u8]) -> EdhocMessageBuffer {
    let mut voucher_input = EdhocMessageBuffer::new();

    voucher_input.content[0] = CBOR_BYTE_STRING;
    voucher_input.content[1] = SHA256_DIGEST_LEN as u8;
    voucher_input.content[2..2 + SHA256_DIGEST_LEN]
        .copy_from_slice(&h_message_1[..SHA256_DIGEST_LEN]);

    voucher_input.content[2 + SHA256_DIGEST_LEN] = CBOR_BYTE_STRING;
    voucher_input.content[3 + SHA256_DIGEST_LEN] = cred_v.len() as u8;
    voucher_input.content[4 + SHA256_DIGEST_LEN..4 + SHA256_DIGEST_LEN + cred_v.len()]
        .copy_from_slice(cred_v);

    voucher_input.len = 4 + SHA256_DIGEST_LEN + cred_v.len();

    voucher_input
}

fn compute_voucher_mac<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    voucher_input: &EdhocMessageBuffer,
) -> BytesMac {
    let mut voucher_mac: BytesMac = [0x00; MAC_LENGTH];

    let mut context = [0x00; MAX_KDF_CONTEXT_LEN];
    context[..voucher_input.len].copy_from_slice(voucher_input.as_slice());

    let voucher_mac_buf = edhoc_kdf_expand(crypto, prk, 2, &context, voucher_input.len, MAC_LENGTH);
    voucher_mac[..MAC_LENGTH].copy_from_slice(&voucher_mac_buf[..MAC_LENGTH]);

    voucher_mac
}

fn encode_voucher(voucher_mac: &BytesMac) -> BytesEncodedVoucher {
    let mut voucher: BytesEncodedVoucher = Default::default();
    voucher[0] = CBOR_MAJOR_BYTE_STRING + MAC_LENGTH as u8;
    voucher[1..1 + MAC_LENGTH].copy_from_slice(&voucher_mac[..MAC_LENGTH]);

    voucher
}

fn edhoc_kdf_expand<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    label: u8,
    context: &BytesMaxContextBuffer,
    context_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let (info, info_len) = encode_info(label, context, context_len, length);
    let output = crypto.hkdf_expand(prk, &info, info_len, length);
    output
}

#[cfg(test)]
mod test_shared {
    use super::*;
    use crate::test_vectors::*;

    use lakers_crypto::default_crypto;

    #[test]
    fn test_compute_keys() {
        let k_1_tv: BytesCcmKeyLen = K_1_TV.try_into().unwrap();
        let iv_1_tv: BytesCcmIvLen = IV_1_TV.try_into().unwrap();
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();

        let prk_xw = compute_prk(
            &mut default_crypto(),
            &X_TV.try_into().unwrap(),
            &G_W_TV.try_into().unwrap(),
        );
        let prk_wx = compute_prk(
            &mut default_crypto(),
            &W_TV.try_into().unwrap(),
            &G_X_TV.try_into().unwrap(),
        );
        assert_eq!(prk_xw, prk_tv);
        assert_eq!(prk_xw, prk_wx);

        let (k_1, iv_1) = compute_k_1_iv_1(&mut default_crypto(), &prk_xw);
        assert_eq!(k_1, k_1_tv);
        assert_eq!(iv_1, iv_1_tv);
    }

    #[test]
    fn test_encode_voucher_input() {
        let h_message_1_tv: BytesHashLen = H_MESSAGE_1_TV.try_into().unwrap();
        let voucher_input_tv: EdhocMessageBuffer = VOUCHER_INPUT_TV.try_into().unwrap();

        let voucher_input = encode_voucher_input(&h_message_1_tv, &CRED_V_TV);
        assert_eq!(voucher_input.content, voucher_input_tv.content);
    }

    #[test]
    fn test_compute_voucher_mac() {
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();
        let voucher_input_tv: EdhocMessageBuffer = VOUCHER_INPUT_TV.try_into().unwrap();
        let voucher_mac_tv: BytesMac = VOUCHER_MAC_TV.try_into().unwrap();

        let voucher_mac = compute_voucher_mac(&mut default_crypto(), &prk_tv, &voucher_input_tv);
        assert_eq!(voucher_mac, voucher_mac_tv);
    }
}

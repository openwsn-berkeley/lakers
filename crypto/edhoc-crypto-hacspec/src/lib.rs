#![no_std]

use edhoc_consts::*;
use hacspec_aes::*;
use hacspec_aes_ccm::*;
use hacspec_hkdf::*;
use hacspec_lib::*;
use hacspec_p256::*;
use hacspec_sha256::*;
use rand::Rng;

pub fn sha256_digest(message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
    let output = BytesHashLen::from_seq(&hash(&ByteSeq::from_slice(message, 0, message_len)));
    output
}

pub fn hkdf_expand(
    prk: &BytesHashLen,
    info: &BytesMaxInfoBuffer,
    info_len: usize,
    length: usize,
) -> BytesMaxBuffer {
    let mut output = BytesMaxBuffer::new();
    output = output.update(
        0,
        &expand(
            &ByteSeq::from_slice(prk, 0, prk.len()),
            &ByteSeq::from_slice(info, 0, info_len),
            length,
        )
        .unwrap(),
    );
    output
}

pub fn hkdf_extract(salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
    let output = BytesHashLen::from_seq(&extract(
        &ByteSeq::from_slice(salt, 0, salt.len()),
        &ByteSeq::from_slice(ikm, 0, ikm.len()),
    ));
    output
}

pub fn aes_ccm_encrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    plaintext: &BufferPlaintext3,
) -> BufferCiphertext3 {
    let output = BufferCiphertext3::from_seq(&encrypt_ccm(
        ByteSeq::from_slice(ad, 0, ad.len()),
        ByteSeq::from_slice(iv, 0, iv.len()),
        ByteSeq::from_slice(&plaintext.content, 0, plaintext.len),
        Key128::from_slice(key, 0, key.len()),
        AES_CCM_TAG_LEN,
    ));

    output
}

pub fn aes_ccm_decrypt_tag_8(
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &BytesEncStructureLen,
    ciphertext: &BufferCiphertext3,
) -> Result<BufferPlaintext3, EDHOCError> {
    match decrypt_ccm(
        ByteSeq::from_slice(ad, 0, ad.len()),
        ByteSeq::from_slice(iv, 0, iv.len()),
        Key128::from_slice(key, 0, key.len()),
        ByteSeq::from_slice(&ciphertext.content, 0, ciphertext.len),
        ciphertext.len,
        AES_CCM_TAG_LEN,
    ) {
        Ok(p) => Ok(BufferPlaintext3::from_seq(&p)),
        Err(_) => Err(EDHOCError::MacVerificationFailed),
    }
}

pub fn p256_ecdh(
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    let scalar = P256Scalar::from_byte_seq_be(private_key);
    let point = (
        P256FieldElement::from_byte_seq_be(public_key),
        p256_calculate_w(P256FieldElement::from_byte_seq_be(public_key)),
    );

    // we only care about the x coordinate
    let (x, _y) = p256_point_mul(scalar, point).unwrap();

    let secret = BytesP256ElemLen::from_seq(&x.to_byte_seq_be());
    secret
}

#[cfg(not(feature = "hacspec-pure"))]
pub fn get_random_byte() -> U8 {
    U8(rand::thread_rng().gen::<u8>())
}

#[cfg(not(feature = "hacspec-pure"))]
pub fn p256_generate_key_pair() -> (BytesP256ElemLen, BytesP256ElemLen) {
    // generate a private key
    let mut private_key = BytesP256ElemLen::new();
    loop {
        for i in 0..private_key.len() {
            private_key[i] = U8(rand::thread_rng().gen::<u8>());
        }
        if p256_validate_private_key(&ByteSeq::from_slice(&private_key, 0, private_key.len())) {
            break;
        }
    }

    // obtain the corresponding public key
    let scalar = P256Scalar::from_byte_seq_be(&private_key);
    let public_key_point = p256_point_mul_base(scalar).unwrap();
    let public_key = BytesP256ElemLen::from_seq(&public_key_point.0.to_byte_seq_be());

    (private_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_keys() {
        let (x, g_x) = p256_generate_key_pair();
        assert_eq!(x.len(), 32);
        assert_eq!(g_x.len(), 32);

        let (y, g_y) = p256_generate_key_pair();

        let g_xy = p256_ecdh(&x, &g_y);
        let g_yx = p256_ecdh(&y, &g_x);

        assert_bytes_eq!(g_xy, g_yx);
    }
}
